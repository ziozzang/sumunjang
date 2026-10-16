//! TLS material hot reload for the mTLS listeners (management HTTPS, HGD1, gRPC).
//!
//! The certificate, key and client-CA files are polled (content digest, default
//! every 10 s; no inotify, so atomic symlink swaps by cert-manager/kubelet are
//! seen). When the digest changes, new rustls server configurations are built
//! for every listener from one consistent read of the three files and swapped
//! atomically. Each new TLS handshake loads the current configuration;
//! established connections keep the configuration they negotiated. Invalid new
//! material (unparsable, key/certificate mismatch, empty CA, oversize) is
//! refused: the previous configuration keeps serving, a failure counter and the
//! error are exposed in `GET /v1/status` (`tls`) and logged once per distinct
//! bad material.
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MAX_FILE: u64 = 1024 * 1024;

/// Current server configuration of one listener, swapped on reload.
#[derive(Clone)]
pub struct AcceptorSource(Arc<ArcSwap<ServerConfig>>);
impl AcceptorSource {
    pub fn fixed(config: Arc<ServerConfig>) -> Self {
        Self(Arc::new(ArcSwap::new(config)))
    }
    /// Acceptor for one new handshake (current material).
    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.0.load_full())
    }
}

#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
}

/// ALPN of each listener.
pub const MANAGEMENT_ALPN: &[u8] = b"http/1.1";
pub const HGD1_ALPN: &[u8] = b"hgd1";
pub const GRPC_ALPN: &[u8] = b"h2";

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "TLS material exceeds 1 MiB");
    Ok(bytes)
}

struct Material {
    digest: String,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca: Vec<u8>,
}
fn load(files: &TlsFiles) -> Result<Material> {
    let (cert, key, ca) = (read(&files.cert)?, read(&files.key)?, read(&files.ca)?);
    let mut joined = Vec::with_capacity(cert.len() + key.len() + ca.len() + 24);
    for part in [&cert, &key, &ca] {
        joined.extend_from_slice(&(part.len() as u64).to_be_bytes());
        joined.extend_from_slice(part);
    }
    Ok(Material {
        digest: crate::actor::sha256_hex(&joined),
        cert,
        key,
        ca,
    })
}

/// Same policy as `hangang_runtime::tls_config` (mandatory client certificates
/// from the explicit CA, safe protocol versions, no early data), built from one
/// consistent read. Returns the configuration and the leaf SHA-256 fingerprint.
/// `notAfter` of a DER X.509 certificate as Unix seconds (minimal DER walk).
pub(crate) fn not_after(der: &[u8]) -> Option<u64> {
    fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = b.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
            (len, &rest[n..])
        };
        (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
    }
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    // TBSCertificate: [0] version (optional), serial, signature, issuer, validity.
    let (tag, _, after_first) = tlv(tbs)?;
    let mut items = if tag == 0xa0 { after_first } else { tbs };
    for _ in 0..3 {
        items = tlv(items)?.2;
    }
    let (_, validity, _) = tlv(items)?;
    let (_, _not_before, after) = tlv(validity)?;
    let (tag, time, _) = tlv(after)?;
    let s = std::str::from_utf8(time).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let y: i64 = s[..2].parse().ok()?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let (month, day, hour, minute, second) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    // Days from civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}
fn build(m: &Material, alpn: &[u8]) -> Result<(Arc<ServerConfig>, String)> {
    let certs =
        rustls_pemfile::certs(&mut m.cert.as_slice()).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certs.is_empty(), "certificate file has no certificate");
    let fingerprint = crate::actor::sha256_hex(certs[0].as_ref());
    let key = rustls_pemfile::private_key(&mut m.key.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("missing TLS private key"))?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut m.ca.as_slice()) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "client CA must not be empty");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    // with_single_cert verifies that the private key matches the certificate.
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    config.max_early_data_size = 0;
    Ok((Arc::new(config), fingerprint))
}

fn leaf_not_after(m: &Material) -> Option<u64> {
    let leaf = rustls_pemfile::certs(&mut m.cert.as_slice()).next()?.ok()?;
    not_after(leaf.as_ref())
}
#[derive(Default)]
struct State {
    not_after: Option<u64>,
    digest: String,
    fingerprint: String,
    loaded_at: u64,
    reloads: u64,
    failures: u64,
    consecutive_failures: u64,
    last_error: Option<String>,
    last_failure_at: Option<u64>,
    failed_digest: Option<String>,
}

/// Shared reloadable TLS material for all mTLS listeners.
pub struct TlsReloader {
    files: TlsFiles,
    management: AcceptorSource,
    hgd1: AcceptorSource,
    grpc: AcceptorSource,
    state: Mutex<State>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Unchanged,
    Reloaded(String),
    Refused(String),
}

impl TlsReloader {
    pub fn new(files: TlsFiles) -> Result<Arc<Self>> {
        let m = load(&files)?;
        let (management, fingerprint) = build(&m, MANAGEMENT_ALPN)?;
        let (hgd1, _) = build(&m, HGD1_ALPN)?;
        let (grpc, _) = build(&m, GRPC_ALPN)?;
        Ok(Arc::new(Self {
            files,
            management: AcceptorSource::fixed(management),
            hgd1: AcceptorSource::fixed(hgd1),
            grpc: AcceptorSource::fixed(grpc),
            state: Mutex::new(State {
                not_after: leaf_not_after(&m),
                digest: m.digest,
                fingerprint,
                loaded_at: crate::now(),
                ..State::default()
            }),
        }))
    }
    pub fn management(&self) -> AcceptorSource {
        self.management.clone()
    }
    pub fn hgd1(&self) -> AcceptorSource {
        self.hgd1.clone()
    }
    pub fn grpc(&self) -> AcceptorSource {
        self.grpc.clone()
    }
    pub fn fingerprint(&self) -> String {
        self.state
            .lock()
            .map(|s| s.fingerprint.clone())
            .unwrap_or_default()
    }
    /// Check the files once and swap all listener configurations on change.
    pub fn poll(&self) -> Poll {
        let Ok(mut state) = self.state.lock() else {
            return Poll::Unchanged;
        };
        let built = load(&self.files).map(|m| {
            if m.digest == state.digest || state.failed_digest.as_deref() == Some(&m.digest) {
                return None;
            }
            let result = (|| {
                let (management, fingerprint) = build(&m, MANAGEMENT_ALPN)?;
                let (hgd1, _) = build(&m, HGD1_ALPN)?;
                let (grpc, _) = build(&m, GRPC_ALPN)?;
                Ok::<_, anyhow::Error>((management, hgd1, grpc, fingerprint, leaf_not_after(&m)))
            })();
            Some((m.digest, result))
        });
        let now = crate::now();
        let refuse = |state: &mut State, error: String, digest: Option<String>| {
            state.failures += 1;
            state.consecutive_failures += 1;
            state.last_error = Some(error.clone());
            state.last_failure_at = Some(now);
            state.failed_digest = digest;
            eprintln!("tls: new material refused, previous certificate kept: {error}");
            Poll::Refused(error)
        };
        match built {
            Ok(None) => Poll::Unchanged,
            Ok(Some((digest, Ok((management, hgd1, grpc, fingerprint, not_after))))) => {
                state.not_after = not_after;
                self.management.0.store(management);
                self.hgd1.0.store(hgd1);
                self.grpc.0.store(grpc);
                state.digest = digest;
                state.failed_digest = None;
                state.consecutive_failures = 0;
                state.reloads += 1;
                state.loaded_at = now;
                state.fingerprint = fingerprint.clone();
                eprintln!("tls: reloaded certificate material; leaf sha256 {fingerprint}");
                Poll::Reloaded(fingerprint)
            }
            Ok(Some((digest, Err(e)))) => refuse(&mut state, format!("{e:#}"), Some(digest)),
            // Unreadable files (for example mid-rotation) are retried next poll.
            Err(e) => {
                let message = format!("{e:#}");
                if state.last_error.as_deref() == Some(&message) && state.consecutive_failures > 0 {
                    return Poll::Unchanged;
                }
                refuse(&mut state, message, None)
            }
        }
    }
    /// (reloads, failures, consecutive failures, leaf notAfter) for metrics.
    pub fn counters(&self) -> (u64, u64, u64, Option<u64>) {
        self.state.lock().map_or((0, 0, 0, None), |s| {
            (s.reloads, s.failures, s.consecutive_failures, s.not_after)
        })
    }
    pub fn status(&self) -> Value {
        let Ok(s) = self.state.lock() else {
            return json!({"enabled": true, "error": "state unavailable"});
        };
        json!({
            "enabled": true,
            "leaf_sha256": s.fingerprint,
            "leaf_not_after": s.not_after,
            "loaded_at": s.loaded_at,
            "reloads_total": s.reloads,
            "reload_failures_total": s.failures,
            "consecutive_failures": s.consecutive_failures,
            "last_error": s.last_error,
            "last_failure_at": s.last_failure_at,
            "listeners": ["management", "hgd1", "grpc"],
        })
    }
}

/// Poll until stopped.
pub async fn follow(
    reloader: Arc<TlsReloader>,
    interval: std::time::Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = reloader.clone();
                let _ = tokio::task::spawn_blocking(move || r.poll()).await;
            }
            _ = stop.changed() => break,
        }
    }
}

/// Mandatory-mTLS management HTTPS with per-handshake current material; same
/// bounds as `hangang_runtime::serve_https`.
pub async fn serve_https(
    listener: tokio::net::TcpListener,
    tls: AcceptorSource,
    router: axum::Router,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    use hyper_util::{
        rt::{TokioIo, TokioTimer},
        service::TowerToHyperService,
    };
    use std::time::Duration;
    use tokio::time::timeout;
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(2048).unwrap(),
        Duration::from_secs(5),
        move |socket, peer| {
            let acceptor = tls.acceptor();
            let router = router
                .clone()
                .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
            async move {
                if let Ok(Ok(stream)) =
                    timeout(Duration::from_secs(3), acceptor.accept(socket)).await
                {
                    if stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .is_none_or(|certs| certs.is_empty())
                    {
                        return;
                    }
                    let router =
                        router.layer(axum::Extension(hangang_runtime::AuthenticatedTlsPeer));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(5))
                        .max_headers(64)
                        .max_buf_size(32 * 1024);
                    let _ = timeout(
                        Duration::from_secs(300),
                        builder.serve_connection(
                            TokioIo::new(stream),
                            TowerToHyperService::new(router),
                        ),
                    )
                    .await;
                }
            }
        },
        shutdown,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };

    pub(crate) struct Pki {
        pub dir: tempfile::TempDir,
        pub ca: CertifiedIssuer<'static, KeyPair>,
    }
    impl Pki {
        pub fn new() -> Self {
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
            let pki = Self {
                dir: tempfile::tempdir().unwrap(),
                ca,
            };
            std::fs::write(pki.path("ca.pem"), pki.ca.pem()).unwrap();
            pki.issue_server();
            pki
        }
        pub fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }
        pub fn files(&self) -> TlsFiles {
            TlsFiles {
                cert: self.path("server.pem"),
                key: self.path("server.key"),
                ca: self.path("ca.pem"),
            }
        }
        /// Write a new server key and certificate (atomic rename, like a
        /// Secret volume update) and return its DER.
        pub fn issue_server(&self) -> Vec<u8> {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let cert = params.signed_by(&key, &self.ca).unwrap();
            for (name, body) in [
                ("server.key", key.serialize_pem()),
                ("server.pem", cert.pem()),
            ] {
                let tmp = self.path(&format!("{name}.tmp"));
                std::fs::write(&tmp, body).unwrap();
                std::fs::rename(&tmp, self.path(name)).unwrap();
            }
            cert.der().to_vec()
        }
        pub fn client_config(&self, alpn: &[u8]) -> Arc<rustls::ClientConfig> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.ca.der().clone()).unwrap();
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let cert = params.signed_by(&key, &self.ca).unwrap();
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                )
                .unwrap();
            config.alpn_protocols = vec![alpn.to_vec()];
            Arc::new(config)
        }
    }
    /// Complete an mTLS handshake and return the server leaf certificate DER.
    pub(crate) async fn served_leaf(
        address: std::net::SocketAddr,
        config: Arc<rustls::ClientConfig>,
    ) -> (
        Vec<u8>,
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    ) {
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect("localhost".try_into().unwrap(), socket)
            .await
            .unwrap();
        let leaf = stream.get_ref().1.peer_certificates().unwrap()[0].to_vec();
        (leaf, stream)
    }

    #[test]
    fn digest_change_reloads_and_bad_material_keeps_previous() {
        let pki = Pki::new();
        let r = TlsReloader::new(pki.files()).unwrap();
        let first = r.fingerprint();
        assert_eq!(r.poll(), Poll::Unchanged);
        let der = pki.issue_server();
        assert_eq!(r.poll(), Poll::Reloaded(crate::actor::sha256_hex(&der)));
        assert_ne!(r.fingerprint(), first);
        let good = r.fingerprint();
        // A key that does not match the certificate is refused once.
        std::fs::write(
            pki.path("server.key"),
            KeyPair::generate().unwrap().serialize_pem(),
        )
        .unwrap();
        assert!(
            matches!(r.poll(), Poll::Refused(e) if e.contains("key")),
            "mismatch refused"
        );
        assert_eq!(
            r.poll(),
            Poll::Unchanged,
            "same bad material is not retried"
        );
        assert_eq!(r.fingerprint(), good);
        // Empty CA and garbage certificate are refused too.
        pki.issue_server();
        std::fs::write(pki.path("ca.pem"), "").unwrap();
        assert!(matches!(r.poll(), Poll::Refused(_)));
        std::fs::write(pki.path("ca.pem"), pki.ca.pem()).unwrap();
        assert!(matches!(r.poll(), Poll::Reloaded(_)));
        let s = r.status();
        assert_eq!(
            (
                s["reloads_total"].clone(),
                s["reload_failures_total"].clone()
            ),
            (json!(2), json!(2))
        );
        assert_eq!(s["consecutive_failures"], 0);
        // Missing files (mid-rotation) keep serving and are logged once.
        std::fs::remove_file(pki.path("server.pem")).unwrap();
        assert!(matches!(r.poll(), Poll::Refused(_)));
        assert_eq!(r.poll(), Poll::Unchanged);
    }

    #[tokio::test]
    async fn management_https_serves_new_certificate_without_restart() {
        let pki = Pki::new();
        let r = TlsReloader::new(pki.files()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let router = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        let task = tokio::spawn(serve_https(listener, r.management(), router, async move {
            let _ = rx.changed().await;
        }));
        let client = pki.client_config(MANAGEMENT_ALPN);
        let (before, held) = served_leaf(address, client.clone()).await;
        let der = pki.issue_server();
        assert!(matches!(r.poll(), Poll::Reloaded(_)));
        let (after, _) = served_leaf(address, client).await;
        assert_ne!(before, after);
        assert_eq!(after, der);
        // The established connection still works on its negotiated session.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut held = held;
        held.write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        held.read_to_end(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200"));
        tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn hgd1_and_grpc_listeners_serve_reloaded_material() {
        let pki = Pki::new();
        let r = TlsReloader::new(pki.files()).unwrap();
        let app = crate::tests::app();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let hgd1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hgd1_address = hgd1.local_addr().unwrap();
        let hgd1_task = tokio::spawn(crate::protocol::serve_with_tls(
            hgd1,
            app.clone(),
            rx.clone(),
            Some(r.hgd1()),
        ));
        let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc_address = grpc.local_addr().unwrap();
        let grpc_task = tokio::spawn(crate::grpc::serve(grpc, r.grpc(), app.clone(), rx.clone()));
        let (h_before, _) = served_leaf(hgd1_address, pki.client_config(HGD1_ALPN)).await;
        let (g_before, _) = served_leaf(grpc_address, pki.client_config(GRPC_ALPN)).await;
        assert_eq!(h_before, g_before);
        let der = pki.issue_server();
        assert!(matches!(r.poll(), Poll::Reloaded(_)));
        assert_eq!(
            served_leaf(hgd1_address, pki.client_config(HGD1_ALPN))
                .await
                .0,
            der
        );
        assert_eq!(
            served_leaf(grpc_address, pki.client_config(GRPC_ALPN))
                .await
                .0,
            der
        );
        // A real gRPC call over the reloaded listener (tonic client, mTLS).
        let client_key = rcgen::KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = params.signed_by(&client_key, &pki.ca).unwrap();
        let tls = tonic::transport::ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(tonic::transport::Certificate::from_pem(pki.ca.pem()))
            .identity(tonic::transport::Identity::from_pem(
                client_cert.pem(),
                client_key.serialize_pem(),
            ));
        let channel = tonic::transport::Endpoint::from_shared(format!("https://{grpc_address}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = guard_grpc::v1::network_client::NetworkClient::new(channel);
        let mut request = tonic::Request::new(guard_grpc::v1::NetworkRequest {
            request_id: 9,
            ip: vec![192, 0, 2, 1],
            minimum_revision: 0,
            include_evidence: false,
        });
        request.metadata_mut().insert(
            "authorization",
            "Bearer collector-test-token".parse().unwrap(),
        );
        let reply = client.check(request).await.unwrap().into_inner();
        assert_eq!((reply.request_id, reply.verdict), (9, 1));
        // A client without a certificate is refused by the reloaded verifier.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pki.ca.der().clone()).unwrap();
        let mut anonymous = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        anonymous.alpn_protocols = vec![b"h2".to_vec()];
        let socket = tokio::net::TcpStream::connect(grpc_address).await.unwrap();
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(anonymous))
            .connect("localhost".try_into().unwrap(), socket)
            .await
            .unwrap();
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 16];
        assert!(matches!(stream.read(&mut buf).await, Err(_) | Ok(0)));
        tx.send(true).unwrap();
        hgd1_task.await.unwrap().unwrap();
        grpc_task.await.unwrap().unwrap();
    }
    #[test]
    fn leaf_expiry_is_parsed_from_der() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 7, 9);
        let cert = params.self_signed(&key).unwrap();
        // 2031-07-09T00:00:00Z
        assert_eq!(not_after(cert.der()), Some(1_941_321_600));
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2061, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        assert_eq!(not_after(cert.der()), Some(2_871_763_200));
        assert_eq!(not_after(b"garbage"), None);
        let pki = Pki::new();
        assert!(
            TlsReloader::new(pki.files())
                .unwrap()
                .counters()
                .3
                .is_some()
        );
    }
}
