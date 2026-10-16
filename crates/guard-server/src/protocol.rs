//! Binary decisions v1: authenticated persistent connection, fixed frames.
use crate::{App, now};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    time::timeout,
};
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 256;
const REQUEST_LEN: usize = 24;
pub(crate) fn tls_acceptor(
    cert: &std::path::Path,
    key: &std::path::Path,
    ca: &std::path::Path,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    Ok(tokio_rustls::TlsAcceptor::from(
        hangang_runtime::tls_config(cert, key, ca, &[b"hgd1"])?,
    ))
}

pub(crate) fn matches_token(supplied: &[u8], expected: &[u8]) -> bool {
    supplied.len() == expected.len()
        && supplied
            .iter()
            .zip(expected)
            .fold(0u8, |a, (b, c)| a | (b ^ c))
            == 0
}
fn decode(frame: &[u8; REQUEST_LEN]) -> anyhow::Result<(u32, IpAddr)> {
    anyhow::ensure!(
        frame[0] == 1 && frame[2..4] == [0, 0],
        "invalid request header"
    );
    let correlation = u32::from_be_bytes(frame[4..8].try_into()?);
    let ip = match frame[1] {
        4 => {
            anyhow::ensure!(
                frame[12..24].iter().all(|b| *b == 0),
                "nonzero IPv4 padding"
            );
            IpAddr::V4(Ipv4Addr::new(frame[8], frame[9], frame[10], frame[11]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&frame[8..24])?)),
        _ => anyhow::bail!("invalid IP family"),
    };
    Ok((correlation, ip))
}
async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    app: App,
) -> anyhow::Result<()> {
    timeout(AUTH_TIMEOUT, async {
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).await?;
        anyhow::ensure!(&header[..4] == b"HGD1", "invalid authentication header");
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        anyhow::ensure!((16..=4096).contains(&len), "invalid token length");
        let mut token = vec![0u8; len];
        stream.read_exact(&mut token).await?;
        anyhow::ensure!(
            matches_token(&token, app.collector.as_bytes()),
            "unauthorized"
        );
        stream.write_all(b"HGA1").await?;
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    // One bounded read may contain multiple pipelined queries. Preserve a split
    // frame and write the corresponding responses together to amortize syscalls.
    let mut requests = [0u8; REQUEST_LEN * 256];
    let mut responses = [0u8; REQUEST_LEN * 256];
    let mut filled = 0;
    let mut partial_since = tokio::time::Instant::now();
    loop {
        let budget = if filled == 0 {
            IDLE_TIMEOUT
        } else {
            let elapsed = partial_since.elapsed();
            anyhow::ensure!(elapsed < AUTH_TIMEOUT, "partial query deadline exceeded");
            AUTH_TIMEOUT - elapsed
        };
        let n = timeout(budget, stream.read(&mut requests[filled..])).await??;
        if filled == 0 {
            partial_since = tokio::time::Instant::now();
        }
        if n == 0 {
            anyhow::ensure!(filled == 0, "truncated query frame");
            return Ok(());
        }
        filled += n;
        let complete = filled / REQUEST_LEN * REQUEST_LEN;
        if complete == 0 {
            continue;
        }
        {
            let view = app.view.load();
            let time = now();
            for offset in (0..complete).step_by(REQUEST_LEN) {
                let request: &[u8; REQUEST_LEN] =
                    requests[offset..offset + REQUEST_LEN].try_into()?;
                let (correlation, ip) = decode(request)?;
                let mut decision = app.query(&view, ip, time);
                if let Some(remaining) = app.source_remaining(&view) {
                    decision.ttl_ms = decision.ttl_ms.min(remaining);
                } else {
                    anyhow::bail!("native policy source unavailable");
                }
                let frame = &mut responses[offset..offset + REQUEST_LEN];
                frame.fill(0);
                frame[0] = 1;
                frame[1] = u8::from(decision.action == "deny");
                frame[2] = u8::from(decision.mode == guard_core::Mode::Enforce);
                frame[4..8].copy_from_slice(&correlation.to_be_bytes());
                frame[8..16].copy_from_slice(&decision.revision.to_be_bytes());
                frame[16..20].copy_from_slice(&(decision.ttl_ms as u32).to_be_bytes());
            }
            let remaining = app
                .source_remaining(&view)
                .ok_or_else(|| anyhow::anyhow!("native policy source unavailable"))?;
            for frame in responses[..complete].chunks_exact_mut(REQUEST_LEN) {
                let ttl =
                    u32::from_be_bytes(frame[16..20].try_into().unwrap()).min(remaining as u32);
                frame[16..20].copy_from_slice(&ttl.to_be_bytes());
            }
        }
        timeout(WRITE_TIMEOUT, stream.write_all(&responses[..complete])).await??;
        requests.copy_within(complete..filled, 0);
        filled -= complete;
        if filled != 0 {
            partial_since = tokio::time::Instant::now();
        }
    }
}

#[cfg(test)]
pub(crate) async fn serve(
    listener: TcpListener,
    app: App,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    serve_with_tls(listener, app, stop, None).await
}
pub(crate) async fn serve_with_tls(
    listener: TcpListener,
    app: App,
    mut stop: watch::Receiver<bool>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        tls.is_some() || listener.local_addr()?.ip().is_loopback(),
        "remote native decisions require mTLS"
    );
    hangang_runtime::serve_connections(
        listener,
        std::num::NonZeroUsize::new(MAX_CONNECTIONS).unwrap(),
        Duration::ZERO,
        move |stream, peer| {
            let app = app.clone();
            let tls = tls.clone();
            async move {
                if tls.is_none() && !peer.ip().is_loopback() {
                    return;
                }
                if let Some(tls) = tls {
                    if let Ok(Ok(stream)) =
                        timeout(Duration::from_secs(3), tls.accept(stream)).await
                        && stream.get_ref().1.alpn_protocol() == Some(b"hgd1".as_slice())
                    {
                        let _ = timeout(Duration::from_secs(300), connection(stream, app)).await;
                    }
                } else {
                    let _ = timeout(Duration::from_secs(300), connection(stream, app)).await;
                }
            }
        },
        async move {
            let _ = stop.changed().await;
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    #[tokio::test]
    async fn remote_mtls_requires_identity_and_preserves_native_decisions() {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
            KeyPair,
        };
        let temp = tempfile::tempdir().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["sumunjang.example.test".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = params.signed_by(&server_key, &ca).unwrap();
        std::fs::write(temp.path().join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(temp.path().join("server.pem"), server_cert.pem()).unwrap();
        std::fs::write(temp.path().join("server.key"), server_key.serialize_pem()).unwrap();
        let tls = tls_acceptor(
            &temp.path().join("server.pem"),
            &temp.path().join("server.key"),
            &temp.path().join("ca.pem"),
        )
        .unwrap();
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address =
            std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let (tx, rx) = watch::channel(false);
        let worker = tokio::spawn(serve_with_tls(listener, crate::tests::app(), rx, Some(tls)));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = params.signed_by(&client_key, &ca).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                vec![client_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = vec![b"hgd1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        assert!(
            connector
                .connect(
                    "wrong.example.test".try_into().unwrap(),
                    TcpStream::connect(address).await.unwrap()
                )
                .await
                .is_err()
        );
        let mut stream = connector
            .connect(
                "sumunjang.example.test".try_into().unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        auth(&mut stream, b"collector-test-token").await;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"HGA1");
        for id in 1u32..=2 {
            let mut request = [0; 24];
            request[0] = 1;
            request[1] = 4;
            request[4..8].copy_from_slice(&id.to_be_bytes());
            request[8..12].copy_from_slice(&[192, 0, 2, 1]);
            stream.write_all(&request).await.unwrap();
            let mut response = [0; 24];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[0], 1);
            assert_eq!(response[1], 0);
            assert_eq!(&response[4..8], &request[4..8]);
        }
        let mut anonymous = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        anonymous.alpn_protocols = vec![b"hgd1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(anonymous));
        if let Ok(mut stream) = connector
            .connect(
                "sumunjang.example.test".try_into().unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
        {
            let mut byte = [0];
            assert!(stream.read(&mut byte).await.is_err());
        }
        tx.send(true).unwrap();
        worker.await.unwrap().unwrap();
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let (_, rx) = watch::channel(false);
        assert!(serve(listener, crate::tests::app(), rx).await.is_err());
    }
    async fn start() -> (
        std::net::SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let worker = tokio::spawn(serve(listener, crate::tests::app(), rx));
        (address, tx, worker)
    }
    async fn auth<S: AsyncWrite + Unpin>(stream: &mut S, token: &[u8]) {
        let mut frame = b"HGD1".to_vec();
        frame.extend_from_slice(&(token.len() as u16).to_be_bytes());
        frame.extend_from_slice(token);
        stream.write_all(&frame).await.unwrap();
    }
    #[tokio::test]
    async fn partial_frame_trickling_does_not_reset_completion_deadline() {
        let (address, stop, worker) = start().await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        auth(&mut stream, b"collector-test-token").await;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await.unwrap();
        let started = tokio::time::Instant::now();
        stream.write_all(&[1]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        stream.write_all(&[4]).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(4), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(started.elapsed() < Duration::from_secs(6));
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn persistent_queries_and_shutdown() {
        let (address, stop, worker) = start().await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        auth(&mut stream, b"collector-test-token").await;
        let mut ack = [0u8; 4];
        stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"HGA1");
        for id in 0u32..8 {
            let mut request = [0u8; 24];
            request[0] = 1;
            request[1] = if id % 2 == 0 { 4 } else { 6 };
            request[4..8].copy_from_slice(&id.to_be_bytes());
            request[8..12].copy_from_slice(&[192, 0, 2, 1]);
            stream.write_all(&request).await.unwrap();
            let mut response = [0u8; 24];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[0], 1);
            assert_eq!(response[1], 0);
            assert_eq!(u32::from_be_bytes(response[4..8].try_into().unwrap()), id);
            assert!(u32::from_be_bytes(response[16..20].try_into().unwrap()) <= 5000);
        }
        stop.send(true).unwrap();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut b = [0];
        assert_eq!(stream.read(&mut b).await.unwrap(), 0);
    }
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Deliberately prove TCP queries ignore both locks.
    async fn tcp_decision_ignores_held_engine_and_database() {
        let app = crate::tests::app();
        let mut engine = guard_core::Engine::new(guard_core::Policy {
            mode: guard_core::Mode::Enforce,
            ..Default::default()
        })
        .unwrap();
        engine
            .add_block(
                guard_core::Block {
                    network: "192.0.2.0/24".into(),
                    expires_at: now() + 300,
                    reason: "test".into(),
                    ..Default::default()
                },
                now(),
            )
            .unwrap();
        app.view.store(Arc::new(engine.decision_view()));
        app.inner.lock().unwrap().engine = engine;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let worker = tokio::spawn(serve(listener, app.clone(), rx));
        let engine_lock = app.inner.lock().unwrap();
        let db_lock = app.db.lock().unwrap();
        timeout(Duration::from_millis(100), async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            auth(&mut stream, b"collector-test-token").await;
            let mut ack = [0; 4];
            stream.read_exact(&mut ack).await.unwrap();
            let mut request = [0u8; 24];
            request[0] = 1;
            request[1] = 4;
            request[8..12].copy_from_slice(&[192, 0, 2, 1]);
            stream.write_all(&request).await.unwrap();
            let mut response = [0; 24];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 1);
            assert_eq!(response[2], 1);
        })
        .await
        .unwrap();
        drop(engine_lock);
        drop(db_lock);
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn tcp_country_rules_share_http_geo_context() {
        let app = crate::tests::app();
        let paths = crate::geoip::GeoPaths {
            country: Some(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/GeoIP2-Country-Test.mmdb"),
            ),
            asn: None,
        };
        app.geo
            .store(Arc::new(crate::geoip::GeoCatalog::load(&paths).unwrap()));
        let mut engine = guard_core::Engine::new(guard_core::Policy {
            mode: guard_core::Mode::Enforce,
            ..Default::default()
        })
        .unwrap();
        engine.set_rules(serde_json::from_value(serde_json::json!({"version":1,"rules":[{"id":"gb","countries":["GB"],"action":"deny"}]})).unwrap()).unwrap();
        app.view.store(Arc::new(engine.decision_view()));
        app.inner.lock().unwrap().engine = engine;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let worker = tokio::spawn(serve(listener, app, rx));
        let mut stream = TcpStream::connect(address).await.unwrap();
        auth(&mut stream, b"collector-test-token").await;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await.unwrap();
        for (octets, action) in [([81, 2, 69, 160], 1), ([192, 0, 2, 1], 0)] {
            let mut request = [0u8; 24];
            request[0] = 1;
            request[1] = 4;
            request[8..12].copy_from_slice(&octets);
            stream.write_all(&request).await.unwrap();
            let mut response = [0u8; 24];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], action);
            assert_eq!(response[2], 1);
        }
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn pipelined_split_frames() {
        let (address, stop, worker) = start().await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        auth(&mut stream, b"collector-test-token").await;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await.unwrap();
        let mut requests = vec![0u8; 24 * 300];
        for (id, frame) in requests.as_chunks_mut::<24>().0.iter_mut().enumerate() {
            frame[0] = 1;
            frame[1] = 4;
            frame[4..8].copy_from_slice(&(id as u32).to_be_bytes());
            frame[8..12].copy_from_slice(&[192, 0, 2, 1]);
        }
        stream.write_all(&requests[..13]).await.unwrap();
        stream.write_all(&requests[13..]).await.unwrap();
        let mut responses = vec![0; 24 * 300];
        timeout(Duration::from_secs(2), stream.read_exact(&mut responses))
            .await
            .unwrap()
            .unwrap();
        for (id, frame) in responses.as_chunks::<24>().0.iter().enumerate() {
            assert_eq!(
                u32::from_be_bytes(frame[4..8].try_into().unwrap()),
                id as u32
            );
            assert_eq!(frame[1], 0);
        }
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn bad_auth_and_malformed_frame_close() {
        let (address, stop, worker) = start().await;
        let mut bad = TcpStream::connect(address).await.unwrap();
        auth(&mut bad, b"admin-test-token").await;
        let mut b = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), bad.read(&mut b))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let mut stream = TcpStream::connect(address).await.unwrap();
        auth(&mut stream, b"collector-test-token").await;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await.unwrap();
        stream.write_all(&[0u8; 24]).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read(&mut b))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        stop.send(true).unwrap();
        worker.await.unwrap().unwrap();
    }
}
