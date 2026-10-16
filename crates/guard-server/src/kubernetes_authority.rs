//! Exclusive native policy publication from one authenticated Kubernetes object.
//! This is Sumunjang IP policy, not Kubernetes NetworkPolicy/CNI enforcement.
use crate::{App, Engine, Policy};
use anyhow::{Result, ensure};
use arc_swap::ArcSwapOption;
use hangang_runtime::time::{LocalDeadline, ReceiverClock};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

const MAX_BODY: usize = 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    api: String,
    namespace: String,
    name: String,
    uid: String,
    ca: PathBuf,
    #[serde(default)]
    token_env: Option<String>,
    #[serde(default)]
    token_file: Option<PathBuf>,
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
impl Config {
    pub(crate) fn load(path: &std::path::Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&crate::read_bounded(path, 16384)?)?;
        let url = reqwest::Url::parse(&config.api)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "invalid Kubernetes authority origin"
        );
        ensure!(
            identifier(&config.namespace) && identifier(&config.name),
            "invalid Kubernetes authority name"
        );
        ensure!(
            !config.uid.is_empty()
                && config.uid.len() <= 128
                && config
                    .uid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid pinned UID"
        );
        ensure!(
            config.token_env.is_some() != config.token_file.is_some(),
            "configure exactly one token_env or token_file reference"
        );
        if let Some(name) = &config.token_env {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "invalid source token environment name"
            );
        }
        Ok(config)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    policy: Policy,
    #[serde(default)]
    rules: guard_core::RuleSet,
    #[serde(default)]
    blocks: Vec<guard_core::Block>,
    #[serde(default)]
    asn_catalog: Vec<guard_core::AsnPrefix>,
}
fn decode(bytes: &[u8], config: &Config) -> Result<(Engine, String)> {
    ensure!(bytes.len() <= MAX_BODY, "policy object capacity exceeded");
    // Kubernetes metadata contains server-owned fields; only spec has a closed schema.
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["apiVersion"] == "policy.hangang.dev/v1alpha1" && value["kind"] == "SumunjangPolicy",
        "unexpected source kind"
    );
    let m = &value["metadata"];
    ensure!(
        m["namespace"] == config.namespace
            && m["name"] == config.name
            && m["uid"] == config.uid
            && m["deletionTimestamp"].is_null(),
        "source identity withdrawn or replaced"
    );
    let version = m["resourceVersion"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
        .ok_or_else(|| anyhow::anyhow!("invalid resourceVersion"))?
        .to_owned();
    let spec: Spec = serde_json::from_value(value["spec"].clone())?;
    ensure!(
        !spec.policy.auto_block,
        "source authority forbids event-driven policy writers"
    );
    ensure!(
        spec.blocks.len() <= guard_core::MAX_BLOCKS && spec.asn_catalog.len() <= 65536,
        "native policy capacity exceeded"
    );
    let mut engine = Engine::new(spec.policy)?;
    engine.set_rules(spec.rules)?;
    engine.set_asn_catalog(spec.asn_catalog)?;
    let mut networks = std::collections::HashSet::new();
    for block in spec.blocks {
        ensure!(
            networks.insert(guard_core::canonical_network(&block.network)?),
            "duplicate source block"
        );
        engine.add_block(block, crate::now())?;
    }
    Ok((engine, version))
}

pub(crate) struct Publication {
    view: Arc<guard_core::DecisionView>,
    deadline: LocalDeadline,
    floor: AtomicU64,
    failed: AtomicBool,
    version: String,
}
impl Publication {
    fn remaining(&self, clock: &ReceiverClock) -> Option<u64> {
        self.remaining_sample(|| {
            self.deadline
                .remaining(clock)
                .ok()
                .and_then(|d| u64::try_from(d.as_nanos()).ok())
        })
    }
    fn remaining_sample(&self, read: impl FnOnce() -> Option<u64>) -> Option<u64> {
        if self.failed.load(Ordering::Acquire) {
            return None;
        }
        // Compare only to a floor published before this backend read: delayed
        // completion of an older read must not falsely retire healthy traffic.
        let previous = self.floor.load(Ordering::Acquire);
        let remaining = read();
        let Some(nanos) = remaining.filter(|n| *n > 0 && *n <= 1_000_000_000 && *n <= previous)
        else {
            self.failed.store(true, Ordering::Release);
            return None;
        };
        self.floor.fetch_min(nanos, Ordering::AcqRel);
        if self.failed.load(Ordering::Acquire) {
            return None;
        }
        let millis = nanos / 1_000_000;
        (millis > 0).then_some(millis)
    }
}
pub(crate) struct Owner {
    clock: ReceiverClock,
    publication: ArcSwapOption<Publication>,
    phase: AtomicU8,
    config: std::sync::OnceLock<serde_json::Value>,
}
impl Owner {
    pub(crate) fn new() -> Result<Arc<Self>> {
        let mut nonce = [0; 16];
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        Ok(Arc::new(Self {
            clock: ReceiverClock::new(nonce).map_err(|_| {
                anyhow::anyhow!("native Kubernetes authority requires suspend-inclusive clock")
            })?,
            publication: ArcSwapOption::empty(),
            phase: AtomicU8::new(1),
            config: std::sync::OnceLock::new(),
        }))
    }
    fn withdraw(&self) {
        if let Some(p) = self.publication.swap(None) {
            p.failed.store(true, Ordering::Release);
        }
    }
    pub(crate) fn remaining(&self, view: &guard_core::DecisionView) -> Option<u64> {
        let p = self.publication.load_full()?;
        if !std::ptr::eq(p.view.as_ref(), view) {
            return None;
        }
        let remaining = p.remaining(&self.clock)?;
        if !self
            .publication
            .load()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &p))
        {
            return None;
        }
        Some(remaining)
    }
    pub(crate) fn report(&self, view: &guard_core::DecisionView) -> serde_json::Value {
        let remaining = self.remaining(view);
        let p = self.publication.load_full();
        serde_json::json!({"enabled":true,"available":remaining.is_some(),"phase":self.phase.load(Ordering::Acquire),"remaining_ms":remaining.unwrap_or(0),"resource_version":p.as_ref().map(|p| &p.version),"mode":"native_ip_policy","clock":"process_local_boottime","source":self.config.get()})
    }
}
struct Retire(Arc<Owner>);
impl Drop for Retire {
    fn drop(&mut self) {
        self.0.withdraw();
        self.0.phase.store(4, Ordering::Release);
    }
}

async fn collect(config: &Config, owner: &Owner) -> Result<(Engine, String, LocalDeadline)> {
    collect_authenticated(config, owner, || {
        if let Some(path) = &config.token_file {
            Ok(String::from_utf8(crate::read_bounded(path, 4096)?)?
                .trim()
                .to_owned())
        } else {
            std::env::var(
                config
                    .token_env
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source credential reference absent"))?,
            )
            .map_err(|_| anyhow::anyhow!("source credential unavailable"))
        }
    })
    .await
}
async fn collect_authenticated(
    config: &Config,
    owner: &Owner,
    credential: impl FnOnce() -> Result<String>,
) -> Result<(Engine, String, LocalDeadline)> {
    let start = owner
        .clock
        .begin_exchange()
        .map_err(|_| anyhow::anyhow!("source clock unavailable"))?;
    let ca = crate::read_bounded(&config.ca, 128 * 1024)?;
    let token = credential()?;
    ensure!(
        (16..=4096).contains(&token.len()) && !token.chars().any(char::is_control),
        "invalid source credential"
    );
    let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
    authorization.set_sensitive(true);
    // No inherited proxies, redirects, ambient trust roots, or stale credential pool.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .timeout(Duration::from_millis(1000))
        .pool_max_idle_per_host(0)
        .build()?;
    let url = format!(
        "{}/apis/policy.hangang.dev/v1alpha1/namespaces/{}/sumunjangpolicies/{}",
        config.api.trim_end_matches('/'),
        config.namespace,
        config.name
    );
    let mut response = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "source collection refused"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_BODY as u64),
        "source capacity exceeded"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_BODY,
            "source capacity exceeded"
        );
        bytes.extend_from_slice(&chunk);
    }
    let (engine, version) = decode(&bytes, config)?;
    let sample = owner
        .clock
        .finish_exchange(start)
        .map_err(|_| anyhow::anyhow!("source clock unavailable"))?;
    let bound = sample
        .before_ticks()
        .checked_add(1000)
        .ok_or_else(|| anyhow::anyhow!("source clock exhausted"))?;
    let (deadline, _) = sample
        .bind_bounds(bound, bound)
        .map_err(|_| anyhow::anyhow!("source expired"))?;
    Ok((engine, version, deadline))
}
fn install(
    app: &App,
    owner: &Owner,
    engine: Engine,
    version: String,
    deadline: LocalDeadline,
) -> Result<()> {
    let mut db = app
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("source persistence unavailable"))?;
    let mut inner = app
        .inner
        .lock()
        .map_err(|_| anyhow::anyhow!("source state unavailable"))?;
    let mut engine = engine;
    engine.advance_revision_past(inner.engine.revision())?;
    let p = Arc::new(Publication {
        view: Arc::new(engine.decision_view()),
        deadline,
        floor: AtomicU64::new(u64::MAX),
        failed: AtomicBool::new(false),
        version,
    });
    ensure!(
        p.remaining(&owner.clock).is_some(),
        "source expired before persistence"
    );
    // Only content changes are audited; the source is re-read every 500 ms.
    let before = crate::audit::state_digest(&inner.engine);
    let after = crate::audit::state_digest(&engine);
    let record = (before != after).then(|| {
        let source = owner
            .config
            .get()
            .map(|c| {
                format!(
                    "{}/{}",
                    c["namespace"].as_str().unwrap_or("?"),
                    c["name"].as_str().unwrap_or("?")
                )
            })
            .unwrap_or_else(|| "unknown".into());
        let mut record = crate::audit::Record::new(
            crate::actor::Actor::kubernetes(&source),
            "kubernetes.authority.publish",
            format!("resourceVersion={}", p.version),
        );
        record.revision_before = Some(inner.engine.revision());
        record.revision_after = Some(engine.revision());
        record.policy_revision = Some(engine.policy_revision());
        record.before_digest = Some(before);
        record.after_digest = Some(after);
        record.summary = format!(
            "{}; {}; {}",
            crate::audit::policy_summary(inner.engine.policy(), engine.policy()),
            crate::audit::rules_summary(inner.engine.rules(), engine.rules()),
            crate::audit::blocks_summary(inner.engine.blocks(), engine.blocks())
        );
        record
    });
    crate::persist_state_audited(
        &mut db,
        &engine.state(),
        record.as_ref().map(|r| (r, app.audit)),
    )
    .map_err(crate::PersistError::into_inner)?;
    ensure!(
        p.remaining(&owner.clock).is_some(),
        "source expired during persistence"
    );
    inner.engine = engine;
    app.view.store(p.view.clone());
    owner.publication.store(Some(p));
    owner.phase.store(2, Ordering::Release);
    Ok(())
}
pub(crate) async fn follow(app: App, config: Config, mut stop: tokio::sync::watch::Receiver<bool>) {
    let owner = app.native_source.as_ref().unwrap().clone();
    let _ = owner.config.set(serde_json::json!({"api":config.api,"namespace":config.namespace,"name":config.name,"uid":config.uid,"token_env":config.token_env,"token_file":config.token_file}));
    let _retire = Retire(owner.clone());
    loop {
        if *stop.borrow() {
            break;
        }
        owner.withdraw();
        owner.phase.store(1, Ordering::Release);
        let result = tokio::select! { biased; _=stop.changed()=>break, result=collect(&config,&owner)=>result };
        let result = match result {
            Ok((engine, version, deadline)) => install(&app, &owner, engine, version, deadline),
            Err(error) => Err(error),
        };
        if result.is_err() {
            owner.withdraw();
            owner.phase.store(3, Ordering::Release);
        }
        tokio::select! { biased; _=stop.changed()=>break, _=tokio::time::sleep(Duration::from_millis(500))=>{} }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use serde_json::json;
    fn config() -> Config {
        Config {
            api: "https://localhost/".into(),
            namespace: "owned".into(),
            name: "native".into(),
            uid: "fixed-uid".into(),
            ca: "unused".into(),
            token_env: Some("NATIVE_K8S_TEST_TOKEN".into()),
            token_file: None,
        }
    }
    fn object() -> serde_json::Value {
        json!({"apiVersion":"policy.hangang.dev/v1alpha1","kind":"SumunjangPolicy","metadata":{"namespace":"owned","name":"native","uid":"fixed-uid","resourceVersion":"opaque:one"},"spec":{"policy":{"mode":"enforce","auto_block":false},"rules":{"version":1,"rules":[{"id":"deny-test","network":"192.0.2.0/24","action":"deny"}]}}})
    }
    fn deadline(owner: &Owner, millis: u64) -> LocalDeadline {
        let sample = owner
            .clock
            .finish_exchange(owner.clock.begin_exchange().unwrap())
            .unwrap();
        let end = sample.before_ticks() + millis;
        sample.bind_bounds(end, end).unwrap().0
    }
    fn owned_app() -> App {
        let mut app = crate::tests::app();
        app.native_source = Some(Owner::new().unwrap());
        app
    }
    fn publish(app: &App, millis: u64) {
        let owner = app.native_source.as_ref().unwrap();
        let (engine, version) = decode(&serde_json::to_vec(&object()).unwrap(), &config()).unwrap();
        install(app, owner, engine, version, deadline(owner, millis)).unwrap();
    }

    #[test]
    fn configuration_pins_origin_identity_and_exactly_one_credential_reference() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.json");
        let value = json!({"api":"https://kubernetes.default.svc","namespace":"owned","name":"native","uid":"fixed-uid","ca":"ca.pem","token_file":"token"});
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(Config::load(&path).is_ok());
        for (field, invalid) in [
            ("api", json!("http://kubernetes.default.svc")),
            ("api", json!("https://kubernetes.default.svc/other")),
            ("namespace", json!("../escape")),
            ("name", json!("-invalid")),
            ("uid", json!("")),
            ("token_env", json!("ALSO_SET")),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(Config::load(&path).is_err());
        }
        let mut absent = value.clone();
        absent.as_object_mut().unwrap().remove("token_file");
        std::fs::write(&path, serde_json::to_vec(&absent).unwrap()).unwrap();
        assert!(Config::load(&path).is_err());
    }
    #[test]
    fn pinned_object_schema_and_native_rules_refuse_replacement_and_partial_policy() {
        let valid = object();
        let (engine, version) = decode(&serde_json::to_vec(&valid).unwrap(), &config()).unwrap();
        assert_eq!(version, "opaque:one");
        assert_eq!(
            engine.decision("192.0.2.1", crate::now()).unwrap().action,
            "deny"
        );
        for path in ["uid", "namespace", "name"] {
            let mut v = valid.clone();
            v["metadata"][path] = json!("replaced");
            assert!(decode(&serde_json::to_vec(&v).unwrap(), &config()).is_err());
        }
        for (path, value) in [
            ("deletionTimestamp", json!("2026-01-01T00:00:00Z")),
            ("resourceVersion", json!("")),
        ] {
            let mut v = valid.clone();
            v["metadata"][path] = value;
            assert!(decode(&serde_json::to_vec(&v).unwrap(), &config()).is_err());
        }
        for spec in [
            json!({"policy":{"auto_block":true}}),
            json!({"policy":{},"unknown":true}),
            json!({"policy":{},"rules":{"version":1,"rules":[{"id":"bad","network":"no-ip","action":"allow"}]}}),
        ] {
            let mut v = valid.clone();
            v["spec"] = spec;
            assert!(decode(&serde_json::to_vec(&v).unwrap(), &config()).is_err());
        }
    }
    #[tokio::test]
    async fn content_changes_and_refused_writers_are_audited_once() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let app = owned_app();
        publish(&app, 900);
        publish(&app, 900);
        let rows = |app: &App| {
            let db = app.db.lock().unwrap();
            crate::audit::query(&db, app.audit, &crate::audit::Filter::default()).unwrap()
                ["entries"]
                .as_array()
                .unwrap()
                .clone()
        };
        let entries = rows(&app);
        assert_eq!(
            entries.len(),
            1,
            "unchanged republication must not be audited"
        );
        assert_eq!(entries[0]["action"], "kubernetes.authority.publish");
        assert_eq!(entries[0]["actor"]["kind"], "kubernetes");
        assert_eq!(entries[0]["target"], "resourceVersion=opaque:one");
        assert!(
            entries[0]["summary"]
                .as_str()
                .unwrap()
                .contains("added deny-test")
        );
        let owner = app.native_source.as_ref().unwrap();
        let mut changed = object();
        changed["metadata"]["resourceVersion"] = json!("opaque:two");
        changed["spec"]["rules"]["rules"][0]["action"] = json!("observe");
        let (engine, version) = decode(&serde_json::to_vec(&changed).unwrap(), &config()).unwrap();
        install(&app, owner, engine, version, deadline(owner, 900)).unwrap();
        let entries = rows(&app);
        assert_eq!(entries.len(), 2);
        assert!(
            entries[0]["summary"]
                .as_str()
                .unwrap()
                .contains("changed deny-test")
        );
        let response = crate::router(app.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/v1/rules")
                    .header("authorization", format!("Bearer {}", app.admin))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let entries = rows(&app);
        assert_eq!(entries.len(), 3);
        assert_eq!(
            (entries[0]["action"].clone(), entries[0]["result"].clone()),
            (json!("rules.replace"), json!("refused"))
        );
    }
    #[tokio::test]
    async fn exact_publication_expiry_withdrawal_restart_and_same_version_renewal() {
        let app = owned_app();
        let before = app.view.load_full();
        assert!(app.source_remaining(&before).is_none()); // No DB restore grant before source.
        publish(&app, 80);
        let old = app.view.load_full();
        assert!(app.source_remaining(&old).is_some());
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert!(app.source_remaining(&old).is_none());
        publish(&app, 1000); // Same authoritative object/resourceVersion, new authenticated observation.
        let fresh = app.view.load_full();
        assert!(fresh.revision > old.revision);
        assert!(app.source_remaining(&fresh).is_some());
        assert!(app.source_remaining(&old).is_none());
        app.native_source.as_ref().unwrap().withdraw();
        assert!(app.source_remaining(&fresh).is_none());
        // A new process owner has no publication seal, even with persisted native state.
        let mut restarted = app.clone();
        restarted.native_source = Some(Owner::new().unwrap());
        assert!(restarted.source_remaining(&fresh).is_none());
    }
    #[tokio::test]
    async fn separate_http_probe_tracks_fresh_expired_and_new_publication() {
        let app = owned_app();
        publish(&app, 80);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(crate::readiness::serve(listener, app.clone(), rx));
        let client = reqwest::Client::new();
        assert_eq!(
            client
                .get(format!("http://{address}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert_eq!(
            client
                .get(format!("http://{address}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        assert_eq!(
            client
                .get(format!("http://{address}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        publish(&app, 1000);
        assert_eq!(
            client
                .get(format!("http://{address}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        app.native_source.as_ref().unwrap().withdraw();
        assert_eq!(
            client
                .get(format!("http://{address}/readyz"))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
    #[test]
    fn source_read_failure_and_reversal_irreversibly_retire_publication() {
        for fail_clock in [false, true] {
            let app = owned_app();
            publish(&app, 1000);
            let owner = app.native_source.as_ref().unwrap();
            let p = owner.publication.load_full().unwrap();
            if fail_clock {
                owner.clock.retire();
            } else {
                p.floor.store(1, Ordering::Release);
            }
            assert!(app.source_remaining(&p.view).is_none());
            p.floor.store(u64::MAX, Ordering::Release);
            assert!(app.source_remaining(&p.view).is_none());
        }
    }
    #[tokio::test]
    async fn writers_and_unavailable_decisions_are_refused_before_body_decode() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let app = owned_app();
        for (path, method, token, expected) in [
            (
                "/v1/policy",
                "PUT",
                app.admin.as_str(),
                StatusCode::CONFLICT,
            ),
            (
                "/v1/rules/lua",
                "PUT",
                app.admin.as_str(),
                StatusCode::CONFLICT,
            ),
            (
                "/v1/blocks",
                "POST",
                app.admin.as_str(),
                StatusCode::CONFLICT,
            ),
            (
                "/v1/geoip/reload",
                "POST",
                app.admin.as_str(),
                StatusCode::CONFLICT,
            ),
            (
                "/v1/events",
                "POST",
                app.collector.as_str(),
                StatusCode::CONFLICT,
            ),
            (
                "/v1/decision",
                "POST",
                app.collector.as_str(),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let response = crate::router(app.clone())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .method(method)
                        .header("authorization", format!("Bearer {token}"))
                        .header("content-type", "application/json")
                        .body(Body::from("invalid JSON never decoded"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
        let response = crate::router(app.clone())
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        publish(&app, 1000);
        let response = crate::router(app)
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn task_cancellation_and_closed_stop_withdraw_source() {
        let app = owned_app();
        publish(&app, 1000);
        let owner = app.native_source.as_ref().unwrap();
        let guard = Retire(owner.clone());
        drop(guard);
        assert!(app.source_remaining(&app.view.load()).is_none());
        let (tx, rx) = tokio::sync::watch::channel(true);
        follow(app.clone(), config(), rx).await;
        drop(tx);
        assert!(app.source_remaining(&app.view.load()).is_none());
        let app = owned_app();
        publish(&app, 1000);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(follow(app.clone(), config(), rx));
        tokio::time::timeout(Duration::from_secs(1), async {
            while app
                .native_source
                .as_ref()
                .unwrap()
                .phase
                .load(Ordering::Acquire)
                != 3
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(app.source_remaining(&app.view.load()).is_none());
        assert_eq!(
            app.native_source
                .as_ref()
                .unwrap()
                .phase
                .load(Ordering::Acquire),
            4
        );
    }

    #[test]
    fn concurrent_clock_reads_with_reversed_completion_preserve_health() {
        use std::sync::Barrier;
        let app = owned_app();
        publish(&app, 1000);
        let p = app
            .native_source
            .as_ref()
            .unwrap()
            .publication
            .load_full()
            .unwrap();
        // Start a fresh test observation sequence on the same publication.
        p.floor.store(u64::MAX, Ordering::Release);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let old = {
            let p = p.clone();
            let entered = entered.clone();
            let release = release.clone();
            std::thread::spawn(move || {
                p.remaining_sample(|| {
                    entered.wait();
                    release.wait();
                    Some(800_000_000)
                })
            })
        };
        entered.wait();
        assert_eq!(p.remaining_sample(|| Some(700_000_000)), Some(700));
        release.wait();
        assert_eq!(old.join().unwrap(), Some(800));
        assert_eq!(p.remaining_sample(|| Some(650_000_000)), Some(650));
        assert!(p.remaining_sample(|| Some(660_000_000)).is_none());
        assert!(p.remaining_sample(|| Some(600_000_000)).is_none());
    }
    #[tokio::test]
    async fn authenticated_https_get_is_pinned_bounded_and_never_retains_failed_collection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        let mut config = config();
        config.api = format!("https://localhost:{}/", address.port());
        config.ca = ca;
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, "owned-test-source-token").unwrap();
        config.token_env = None;
        config.token_file = Some(token_path.clone());
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            for iteration in 0..5 {
                let (io, _) = listener.accept().await.unwrap();
                let mut io = match acceptor.accept(io).await {
                    Ok(io) => io,
                    Err(_) => {
                        assert_eq!(iteration, 4);
                        continue;
                    }
                };
                let mut bytes = Vec::new();
                let mut buffer = [0; 1024];
                while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = io.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    assert!(bytes.len() < 16384);
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.starts_with("GET /apis/policy.hangang.dev/v1alpha1/namespaces/owned/sumunjangpolicies/native HTTP/1.1"));
                let expected = if iteration == 0 {
                    "authorization: bearer owned-test-source-token"
                } else {
                    "authorization: bearer rotated-owned-test-source-token"
                };
                assert!(request.to_ascii_lowercase().contains(expected));
                let (status, body) = if iteration == 0 {
                    ("200 OK", serde_json::to_string(&object()).unwrap())
                } else if iteration == 1 {
                    ("404 Not Found", "{}".into())
                } else if iteration == 2 {
                    ("302 Found", "{}".into())
                } else {
                    ("200 OK", " ".repeat(MAX_BODY + 1))
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = io.write_all(reply.as_bytes()).await;
            }
        });
        let app = owned_app();
        let owner = app.native_source.as_ref().unwrap();
        let (engine, version, deadline) = collect(&config, owner).await.unwrap();
        install(&app, owner, engine, version, deadline).unwrap();
        assert!(app.source_remaining(&app.view.load()).is_some());
        let allowed = crate::grpc::fixture_check(app.clone(), vec![198, 51, 100, 1])
            .await
            .unwrap();
        assert_eq!((allowed.verdict, allowed.mode), (1, 2));
        assert!((1..=1000).contains(&allowed.ttl_ms));
        let denied = crate::grpc::fixture_check(app.clone(), vec![192, 0, 2, 1])
            .await
            .unwrap();
        assert_eq!((denied.verdict, denied.mode), (2, 2));
        std::fs::write(&token_path, "rotated-owned-test-source-token").unwrap();
        owner.withdraw();
        assert_eq!(
            crate::grpc::fixture_check(app.clone(), vec![198, 51, 100, 1])
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert!(collect(&config, owner).await.is_err());
        assert!(app.source_remaining(&app.view.load()).is_none());
        assert!(collect(&config, owner).await.is_err());
        assert!(collect(&config, owner).await.is_err());
        let wrong_ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&config.ca, wrong_ca.cert.pem()).unwrap();
        assert!(collect(&config, owner).await.is_err());
        server.await.unwrap();
    }
}
