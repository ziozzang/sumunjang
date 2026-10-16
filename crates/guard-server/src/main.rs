mod actor;
#[cfg(test)]
mod api_tests;
mod audit;
mod console_api;
mod explain;
mod geoip;
mod grpc;
mod kubernetes;
mod kubernetes_authority;
mod lua_rules;
mod metrics_http;
mod protocol;
mod readiness;
#[cfg(target_os = "linux")]
mod supervisor;
mod tls_reload;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State as HttpState},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    serve::ListenerExt,
};
use clap::Parser;
use guard_core::{Block, Engine, EventBatch, Policy};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Zero-trust IP/network decision authority"
)]
#[command(group(clap::ArgGroup::new("update_source").args(["update_manifest", "update_github"]).requires("supervised")))]
struct Args {
    /// Report version, identity, and capabilities without starting the service.
    #[arg(long)]
    about: bool,
    /// Validate a Kubernetes LabelSelector JSON file without DB or listeners.
    #[arg(long)]
    check_kubernetes_selector: Option<PathBuf>,
    /// Parse an offline NamespaceList/PodList fixture without activation.
    #[arg(long)]
    check_kubernetes_pod_facts: Option<PathBuf>,
    /// Evaluate an owned offline NetworkPolicy/query fixture without activating it.
    #[arg(long)]
    evaluate_kubernetes_policy: Option<PathBuf>,
    /// Read and compile a namespaced Kubernetes policy source without activation.
    #[arg(long)]
    observe_kubernetes_policy: Option<PathBuf>,
    /// Continuously collect a read-only policy source for authenticated diagnostics.
    #[arg(long)]
    kubernetes_policy_source: Option<PathBuf>,
    /// Exclusively authorize native IP policy from one pinned Kubernetes CRD.
    #[arg(long, conflicts_with_all = ["policy", "bootstrap_policy", "asn_catalog"])]
    kubernetes_authority: Option<PathBuf>,
    /// Validate configured credentials, stored policy and GeoIP without writes/listeners.
    #[arg(long)]
    check: bool,
    /// Discover latest stable GitHub release without activating it.
    #[arg(long)]
    check_update: bool,
    /// Linux stable-PID owner, retaining listeners across a single-writer replacement.
    #[arg(long)]
    supervised: bool,
    #[arg(long, hide = true)]
    serve_child: bool,
    #[arg(long)]
    update_manifest: Option<String>,
    #[arg(long)]
    update_github: bool,
    #[arg(long, default_value = "HANGANG_GUARD_UPDATE_KEY")]
    update_key_env: String,
    #[arg(long, requires = "update_source", conflicts_with = "update_github")]
    update_ca: Option<PathBuf>,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(10..))]
    update_interval_seconds: u64,
    #[arg(long, requires = "supervised")]
    update_status_file: Option<PathBuf>,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=15))]
    update_grace_seconds: u64,

    #[arg(long, default_value = "127.0.0.1:9080")]
    listen: String,
    /// Optional persistent binary decision endpoint; remote listeners require mTLS.
    #[arg(long)]
    decision_listen: Option<std::net::SocketAddr>,
    /// Optional plain HTTP /healthz and source-aware /readyz only; no management routes.
    #[arg(long)]
    readiness_listen: Option<std::net::SocketAddr>,
    /// Additional gRPC network decisions; mTLS required.
    #[arg(long, requires_all = ["decision_tls_cert", "decision_listen"])]
    grpc_listen: Option<std::net::SocketAddr>,
    /// Serve management HTTP over mandatory mTLS using the decision TLS identity.
    #[arg(long, requires = "decision_tls_cert")]
    management_tls: bool,
    #[arg(long, requires_all = ["decision_tls_key", "decision_client_ca", "decision_listen"])]
    decision_tls_cert: Option<PathBuf>,
    #[arg(long, requires = "decision_tls_cert")]
    decision_tls_key: Option<PathBuf>,
    #[arg(long, requires = "decision_tls_cert")]
    decision_client_ca: Option<PathBuf>,
    #[arg(long,default_value_t=4096,value_parser=clap::value_parser!(u32).range(1..=65536))]
    max_http_requests: u32,
    #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u16).range(1..=64))]
    threads: u16,
    #[arg(long, default_value = "hangang-guard.sqlite3")]
    database: PathBuf,
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Import only when no durable checkpoint exists; stored policy remains authoritative.
    #[arg(long, conflicts_with = "policy")]
    bootstrap_policy: Option<PathBuf>,
    #[arg(long)]
    asn_catalog: Option<PathBuf>,
    #[arg(long)]
    geoip_database: Option<PathBuf>,
    #[arg(long)]
    geoip_asn_database: Option<PathBuf>,
    /// Maximum retained policy-change audit rows (oldest removed first).
    #[arg(long, default_value_t = audit::DEFAULT_MAX_ROWS, value_parser = clap::value_parser!(u64).range(1000..=10_000_000))]
    audit_max_rows: u64,
    /// Maximum policy-change audit age in days.
    #[arg(long, default_value_t = audit::DEFAULT_MAX_DAYS, value_parser = clap::value_parser!(u64).range(1..=3650))]
    audit_retention_days: u64,
    /// Per-address signal history retention in hours (memory only).
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u64).range(1..=48))]
    history_hours: u64,
    /// Days an expired allowlist entry stays visible before automatic, audited removal.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3650))]
    allow_expired_retention_days: u64,
    /// Seconds between TLS certificate/key/CA file checks (0 disables reload).
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(0..=3600))]
    tls_reload_seconds: u64,
}
struct Inner {
    engine: Engine,
}
#[derive(Clone)]
struct App {
    inner: Arc<Mutex<Inner>>,
    view: Arc<arc_swap::ArcSwap<guard_core::DecisionView>>,
    db: Arc<Mutex<Connection>>,
    workers: Arc<tokio::sync::Semaphore>,
    max_http_requests: usize,
    geo: Arc<arc_swap::ArcSwap<geoip::GeoCatalog>>,
    geo_paths: Arc<geoip::GeoPaths>,
    geo_reload: Arc<tokio::sync::Semaphore>,
    collector: Arc<String>,
    admin: Arc<String>,
    update_status: Option<PathBuf>,
    update_request: Option<PathBuf>,
    native_source: Option<Arc<kubernetes_authority::Owner>>,
    network_source: Arc<arc_swap::ArcSwapOption<kubernetes::SourceSnapshot>>,
    network_source_phase: Arc<std::sync::atomic::AtomicU8>,
    audit: audit::Retention,
    nonces: actor::Nonces,
    /// Seconds an expired allow entry is kept (visible as expired) before pruning.
    allow_expired_keep: u64,
    /// Reloadable mTLS material (None without decision TLS flags).
    tls: Option<Arc<tls_reload::TlsReloader>>,
    /// Set while the most recent periodic checkpoint failed (readiness).
    checkpoint_failed: Arc<std::sync::atomic::AtomicBool>,
    /// Optional read-only credential for `GET /metrics`.
    metrics_token: Option<Arc<String>>,
}
/// Optional metrics credential: 16..4096 bytes, distinct from the others.
fn metrics_token(collector: &str, admin: &str) -> anyhow::Result<Option<String>> {
    match std::env::var("HANGANG_GUARD_METRICS_TOKEN") {
        Err(_) => Ok(None),
        Ok(t) => {
            anyhow::ensure!(
                (16..=4096).contains(&t.len()) && t != collector && t != admin,
                "metrics token must be distinct and 16..4096 bytes"
            );
            Ok(Some(t))
        }
    }
}
impl App {
    /// Readiness: a fresh native source (when configured) and a healthy
    /// durable checkpoint. TLS reload failures keep the previous valid
    /// material serving and do not affect readiness (see `GET /v1/status`).
    fn ready_reason(&self) -> Option<&'static str> {
        if self.source_remaining(&self.view.load()).is_none() {
            Some("native source unavailable")
        } else if self
            .checkpoint_failed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Some("checkpoint failing")
        } else {
            None
        }
    }
    fn source_remaining(&self, view: &guard_core::DecisionView) -> Option<u64> {
        self.native_source
            .as_ref()
            .map_or(Some(5000), |owner| owner.remaining(view))
    }
    fn query<'a>(
        &self,
        view: &'a guard_core::DecisionView,
        ip: std::net::IpAddr,
        time: u64,
    ) -> guard_core::DecisionRef<'a> {
        if view.requires_geo() {
            let geo = self.geo.load();
            view.query_ip_context(ip, time, geo.context(ip))
        } else {
            view.query_ip(ip, time)
        }
    }
}
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(code: StatusCode, message: impl ToString) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"error":message.to_string()})))
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn authorize(headers: &HeaderMap, token: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let supplied = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let supplied = supplied.strip_prefix("Bearer ").unwrap_or("");
    // Comparison visits every credential byte for equal-length credentials.
    let different = supplied.len() != token.len()
        || supplied
            .bytes()
            .zip(token.bytes())
            .fold(0u8, |a, (b, c)| a | (b ^ c))
            != 0;
    if different {
        Err(error(StatusCode::UNAUTHORIZED, "unauthorized"))
    } else {
        Ok(())
    }
}
async fn network_source_status(HttpState(app): HttpState<App>, headers: HeaderMap) -> ApiResult {
    authorize(&headers, &app.admin)?;
    let snapshot = app.network_source.load_full().ok_or_else(|| {
        let state = match app
            .network_source_phase
            .load(std::sync::atomic::Ordering::Acquire)
        {
            0 => "disabled",
            1 => "collecting",
            3 => "failed",
            4 => "stopped",
            _ => "unavailable",
        };
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":format!("source {state}"),"state":state,"activated":false})),
        )
    })?;
    let report = snapshot.report();
    if report["fresh"] != true {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "source snapshot expired",
        ));
    }
    Ok(Json(report))
}
async fn network_source_evaluate(
    HttpState(app): HttpState<App>,
    headers: HeaderMap,
    Json(query): Json<kubernetes::SourceQuery>,
) -> ApiResult {
    authorize(&headers, &app.admin)?;
    let snapshot = app
        .network_source
        .load_full()
        .ok_or_else(|| error(StatusCode::SERVICE_UNAVAILABLE, "source unavailable"))?;
    snapshot.evaluate(query).map(Json).map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "source unavailable or query invalid",
        )
    })
}
fn persist_state(db: &mut Connection, state: &guard_core::State) -> anyhow::Result<()> {
    persist_state_audited(db, state, None).map_err(PersistError::into_inner)
}
/// Where a checkpoint failed: before COMMIT nothing was written; a COMMIT
/// failure leaves the durable outcome uncertain until the next checkpoint.
enum PersistError {
    Before(anyhow::Error),
    Commit(anyhow::Error),
}
impl PersistError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Before(e) | Self::Commit(e) => e,
        }
    }
}
/// Checkpoint and audit row share one transaction: neither commits alone.
fn persist_state_audited(
    db: &mut Connection,
    state: &guard_core::State,
    record: Option<(&audit::Record, audit::Retention)>,
) -> Result<(), PersistError> {
    let encoded = serde_json::to_string(state).map_err(|e| PersistError::Before(e.into()))?;
    let tx = db
        .transaction()
        .map_err(|e| PersistError::Before(e.into()))?;
    tx.execute("INSERT INTO checkpoint(id,body) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET body=excluded.body", [&encoded]).map_err(|e| PersistError::Before(e.into()))?;
    if let Some((record, retention)) = record {
        audit::insert(&tx, retention, record).map_err(|e| PersistError::Before(e.into()))?;
    }
    tx.commit().map_err(|e| PersistError::Commit(e.into()))?;
    Ok(())
}

/// What an audited policy mutation changes.
#[derive(Clone, Copy)]
enum Scope {
    Policy,
    Rules,
    Blocks,
    Zones,
}
struct Change {
    actor: actor::Actor,
    action: &'static str,
    scope: Scope,
    target: String,
    reason: Option<String>,
}
impl Change {
    fn new(
        actor: actor::Actor,
        action: &'static str,
        scope: Scope,
        target: impl Into<String>,
    ) -> Self {
        Self {
            actor,
            action,
            scope,
            target: target.into(),
            reason: None,
        }
    }
}
fn scope_digest(scope: Scope, e: &Engine) -> String {
    match scope {
        Scope::Policy => audit::policy_digest(e),
        Scope::Rules => audit::rules_digest(e),
        Scope::Blocks => audit::blocks_digest(e),
        Scope::Zones => audit::digest(e.zones()),
    }
}
fn scope_summary(scope: Scope, before: &Engine, after: &Engine) -> String {
    match scope {
        Scope::Policy => audit::policy_summary(before.policy(), after.policy()),
        Scope::Rules => audit::rules_summary(before.rules(), after.rules()),
        Scope::Blocks => audit::blocks_summary(before.blocks(), after.blocks()),
        Scope::Zones => audit::zones_summary(before.zones(), after.zones()),
    }
}
/// Best-effort refusal record; a failure cannot change an already refused outcome.
fn count(counter: &std::sync::atomic::AtomicU64) {
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}
fn record_refusal(app: &App, db: &mut Connection, mut record: audit::Record, message: String) {
    count(&guard_core::metrics::METRICS.admin_changes[1]);
    if record.action == "rules.replace" && !message.starts_with("rules revision conflict") {
        count(&guard_core::metrics::METRICS.rules_compile_failures[1]);
    }
    record.result = audit::Outcome::Refused;
    record.summary = format!("refused: {message}");
    record.error = Some(message);
    if let Err(e) = audit::insert_alone(db, app.audit, &record) {
        eprintln!("audit refusal record failed: {e}");
    }
}
fn audit_header(mut response: Response, id: &str) -> Response {
    if let Ok(value) = axum::http::HeaderValue::from_str(id) {
        response.headers_mut().insert("x-sumunjang-audit-id", value);
    }
    response
}
/// Durable, audited policy mutation on a cloned engine. The checkpoint and the
/// audit row commit together; on any failure the published state is unchanged.
async fn mutation<F>(app: App, change: Change, f: F) -> Result<Response, (StatusCode, Json<Value>)>
where
    F: FnOnce(&mut Engine) -> anyhow::Result<Value> + Send + 'static,
{
    if app.native_source.is_some() {
        return Err(error(
            StatusCode::CONFLICT,
            "exclusive Kubernetes policy owner",
        ));
    }
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // DB gate orders durable writes and checkpoints, so an older checkpoint
        // cannot overwrite a newly committed policy. Ordinary queries skip it.
        let mut db = app
            .db
            .lock()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
        let mut inner = app
            .inner
            .lock()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
        let mut record = audit::Record::new(change.actor, change.action, change.target);
        record.reason = change.reason;
        record.revision_before = Some(inner.engine.revision());
        record.before_digest = Some(scope_digest(change.scope, &inner.engine));
        let mut next = inner.engine.clone();
        let value = match f(&mut next) {
            Ok(value) => value,
            Err(e) => {
                record.revision_after = record.revision_before;
                record.after_digest = record.before_digest.clone();
                record.policy_revision = Some(inner.engine.policy_revision());
                drop(inner);
                record_refusal(&app, &mut db, record, e.to_string());
                return Err(error(StatusCode::BAD_REQUEST, e));
            }
        };
        record.revision_after = Some(next.revision());
        record.policy_revision = Some(next.policy_revision());
        record.after_digest = Some(scope_digest(change.scope, &next));
        record.summary = scope_summary(change.scope, &inner.engine, &next);
        if let Err(failure) =
            persist_state_audited(&mut db, &next.state(), Some((&record, app.audit)))
        {
            drop(inner);
            let mut failed = record.clone();
            failed.result = audit::Outcome::Uncertain;
            failed.error = Some("checkpoint failed".into());
            match failure {
                // Same ID: if COMMIT did persist the committed row this insert
                // fails on uniqueness; otherwise the uncertain row records it.
                PersistError::Commit(_) => {
                    count(&guard_core::metrics::METRICS.admin_changes[2]);
                    let _ = audit::insert_alone(&mut db, app.audit, &failed);
                }
                PersistError::Before(e) => {
                    record_refusal(
                        &app,
                        &mut db,
                        record,
                        format!("checkpoint or audit write failed: {e}"),
                    );
                }
            }
            return Err(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "checkpoint failed",
            ));
        }
        inner.engine = next;
        count(&guard_core::metrics::METRICS.admin_changes[0]);
        if inner.engine.revision() != app.view.load().revision {
            app.view.store(Arc::new(inner.engine.decision_view()));
        }
        drop(inner);
        drop(db);
        if serde_json::to_vec(&value)
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed"))?
            .len()
            > 4 * 1024 * 1024
        {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "response exceeds size limit",
            ));
        }
        Ok(audit_header(Json(value).into_response(), &record.id))
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}
/// Non-durable engine operation (reads, evidence ingestion). Policy mutations
/// use [`mutation`], which checkpoints and audits.
async fn operation<F>(app: App, f: F) -> ApiResult
where
    F: FnOnce(&mut Engine) -> anyhow::Result<Value> + Send + 'static,
{
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut inner = app
            .inner
            .lock()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
        let value = f(&mut inner.engine).map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
        if inner.engine.revision() != app.view.load().revision {
            app.view.store(Arc::new(inner.engine.decision_view()));
        }
        drop(inner);
        if serde_json::to_vec(&value)
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed"))?
            .len()
            > 4 * 1024 * 1024
        {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "response exceeds size limit",
            ));
        }
        Ok(Json(value))
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

async fn events(HttpState(app): HttpState<App>, Json(batch): Json<EventBatch>) -> ApiResult {
    if app.native_source.is_some() {
        return Err(error(
            StatusCode::CONFLICT,
            "exclusive Kubernetes policy owner",
        ));
    }
    let received = now();
    if batch.events.len() > 256
        || batch.source_id.is_empty()
        || batch.source_id.len() > 64
        || batch
            .events
            .iter()
            .any(|e| e.observed_at.abs_diff(received) > 300)
    {
        guard_core::metrics::METRICS
            .evidence_batches_rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(error(
            StatusCode::BAD_REQUEST,
            "invalid event batch or timestamp",
        ));
    }
    operation(app, move |engine| {
        Ok(serde_json::to_value(engine.ingest(batch, received)?)?)
    })
    .await
}
async fn snapshot(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| {
        anyhow::ensure!(
            e.rules().rules.is_empty(),
            "dynamic rules require decision protocol"
        );
        Ok(serde_json::to_value(e.snapshot(now()))?)
    })
    .await
    .map_err(|(code, body)| {
        if body.0["error"] == "dynamic rules require decision protocol" {
            (StatusCode::NOT_IMPLEMENTED, body)
        } else {
            (code, body)
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    source_id: String,
    ip: std::net::IpAddr,
    kind: Option<guard_core::EventKind>,
    /// Additive: include decision evidence (matched rules, ASN, country, reason code).
    #[serde(default)]
    evidence: bool,
}
struct HttpLatency(std::time::Instant);
impl Drop for HttpLatency {
    fn drop(&mut self) {
        guard_core::metrics::METRICS
            .latency(guard_core::metrics::Transport::Http, self.0.elapsed());
    }
}
/// Attach decision evidence computed on the currently published view.
fn decision_with_evidence(app: &App, decision: Value, ip: std::net::IpAddr, time: u64) -> Response {
    let mut decision = decision;
    let view = app.view.load_full();
    let catalog = app.geo.load_full();
    let (evidence, _) = explain::decision_evidence(&view, &catalog, ip, time);
    decision["evidence"] = evidence.to_json(view.mode, view.revision);
    Json(decision).into_response()
}
async fn decision(
    HttpState(app): HttpState<App>,
    Json(input): Json<DecisionRequest>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    if input.source_id.is_empty() || input.source_id.len() > 64 {
        return Err(error(StatusCode::BAD_REQUEST, "invalid source ID"));
    }
    let time = now();
    let started = std::time::Instant::now();
    let _latency = HttpLatency(started);
    let view = app.view.load();
    let mut before = app.query(&view, input.ip, time);
    {
        use guard_core::metrics::{METRICS, Transport};
        // The ingest path below may add an automatic block; it is recorded
        // with the pre-ingest outcome (the reply then reflects the new block).
        METRICS.decision(Transport::Http, before.mode, before.code);
    }
    if app.native_source.is_some() {
        let remaining = app
            .source_remaining(&view)
            .ok_or_else(|| error(StatusCode::SERVICE_UNAVAILABLE, "native source unavailable"))?;
        before.ttl_ms = before.ttl_ms.min(remaining);
        // Event aggregation is a separate policy writer, forbidden in source mode.
        if input.kind.is_some() {
            return Err(error(
                StatusCode::CONFLICT,
                "exclusive Kubernetes policy owner",
            ));
        }
        if input.evidence {
            let value = serde_json::to_value(before).unwrap_or(Value::Null);
            return Ok(decision_with_evidence(&app, value, input.ip, time));
        }
        return Ok(Json(before).into_response());
    }
    // Admission reads never wait for evidence aggregation or admin fsync.
    if input.kind.is_none() || before.action == "deny" {
        if input.evidence {
            let value = serde_json::to_value(before).unwrap_or(Value::Null);
            return Ok(decision_with_evidence(&app, value, input.ip, time));
        }
        return Ok(Json(before).into_response());
    }
    drop(view);
    let want_evidence = input.evidence;
    let evidence_app = app.clone();
    let evidence_ip = input.ip;
    let geo = app.geo.load_full();
    operation(app, move |engine| {
        let ip = input.ip.to_string();
        if engine
            .decision_context(&ip, time, geo.context(input.ip))?
            .action
            != "deny"
        {
            engine.ingest(
                EventBatch {
                    source_id: input.source_id,
                    events: vec![guard_core::Event {
                        ip: ip.clone(),
                        kind: input.kind.expect("kind checked"),
                        observed_at: time,
                    }],
                },
                time,
            )?;
        }
        Ok(serde_json::to_value(engine.decision_context(
            &ip,
            time,
            geo.context(input.ip),
        )?)?)
    })
    .await
    .map(|Json(value)| {
        if want_evidence {
            decision_with_evidence(&evidence_app, value, evidence_ip, time)
        } else {
            Json(value).into_response()
        }
    })
}

async fn status(HttpState(app): HttpState<App>) -> ApiResult {
    let max_requests = app.max_http_requests;
    let geoip = app.geo.load().status();
    let tls = app
        .tls
        .as_ref()
        .map_or(json!({"enabled":false}), |t| t.status());
    let ready = app.ready_reason();
    operation(app,move|e|{let(candidates,blocks)=e.capacity();Ok(json!({"health":"ok","tls":tls,"ready":ready.is_none(),"not_ready_reason":ready,"stats":e.stats(),"geoip":geoip,"rules":{"count":e.rules().rules.len(),"snapshot_supported":e.rules().rules.is_empty()},"capacity":{"candidates":candidates,"blocks":blocks,"max_candidates":guard_core::MAX_CANDIDATES,"max_blocks":guard_core::MAX_BLOCKS,"max_batch":256,"max_body_bytes":4*1024*1024,"max_workers":1024,"max_requests":max_requests}}))}).await
}

async fn candidates(HttpState(app): HttpState<App>) -> ApiResult {
    let geo = app.geo.load_full();
    operation(app, move |e| {
        let mut list = e.candidates(now());
        for c in &mut list {
            if let Ok(ip) = c.ip.parse() {
                c.country = geo.context(ip).country.map(str::to_owned);
            }
        }
        Ok(serde_json::to_value(list)?)
    })
    .await
}
/// Optional operator change reason recorded in the audit row.
fn check_reason(reason: &Option<String>) -> Result<(), (StatusCode, Json<Value>)> {
    if reason
        .as_ref()
        .is_some_and(|r| r.len() > 256 || r.chars().any(char::is_control))
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "reason must be at most 256 bytes without control characters",
        ));
    }
    Ok(())
}
/// Map a compare-and-set refusal to 409 with the current revision.
fn conflict(
    app: &App,
    prefix: &str,
    current: fn(&Engine) -> String,
) -> impl FnOnce((StatusCode, Json<Value>)) -> (StatusCode, Json<Value>) + use<> {
    let app = app.clone();
    let prefix = prefix.to_owned();
    move |(code, mut body)| {
        if body.0["error"]
            .as_str()
            .is_some_and(|s| s.starts_with(&prefix))
        {
            if let Ok(inner) = app.inner.lock() {
                body.0["current_revision"] = json!(current(&inner.engine));
            }
            (StatusCode::CONFLICT, body)
        } else {
            (code, body)
        }
    }
}
async fn policy_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| Ok(serde_json::to_value(e.policy())?)).await
}
type Admin = axum::Extension<actor::Actor>;
type MutationResult = Result<Response, (StatusCode, Json<Value>)>;
async fn policy_put(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(policy): Json<Policy>,
) -> MutationResult {
    let change = Change::new(actor, "policy.replace", Scope::Policy, "policy");
    mutation(app, change, move |e| {
        let mut policy = policy;
        e.carry_allow_meta(&mut policy);
        e.set_policy(policy)?;
        Ok(json!({"ok":true}))
    })
    .await
}
// Body-bound CAS survives console mediation that does not forward ETag headers.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyReplacement {
    expected_revision: String,
    policy: Policy,
    /// Optional operator-supplied change reason (≤ 256 bytes), kept in the audit.
    #[serde(default)]
    reason: Option<String>,
}
fn policy_document(e: &Engine) -> Value {
    json!({"revision": e.policy_revision(), "policy": e.policy()})
}
async fn policy_document_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| Ok(policy_document(e))).await
}
async fn policy_document_put(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(input): Json<PolicyReplacement>,
) -> MutationResult {
    check_reason(&input.reason)?;
    let mut change = Change::new(actor, "policy.document.replace", Scope::Policy, "policy");
    change.reason = input.reason.clone();
    let on_conflict = conflict(&app, "policy revision conflict;", Engine::policy_revision);
    mutation(app, change, move |e| {
        anyhow::ensure!(e.policy_revision() == input.expected_revision, "policy revision conflict; draft preserved. Reload policy and reconcile before saving. / 정책 충돌: 초안은 유지됩니다. 저장된 정책을 다시 불러와 변경을 조정하세요.");
        let mut policy = input.policy;
        e.carry_allow_meta(&mut policy);
        e.set_policy(policy)?;
        Ok(policy_document(e))
    }).await.map_err(on_conflict)
}
async fn blocks(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| {
        let now = now();
        e.snapshot(now);
        Ok(Value::Array(
            e.blocks().map(console_api::block_json).collect(),
        ))
    })
    .await
}
async fn block_add(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(block): Json<Block>,
) -> MutationResult {
    let target = block.network.clone();
    let mut block = block;
    let time = now();
    block.origin = guard_core::BlockOrigin {
        source: guard_core::BlockSource::Manual,
        created_at: Some(time),
        created_by: Some(actor.name.chars().take(64).collect()),
    };
    let mut change = Change::new(actor, "blocks.add", Scope::Blocks, target);
    change.reason = Some(block.reason.clone()).filter(|r| !r.is_empty());
    mutation(app, change, move |e| {
        e.add_block(block, time)?;
        Ok(json!({"ok":true}))
    })
    .await
}
#[derive(Deserialize)]
struct Network {
    network: String,
    /// Optional change reason (block removal), recorded in the audit row.
    #[serde(default)]
    reason: Option<String>,
}
async fn block_delete(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(input): Json<Network>,
) -> MutationResult {
    check_reason(&input.reason)?;
    let target = input.network.clone();
    let mut change = Change::new(actor, "blocks.remove", Scope::Blocks, target);
    change.reason = input.reason.clone();
    mutation(app, change, move |e| {
        Ok(json!({"removed":e.remove_block(&input.network)?}))
    })
    .await
}
#[derive(Deserialize)]
struct Approval {
    ip: String,
    #[serde(default)]
    reason: Option<String>,
}
async fn approve(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(input): Json<Approval>,
) -> MutationResult {
    check_reason(&input.reason)?;
    let target = input.ip.clone();
    let by: String = actor.name.chars().take(64).collect();
    let mut change = Change::new(actor, "candidates.approve", Scope::Blocks, target);
    change.reason = input.reason.clone();
    mutation(app, change, move |e| {
        Ok(console_api::block_json(&e.approve_as(
            &input.ip,
            now(),
            Some(&by),
        )?))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupRequest {
    ip: std::net::IpAddr,
}
async fn lookup(HttpState(app): HttpState<App>, Json(input): Json<LookupRequest>) -> ApiResult {
    let geo = app.geo.load_full();
    operation(app, move |engine| {
        let ip = input.ip.to_string();
        let inspection = engine.inspect_ip(&ip, now(), geo.context(input.ip))?;
        Ok(json!({"ip":ip,"geoip":geo.lookup(input.ip),"inspection":inspection}))
    })
    .await
}
async fn network_inspect(HttpState(app): HttpState<App>, Json(input): Json<Network>) -> ApiResult {
    operation(app, move |engine| {
        Ok(serde_json::to_value(
            engine.inspect_network(&input.network, now())?,
        )?)
    })
    .await
}
async fn geo_reload(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
) -> MutationResult {
    if app.native_source.is_some() {
        return Err(error(
            StatusCode::CONFLICT,
            "exclusive Kubernetes policy owner",
        ));
    }
    let _permit = app
        .geo_reload
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::CONFLICT, "GeoIP reload already running"))?;
    let paths = app.geo_paths.clone();
    let mut record = audit::Record::new(actor, "geoip.reload", "geoip");
    let before = serde_json::to_value(app.geo.load().status()).unwrap_or(Value::Null);
    record.before_digest = Some(audit::digest(&before));
    let catalog = match tokio::task::spawn_blocking(move || geoip::GeoCatalog::load(&paths))
        .await
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "GeoIP worker failed"))?
    {
        Ok(catalog) => catalog,
        Err(e) => {
            record.after_digest = record.before_digest.clone();
            let audit_app = app.clone();
            let message = format!("GeoIP reload failed; last good catalog kept: {e}");
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(mut db) = audit_app.db.lock() {
                    record_refusal(&audit_app, &mut db, record, message);
                }
            })
            .await;
            return Err(error(StatusCode::BAD_REQUEST, e));
        }
    };
    let status = catalog.status();
    let after = serde_json::to_value(&status).unwrap_or(Value::Null);
    record.after_digest = Some(audit::digest(&after));
    record.summary = format!(
        "GeoIP catalog reloaded: {} -> {}",
        geo_label(&before),
        geo_label(&after)
    );
    // The audit row commits before the in-memory swap, which cannot fail.
    let audit_app = app.clone();
    let id = record.id.clone();
    tokio::task::spawn_blocking(move || {
        let mut db = audit_app
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database unavailable"))?;
        audit::insert_alone(&mut db, audit_app.audit, &record)
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "audit worker failed"))?
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit write failed; GeoIP catalog unchanged",
        )
    })?;
    app.geo.store(Arc::new(catalog));
    Ok(audit_header(
        Json(json!({"geoip":status})).into_response(),
        &id,
    ))
}
fn geo_label(status: &Value) -> String {
    let part = |name: &str| {
        let v = &status[name];
        if v.is_null() {
            format!("{name}=none")
        } else {
            format!(
                "{name}={}@{}",
                v["database_type"].as_str().unwrap_or("?"),
                v["build_epoch"]
            )
        }
    };
    format!("{} {}", part("country"), part("asn"))
}
/// Record a refused mutation whose engine closure never ran.
async fn refuse_unapplied(app: &App, change: Change, message: String) {
    let app = app.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let mut record = audit::Record::new(change.actor, change.action, change.target);
        record.reason = change.reason;
        if let Ok(inner) = app.inner.lock() {
            record.revision_before = Some(inner.engine.revision());
            record.revision_after = record.revision_before;
            record.policy_revision = Some(inner.engine.policy_revision());
            record.before_digest = Some(scope_digest(change.scope, &inner.engine));
            record.after_digest = record.before_digest.clone();
        }
        if let Ok(mut db) = app.db.lock() {
            record_refusal(&app, &mut db, record, message);
        }
    })
    .await;
}
async fn rules_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| Ok(serde_json::to_value(e.rules())?)).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesReplacement {
    expected_revision: String,
    rules: guard_core::RuleSet,
    #[serde(default)]
    reason: Option<String>,
}
const RULES_CONFLICT: &str = "rules revision conflict;";
fn rules_document(e: &Engine) -> Value {
    json!({"revision": e.rules_revision(), "rules": e.rules(),
           "source": if e.rules_script().is_some() {"lua"} else {"json"},
           "script": e.rules_script()})
}
/// `PUT /v1/rules`: `{expected_revision, rules, reason?}` (compare-and-set) or a
/// bare RuleSet (deprecated unconditional write, kept for compatibility).
async fn rules_put(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(body): Json<Value>,
) -> MutationResult {
    let mut change = Change::new(actor, "rules.replace", Scope::Rules, "rules");
    if body.get("expected_revision").is_some() {
        let input: RulesReplacement =
            serde_json::from_value(body).map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e))?;
        check_reason(&input.reason)?;
        change.reason = input.reason.clone();
        let on_conflict = conflict(&app, RULES_CONFLICT, Engine::rules_revision);
        return mutation(app, change, move |e| {
            anyhow::ensure!(
                e.rules_revision() == input.expected_revision,
                "rules revision conflict; draft preserved. Reload rules and reconcile before saving."
            );
            e.set_rules(input.rules)?;
            Ok(rules_document(e))
        })
        .await
        .map_err(on_conflict);
    }
    let rules: guard_core::RuleSet =
        serde_json::from_value(body).map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    mutation(app, change, move |e| {
        e.set_rules(rules)?;
        Ok(serde_json::to_value(e.rules())?)
    })
    .await
}
async fn rules_document_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| Ok(rules_document(e))).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LuaRequest {
    script: String,
    /// Optional compare-and-set against `GET /v1/rules/document` revision.
    #[serde(default)]
    expected_revision: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}
async fn compile_script(
    app: &App,
    script: String,
) -> Result<guard_core::RuleSet, (StatusCode, Json<Value>)> {
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        lua_rules::compile_lua(&script)
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "rule worker failed"))?
    .map_err(|e| {
        count(&guard_core::metrics::METRICS.rules_compile_failures[0]);
        error(StatusCode::BAD_REQUEST, e)
    })
}
async fn rules_lua(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
    Json(input): Json<LuaRequest>,
) -> MutationResult {
    check_reason(&input.reason)?;
    let mut change = Change::new(actor, "rules.lua.replace", Scope::Rules, "rules");
    change.reason = input.reason.clone();
    let script = input.script.clone();
    let expected = input.expected_revision.clone();
    let rules = match compile_script(&app, input.script).await {
        Ok(rules) => rules,
        Err(refusal) => {
            let message = refusal.1.0["error"]
                .as_str()
                .unwrap_or("Lua compilation failed")
                .to_owned();
            refuse_unapplied(&app, change, format!("Lua compilation failed: {message}")).await;
            return Err(refusal);
        }
    };
    let on_conflict = conflict(&app, RULES_CONFLICT, Engine::rules_revision);
    mutation(app, change, move |e| {
        if let Some(expected) = &expected {
            anyhow::ensure!(
                &e.rules_revision() == expected,
                "rules revision conflict; draft preserved. Reload rules and reconcile before saving."
            );
        }
        e.set_rules_from_script(rules, script)?;
        Ok(if expected.is_some() {
            rules_document(e)
        } else {
            serde_json::to_value(e.rules())?
        })
    })
    .await
    .map_err(on_conflict)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleValidation {
    rules: Option<guard_core::RuleSet>,
    script: Option<String>,
}
async fn rules_validate(
    HttpState(app): HttpState<App>,
    Json(input): Json<RuleValidation>,
) -> ApiResult {
    let rules = match (input.rules, input.script) {
        (Some(mut rules), None) => {
            rules.validate().map_err(|e| {
                count(&guard_core::metrics::METRICS.rules_compile_failures[1]);
                error(StatusCode::BAD_REQUEST, e)
            })?;
            rules
        }
        (None, Some(script)) => compile_script(&app, script).await?,
        _ => {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "provide exactly one of rules or script",
            ));
        }
    };
    Ok(Json(json!({"valid":true,"rules":rules})))
}
async fn native_source_status(HttpState(app): HttpState<App>) -> Json<Value> {
    Json(
        app.native_source
            .as_ref()
            .map_or(json!({"enabled":false}), |owner| {
                owner.report(&app.view.load())
            }),
    )
}
async fn ready(HttpState(app): HttpState<App>) -> Response {
    match app.ready_reason() {
        None => Json(json!({"status":"ready"})).into_response(),
        Some(reason) => error(StatusCode::SERVICE_UNAVAILABLE, reason).into_response(),
    }
}
fn router(app: App) -> Router {
    let credentials = app.clone();
    let requests = Arc::new(tokio::sync::Semaphore::new(app.max_http_requests));
    Router::new()
        .route("/", get(|| async { Html(include_str!("dashboard.html")) }))
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics_http::metrics))
        .route("/v1/kubernetes/authority", get(native_source_status))
        .route(
            "/v1/decision",
            post(decision).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/v1/events", post(events))
        .route("/v1/snapshot", get(snapshot))
        .route("/v1/status", get(status))
        .route("/v1/kubernetes/status", get(network_source_status))
        .route("/v1/kubernetes/evaluate", post(network_source_evaluate))
        .route("/v1/update/status", get(update_status))
        .route("/v1/update/check", post(update_check))
        .route(
            "/v1/lookup",
            post(lookup).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/v1/networks/inspect",
            post(network_inspect).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/v1/geoip/reload", post(geo_reload))
        .route("/v1/rules", get(rules_get).put(rules_put))
        .route(
            "/v1/rules/lua",
            axum::routing::put(rules_lua).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v1/rules/validate", post(rules_validate))
        .route("/v1/candidates", get(candidates))
        .route("/v1/policy", get(policy_get).put(policy_put))
        .route(
            "/v1/policy/document",
            get(policy_document_get).put(policy_document_put),
        )
        .route(
            "/v1/blocks",
            get(blocks).post(block_add).delete(block_delete),
        )
        .route("/v1/candidates/approve", post(approve))
        .route("/v1/audit", get(audit_get))
        .route("/v1/audit/query", post(audit_post))
        .route(
            "/v1/explain",
            post(explain::explain).layer(DefaultBodyLimit::max(128 * 1024)),
        )
        .route("/v1/explain/batch", post(explain::batch))
        .route("/v1/reasons", get(explain::reasons))
        .route("/v1/rules/document", get(rules_document_get))
        .route(
            "/v1/zones",
            get(console_api::zones_get)
                .post(console_api::zones_change)
                .delete(console_api::zones_delete),
        )
        .route("/v1/zones/snapshot", get(console_api::zones_snapshot))
        .route("/v1/zones/lookup", post(console_api::zones_lookup))
        .route("/v1/history", get(console_api::history_get))
        .route("/v1/history/query", post(console_api::history_post))
        .route("/v1/asn/catalog", get(console_api::asn_get))
        .route("/v1/asn/catalog/query", post(console_api::asn_post))
        .route(
            "/v1/allowlist",
            get(console_api::allowlist_get)
                .post(console_api::allowlist_add)
                .delete(console_api::allowlist_remove),
        )
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let credentials = credentials.clone();
                let requests = requests.clone();
                async move {
                    use axum::response::IntoResponse;
                    let _permit = match requests.try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            return error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "request capacity reached",
                            )
                            .into_response();
                        }
                    };
                    let path = request.uri().path().to_owned();
                    let path = path.as_str();
                    let admin_path = path.starts_with("/v1/")
                        && !matches!(path, "/v1/events" | "/v1/snapshot" | "/v1/decision");
                    let token = if matches!(path, "/v1/events" | "/v1/snapshot" | "/v1/decision") {
                        Some(credentials.collector.as_str())
                    } else if admin_path {
                        Some(credentials.admin.as_str())
                    } else {
                        None
                    };
                    if let Some(token) = token
                        && let Err(e) = authorize(request.headers(), token)
                    {
                        return e.into_response();
                    }
                    // Read-only metrics credential, or the admin credential.
                    if path == "/metrics"
                        && credentials
                            .metrics_token
                            .as_deref()
                            .is_none_or(|t| authorize(request.headers(), t).is_err())
                        && let Err(e) = authorize(request.headers(), &credentials.admin)
                    {
                        return e.into_response();
                    }
                    let mut request = request;
                    if admin_path {
                        request = match admin_actor(&credentials, request).await {
                            Ok(request) => request,
                            Err(response) => return response,
                        };
                    }
                    if path == "/v1/decision"
                        && credentials
                            .source_remaining(&credentials.view.load())
                            .is_none()
                    {
                        guard_core::metrics::METRICS.unavailable(
                            guard_core::metrics::Transport::Http,
                            guard_core::metrics::Unavailable::Source,
                        );
                        return error(StatusCode::SERVICE_UNAVAILABLE, "native source unavailable")
                            .into_response();
                    }
                    // Refuse competing writers before JSON/Lua/body decoding.
                    if credentials.native_source.is_some()
                        && (path == "/v1/snapshot"
                            || (request.method() != axum::http::Method::GET
                                && !matches!(
                                    path,
                                    "/v1/decision"
                                        | "/v1/kubernetes/evaluate"
                                        | "/v1/lookup"
                                        | "/v1/networks/inspect"
                                        | "/v1/rules/validate"
                                        | "/v1/update/check"
                                        | "/v1/audit/query"
                                        | "/v1/explain"
                                        | "/v1/explain/batch"
                                        | "/v1/history/query"
                                        | "/v1/asn/catalog/query"
                                        | "/v1/zones/lookup"
                                )))
                    {
                        if let Some(action) = action_for(request.method(), path)
                            && let Some(actor) = request.extensions().get::<actor::Actor>()
                        {
                            let change = Change::new(
                                actor.clone(),
                                action,
                                Scope::Policy,
                                action_target(action),
                            );
                            refuse_unapplied(
                                &credentials,
                                change,
                                "exclusive Kubernetes policy owner".into(),
                            )
                            .await;
                        }
                        return error(StatusCode::CONFLICT, "exclusive Kubernetes policy owner")
                            .into_response();
                    }
                    next.run(request).await
                }
            },
        ))
        .layer(axum::middleware::from_fn(
            |request: axum::extract::Request, next: axum::middleware::Next| async move {
                let mut response = next.run(request).await;
                response.headers_mut().insert(
                    "x-content-type-options",
                    axum::http::HeaderValue::from_static("nosniff"),
                );
                response.headers_mut().insert(
                    "cache-control",
                    axum::http::HeaderValue::from_static("no-store"),
                );
                response
            },
        ))
        .with_state(app)
}
/// Attach the administrative actor: a verified Hangang delegated actor when the
/// broker signed the request, otherwise the shared admin credential.
async fn admin_actor(
    app: &App,
    mut request: axum::extract::Request,
) -> Result<axum::extract::Request, Response> {
    let headers = request.headers();
    let assertions: Vec<_> = headers.get_all(actor::ASSERTION_HEADER).iter().collect();
    let macs: Vec<_> = headers.get_all(actor::MAC_HEADER).iter().collect();
    if assertions.is_empty() && macs.is_empty() {
        request.extensions_mut().insert(actor::Actor::credential());
        return Ok(request);
    }
    let invalid = || {
        error(
            StatusCode::UNAUTHORIZED,
            "invalid delegated actor assertion",
        )
        .into_response()
    };
    let (Some(encoded), Some(mac)) = (
        assertions
            .first()
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        macs.first()
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    ) else {
        return Err(invalid());
    };
    if assertions.len() != 1 || macs.len() != 1 {
        return Err(invalid());
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 4 * 1024 * 1024)
        .await
        .map_err(|_| {
            error(StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds limit").into_response()
        })?;
    let actor = actor::verify(
        &encoded,
        &mac,
        app.admin.as_bytes(),
        parts.method.as_str(),
        parts.uri.path(),
        &bytes,
        now(),
        &app.nonces,
    )
    .map_err(|message| error(StatusCode::UNAUTHORIZED, message).into_response())?;
    let mut request = axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes));
    request.extensions_mut().insert(actor);
    Ok(request)
}
/// Audit action names of administrative mutation endpoints.
fn action_for(method: &axum::http::Method, path: &str) -> Option<&'static str> {
    use axum::http::Method;
    Some(match (method, path) {
        (&Method::PUT, "/v1/policy") => "policy.replace",
        (&Method::PUT, "/v1/policy/document") => "policy.document.replace",
        (&Method::POST, "/v1/blocks") => "blocks.add",
        (&Method::DELETE, "/v1/blocks") => "blocks.remove",
        (&Method::POST, "/v1/candidates/approve") => "candidates.approve",
        (&Method::PUT, "/v1/rules") => "rules.replace",
        (&Method::PUT, "/v1/rules/lua") => "rules.lua.replace",
        (&Method::POST, "/v1/geoip/reload") => "geoip.reload",
        (&Method::POST, "/v1/update/check") => "update.check",
        (&Method::POST, "/v1/allowlist") => "allowlist.add",
        (&Method::DELETE, "/v1/allowlist") => "allowlist.remove",
        (&Method::POST, "/v1/zones") => "zones.change",
        (&Method::DELETE, "/v1/zones") => "zones.remove",
        _ => return None,
    })
}
fn action_target(action: &str) -> &'static str {
    match action.split('.').next() {
        Some("policy") => "policy",
        Some("allowlist") => "allowlist",
        Some("zones") => "zones",
        Some("blocks") | Some("candidates") => "blocks",
        Some("rules") => "rules",
        Some("geoip") => "geoip",
        Some("update") => "update",
        _ => "unknown",
    }
}
async fn audit_get(
    HttpState(app): HttpState<App>,
    query: Result<axum::extract::Query<audit::Filter>, axum::extract::rejection::QueryRejection>,
) -> ApiResult {
    let axum::extract::Query(filter) = query.map_err(|e| {
        error(
            StatusCode::BAD_REQUEST,
            format!("invalid audit filter: {e}"),
        )
    })?;
    audit_query(app, filter).await
}
async fn audit_post(
    HttpState(app): HttpState<App>,
    Json(filter): Json<audit::Filter>,
) -> ApiResult {
    audit_query(app, filter).await
}
async fn audit_query(app: App, filter: audit::Filter) -> ApiResult {
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let db = app
            .db
            .lock()
            .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
        audit::query(&db, app.audit, &filter)
            .map(Json)
            .map_err(|e| match e.downcast_ref::<rusqlite::Error>() {
                Some(_) => error(StatusCode::SERVICE_UNAVAILABLE, "audit store unavailable"),
                None => error(StatusCode::BAD_REQUEST, e),
            })
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}
fn open_database(path: &std::path::Path) -> anyhow::Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);")?;
    audit::init(&db)?;
    Ok(db)
}

async fn update_status(HttpState(app): HttpState<App>) -> ApiResult {
    let Some(path) = app.update_status else {
        return Ok(Json(
            json!({"enabled":false,"phase":"disabled","current_version":env!("CARGO_PKG_VERSION")}),
        ));
    };
    let result = tokio::task::spawn_blocking(move || read_bounded(&path, 16 * 1024))
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "update status unavailable"))?;
    let bytes =
        result.map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "update status unavailable"))?;
    Ok(Json(serde_json::from_slice(&bytes).map_err(|_| {
        error(StatusCode::SERVICE_UNAVAILABLE, "invalid update status")
    })?))
}

async fn update_check(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): Admin,
) -> MutationResult {
    let Some(path) = app.update_request.clone() else {
        refuse_unapplied(
            &app,
            Change::new(actor, "update.check", Scope::Policy, "update"),
            "automatic updates are disabled".into(),
        )
        .await;
        return Err(error(
            StatusCode::CONFLICT,
            "automatic updates are disabled",
        ));
    };
    // Two-phase: the request file is outside SQLite, so record `uncertain`
    // first, then finalize. A crash in between truthfully stays uncertain.
    let mut record = audit::Record::new(actor, "update.check", "update");
    record.result = audit::Outcome::Uncertain;
    record.summary = "signed release check requested from the supervisor".into();
    let id = record.id.clone();
    let audit_app = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut db = audit_app
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database unavailable"))?;
        audit::insert_alone(&mut db, audit_app.audit, &record)
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "audit worker failed"))?
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit write failed; update check not queued",
        )
    })?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let queued = match options.open(path).await {
        Ok(file) => file.sync_all().await.is_ok(),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => true,
        Err(_) => false,
    };
    let finish_app = app.clone();
    let finish_id = id.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let db = finish_app
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database unavailable"))?;
        if queued {
            audit::finish(&db, &finish_id, audit::Outcome::Committed, None)
        } else {
            audit::finish(
                &db,
                &finish_id,
                audit::Outcome::Refused,
                Some("could not queue update check"),
            )
        }
    })
    .await;
    if !queued {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not queue update check",
        ));
    }
    Ok(audit_header(
        Json(json!({"queued":true})).into_response(),
        &id,
    ))
}

fn read_bounded(path: &std::path::Path, max: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "configured input is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= max, "configured input exceeds size limit");
    Ok(bytes)
}

fn check_configuration(args: &Args) -> anyhow::Result<()> {
    if let Some(path) = &args.kubernetes_authority {
        kubernetes_authority::Config::load(path)?;
        kubernetes_authority::Owner::new()?;
    }

    if args.update_github || args.update_manifest.is_some() {
        let key = std::env::var(&args.update_key_env)
            .map_err(|_| anyhow::anyhow!("update public-key environment variable unavailable"))?;
        guard_update::update::TrustKey::from_base64(&key)?;
    }
    if let Some(path) = &args.update_ca {
        reqwest::Certificate::from_pem(&read_bounded(path, 128 * 1024)?)?;
    }
    let collector = std::env::var("HANGANG_GUARD_COLLECTOR_TOKEN")?;
    let admin = std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?;
    anyhow::ensure!(
        (16..=4096).contains(&collector.len())
            && (16..=4096).contains(&admin.len())
            && collector != admin,
        "tokens must be distinct and 16..4096 bytes"
    );
    metrics_token(&collector, &admin)?;
    let mut fresh_database = true;
    let mut engine = if args.database.exists() {
        let db = Connection::open_with_flags(
            &args.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let saved = db.query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| {
            r.get::<_, String>(0)
        });
        match saved {
            Ok(body) => {
                fresh_database = false;
                Engine::restore(serde_json::from_str(&body)?)?
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Engine::new(Policy::default())?,
            Err(e) => return Err(e.into()),
        }
    } else {
        let parent = args
            .database
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        anyhow::ensure!(parent.is_dir(), "database directory does not exist");
        Engine::new(Policy::default())?
    };
    if fresh_database && let Some(path) = &args.bootstrap_policy {
        engine.set_policy(serde_json::from_slice(&read_bounded(path, 1024 * 1024)?)?)?;
    }
    if let Some(path) = &args.policy {
        engine.set_policy(serde_json::from_slice(&read_bounded(
            path,
            4 * 1024 * 1024,
        )?)?)?;
    }
    if let Some(path) = &args.asn_catalog {
        engine.set_asn_catalog(serde_json::from_slice(&read_bounded(
            path,
            16 * 1024 * 1024,
        )?)?)?;
    }
    if let Some(cert) = &args.decision_tls_cert {
        protocol::tls_acceptor(
            cert,
            args.decision_tls_key.as_ref().unwrap(),
            args.decision_client_ca.as_ref().unwrap(),
        )?;
    }
    geoip::GeoCatalog::load(&geoip::GeoPaths {
        country: args.geoip_database.clone(),
        asn: args.geoip_asn_database.clone(),
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn worker_arguments() -> Vec<std::ffi::OsString> {
    let mut input = std::env::args_os().skip(1);
    let mut result = Vec::new();
    while let Some(arg) = input.next() {
        let name = arg.to_str().unwrap_or("").split('=').next().unwrap_or("");
        if matches!(
            name,
            "--supervised"
                | "--serve-child"
                | "--update-github"
                | "--check"
                | "--check-update"
                | "--about"
        ) {
            continue;
        }
        if matches!(
            name,
            "--update-manifest"
                | "--update-ca"
                | "--update-key-env"
                | "--update-interval-seconds"
                | "--update-status-file"
                | "--update-grace-seconds"
        ) {
            if !arg.to_str().unwrap_or("").contains('=') {
                input.next();
            }
            continue;
        }
        result.push(arg);
    }
    result
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(path) = &args.evaluate_kubernetes_policy {
        println!(
            "{}",
            kubernetes::evaluate_policy(&read_bounded(path, 1024 * 1024)?)?
        );
        return Ok(());
    }
    if let Some(path) = &args.check_kubernetes_pod_facts {
        println!(
            "{}",
            kubernetes::check_pod_facts(&read_bounded(path, 1024 * 1024)?)?
        );
        return Ok(());
    }
    if let Some(path) = &args.check_kubernetes_selector {
        kubernetes::compile_selector(&read_bounded(path, 65536)?)?;
        println!("Kubernetes selector shape, label syntax and predicate bounds: valid");
        return Ok(());
    }
    if args.about {
        println!(
            "{}",
            json!({"name":"sumunjang","version":env!("CARGO_PKG_VERSION"),"repository":"https://github.com/ziozzang/sumunjang","role":"zero-trust IP/network decision authority","principal_management":"hopae","target":env!("GUARD_TARGET"),"supervised_updates":cfg!(target_os="linux")})
        );
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads as usize)
        .enable_all()
        .build()?
        .block_on(run(args))
}
async fn run(args: Args) -> anyhow::Result<()> {
    if let Some(path) = &args.observe_kubernetes_policy {
        println!(
            "{}",
            kubernetes::observe_source(&read_bounded(path, 16384)?).await?
        );
        return Ok(());
    }
    if args.check_update {
        let release = guard_update::github_release::latest().await?;
        println!(
            "{}",
            serde_json::to_string(&release.check(
                semver::Version::parse(env!("CARGO_PKG_VERSION"))?,
                env!("GUARD_TARGET")
            )?)?
        );
        return Ok(());
    }
    if let Some(address) = args.decision_listen {
        anyhow::ensure!(
            (address.ip().is_loopback() || args.decision_tls_cert.is_some())
                && !address.ip().is_multicast(),
            "remote binary decision listener requires mTLS"
        );
    }
    // One reloadable source of TLS material for every mTLS listener.
    let tls_reloader = args
        .decision_tls_cert
        .as_ref()
        .map(|cert| {
            tls_reload::TlsReloader::new(tls_reload::TlsFiles {
                cert: cert.clone(),
                key: args.decision_tls_key.clone().unwrap(),
                ca: args.decision_client_ca.clone().unwrap(),
            })
        })
        .transpose()?;
    if let Some(r) = &tls_reloader {
        eprintln!(
            "tls: loaded certificate material; leaf sha256 {}",
            r.fingerprint()
        );
    }
    let management_tls = if args.management_tls {
        tls_reloader.as_ref().map(|r| r.management())
    } else {
        None
    };
    let decision_tls = tls_reloader.as_ref().map(|r| r.hgd1());
    if args.check {
        check_configuration(&args)?;
        println!("configuration valid");
        return Ok(());
    }
    if args.supervised && !args.serve_child {
        #[cfg(target_os = "linux")]
        {
            check_configuration(&args)?;
            let update = if args.update_github || args.update_manifest.is_some() {
                let public_key = std::env::var(&args.update_key_env).map_err(|_| {
                    anyhow::anyhow!("update public-key environment variable unavailable")
                })?;
                guard_update::update::TrustKey::from_base64(&public_key)?;
                Some(supervisor::UpdateOptions {
                    manifest_url: args.update_manifest.clone(),
                    github: args.update_github,
                    additional_ca: args.update_ca.clone(),
                    public_key,
                    interval: std::time::Duration::from_secs(args.update_interval_seconds),
                    status_path: args
                        .update_status_file
                        .clone()
                        .unwrap_or_else(|| args.database.with_extension("update-status.json")),
                })
            } else {
                None
            };
            return supervisor::run(supervisor::Options {
                http: args.listen.parse().map_err(|_| {
                    anyhow::anyhow!("supervised listener must be a literal IP:port")
                })?,
                decision: args.decision_listen,
                grpc: args.grpc_listen,
                readiness: args.readiness_listen,
                database: args.database.clone(),
                worker_arguments: worker_arguments(),
                update,
                grace: std::time::Duration::from_secs(args.update_grace_seconds),
            })
            .await;
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("supervised automatic updates require Linux");
    }
    if args.serve_child {
        anyhow::ensure!(
            std::env::var("HANGANG_GUARD_WORKER").as_deref() == Ok("1"),
            "private worker handshake unavailable"
        );
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("supervised workers require Linux");
    }
    let collector = std::env::var("HANGANG_GUARD_COLLECTOR_TOKEN")?;
    let admin = std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?;
    anyhow::ensure!(
        (16..=4096).contains(&collector.len())
            && (16..=4096).contains(&admin.len())
            && collector != admin,
        "tokens must be distinct and 16..4096 bytes"
    );
    let metrics_token = metrics_token(&collector, &admin)?.map(Arc::new);
    let mut db = open_database(&args.database)?;
    let saved = db.query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| {
        r.get::<_, String>(0)
    });
    let fresh_database = matches!(saved, Err(rusqlite::Error::QueryReturnedNoRows));
    let mut engine = match saved {
        Ok(body) => Engine::restore(serde_json::from_str(&body)?)?,
        Err(rusqlite::Error::QueryReturnedNoRows) => Engine::new(Policy::default())?,
        Err(e) => return Err(e.into()),
    };
    let audit_retention = audit::Retention {
        max_rows: args.audit_max_rows,
        max_days: args.audit_retention_days,
    };
    engine.set_history(Arc::new(Mutex::new(
        guard_core::history::SignalHistory::new(args.history_hours * 3600),
    )));
    let startup_before = Some(engine.clone());
    if fresh_database && let Some(path) = args.bootstrap_policy {
        engine.set_policy(serde_json::from_slice(&read_bounded(&path, 1024 * 1024)?)?)?;
    }
    if let Some(path) = args.policy {
        engine.set_policy(serde_json::from_slice(&std::fs::read(path)?)?)?;
    }
    if let Some(path) = args.asn_catalog {
        engine.set_asn_catalog(serde_json::from_slice(&std::fs::read(path)?)?)?;
    }
    // Startup configuration files that change stored policy are audited with
    // the checkpoint that makes them durable.
    let startup_record = startup_before.and_then(|before| {
        let changed = audit::state_digest(&before) != audit::state_digest(&engine);
        changed.then(|| {
            let mut record = audit::Record::new(actor::Actor::local(), "startup.import", "policy");
            record.revision_before = Some(before.revision());
            record.revision_after = Some(engine.revision());
            record.policy_revision = Some(engine.policy_revision());
            record.before_digest = Some(audit::state_digest(&before));
            record.after_digest = Some(audit::state_digest(&engine));
            record.summary = format!(
                "{}; {}",
                audit::policy_summary(before.policy(), engine.policy()),
                audit::rules_summary(before.rules(), engine.rules())
            );
            record
        })
    });
    persist_state_audited(
        &mut db,
        &engine.state(),
        startup_record.as_ref().map(|r| (r, audit_retention)),
    )
    .map_err(PersistError::into_inner)?;
    let geo_paths = geoip::GeoPaths {
        country: args.geoip_database,
        asn: args.geoip_asn_database,
    };
    let geo = geoip::GeoCatalog::load(&geo_paths)?;
    let native_config = args
        .kubernetes_authority
        .as_ref()
        .map(|p| kubernetes_authority::Config::load(p))
        .transpose()?;
    let native_source = native_config
        .as_ref()
        .map(|_| kubernetes_authority::Owner::new())
        .transpose()?;
    let app = App {
        audit: audit_retention,
        nonces: actor::Nonces::default(),
        allow_expired_keep: args.allow_expired_retention_days * 86_400,
        tls: tls_reloader.clone(),
        checkpoint_failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        metrics_token,
        native_source,
        network_source: Arc::new(arc_swap::ArcSwapOption::empty()),
        network_source_phase: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        geo: Arc::new(arc_swap::ArcSwap::from_pointee(geo)),
        geo_paths: Arc::new(geo_paths),
        geo_reload: Arc::new(tokio::sync::Semaphore::new(1)),
        max_http_requests: args.max_http_requests as usize,
        view: Arc::new(arc_swap::ArcSwap::from_pointee(engine.decision_view())),
        inner: Arc::new(Mutex::new(Inner { engine })),
        db: Arc::new(Mutex::new(db)),
        workers: Arc::new(tokio::sync::Semaphore::new(1024)),
        collector: Arc::new(collector),
        admin: Arc::new(admin),
        update_status: args
            .serve_child
            .then(|| std::env::var_os("HANGANG_GUARD_UPDATE_STATUS").map(PathBuf::from))
            .flatten(),
        update_request: args
            .serve_child
            .then(|| std::env::var_os("HANGANG_GUARD_UPDATE_REQUEST").map(PathBuf::from))
            .flatten(),
    };
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let native_worker = native_config.map(|config| {
        tokio::spawn(kubernetes_authority::follow(
            app.clone(),
            config,
            stop_rx.clone(),
        ))
    });
    if let Some(path) = args.kubernetes_policy_source {
        tokio::spawn(kubernetes::follow_source(
            path,
            app.network_source.clone(),
            app.network_source_phase.clone(),
            stop_rx.clone(),
        ));
    }
    let readiness_worker = if let Some(address) = args.readiness_listen {
        let listener = if args.serve_child {
            #[cfg(target_os = "linux")]
            {
                supervisor::inherited_listener("HANGANG_GUARD_READINESS_FD", address)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("supervised workers require Linux");
            }
        } else {
            tokio::net::TcpListener::bind(address).await?
        };
        Some(tokio::spawn(readiness::serve(
            listener,
            app.clone(),
            stop_rx.clone(),
        )))
    } else {
        None
    };
    let binary_worker = if let Some(address) = args.decision_listen {
        anyhow::ensure!(
            (address.ip().is_loopback() || args.decision_tls_cert.is_some())
                && !address.ip().is_multicast(),
            "remote binary decision listener requires mTLS"
        );
        let binary = if args.serve_child {
            #[cfg(target_os = "linux")]
            {
                supervisor::inherited_listener("HANGANG_GUARD_DECISION_FD", address)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("supervised workers require Linux");
            }
        } else {
            tokio::net::TcpListener::bind(address).await?
        };
        eprintln!("binary decisions listening on {}", binary.local_addr()?);
        Some(tokio::spawn(protocol::serve_with_tls(
            binary,
            app.clone(),
            stop_rx.clone(),
            decision_tls,
        )))
    } else {
        None
    };
    let grpc_worker = if let Some(address) = args.grpc_listen {
        let tls = tls_reloader
            .as_ref()
            .map(|r| r.grpc())
            .ok_or_else(|| anyhow::anyhow!("gRPC requires decision TLS material"))?;
        let listener = if args.serve_child {
            #[cfg(target_os = "linux")]
            {
                supervisor::inherited_listener("HANGANG_GUARD_GRPC_FD", address)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("supervised workers require Linux");
            }
        } else {
            tokio::net::TcpListener::bind(address).await?
        };
        Some(tokio::spawn(grpc::serve(
            listener,
            tls,
            app.clone(),
            stop_rx.clone(),
        )))
    } else {
        None
    };
    if let Some(reloader) = tls_reloader.clone()
        && args.tls_reload_seconds > 0
    {
        tokio::spawn(tls_reload::follow(
            reloader,
            std::time::Duration::from_secs(args.tls_reload_seconds),
            stop_rx.clone(),
        ));
    }
    let checkpoint_app = app.clone();
    let worker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {_ = interval.tick()=>{let a=checkpoint_app.clone();if let Err(e)=checkpoint(a).await {eprintln!("checkpoint failed: {e}");} console_api::prune_expired_allow(checkpoint_app.clone()).await;}, _=stop_rx.changed()=>break}
        }
    });
    let listener = if args.serve_child {
        #[cfg(target_os = "linux")]
        {
            supervisor::inherited_listener("HANGANG_GUARD_HTTP_FD", args.listen.parse()?)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("supervised workers require Linux");
        }
    } else {
        tokio::net::TcpListener::bind(&args.listen).await?
    };
    eprintln!("sumunjang listening on {}", listener.local_addr()?);
    let shutdown_stop = stop_tx.clone();
    if args.serve_child {
        // A replacement source-owned worker must obtain fresh authority before
        // the stable supervisor retires its previous generation.
        if app.native_source.is_some() {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while app.source_remaining(&app.view.load()).is_none() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| anyhow::anyhow!("native source not ready"))?;
        }
        #[cfg(target_os = "linux")]
        supervisor::notify_ready()?;
    }
    let stopping = async move {
        shutdown().await;
        let _ = shutdown_stop.send(true);
    };
    let serving = if let Some(config) = management_tls {
        tls_reload::serve_https(listener, config, router(app.clone()), stopping).await
    } else {
        let listener = listener.tap_io(|stream| {
            if let Err(e) = stream.set_nodelay(true) {
                eprintln!("HTTP TCP_NODELAY failed: {e}");
            }
        });
        axum::serve(listener, router(app.clone()))
            .with_graceful_shutdown(stopping)
            .await
            .map_err(anyhow::Error::from)
    };
    let _ = stop_tx.send(true);
    let _ = worker.await;
    if let Some(worker) = binary_worker {
        worker.await??;
    }
    if let Some(worker) = grpc_worker {
        worker.await??;
    }
    if let Some(worker) = readiness_worker {
        worker.await??;
    }
    if let Some(worker) = native_worker {
        worker.await?;
    }
    checkpoint(app).await?;
    serving?;
    Ok(())
}
async fn checkpoint(app: App) -> anyhow::Result<()> {
    let flag = app.checkpoint_failed.clone();
    let result = checkpoint_once(app).await;
    flag.store(result.is_err(), std::sync::atomic::Ordering::Release);
    let m = &guard_core::metrics::METRICS;
    if result.is_ok() {
        count(&m.checkpoint_success);
        m.checkpoint_last_success
            .store(now(), std::sync::atomic::Ordering::Relaxed);
    } else {
        count(&m.checkpoint_failure);
    }
    result
}
async fn checkpoint_once(app: App) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut db = app
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("database unavailable"))?;
        let state = {
            let inner = app
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("state unavailable"))?;
            inner.engine.state()
        };
        // Serialization and SQLite fsync run without holding the engine lock.
        persist_state(&mut db, &state)?;
        // Age retention also applies when no new audit rows arrive.
        audit::prune(&db, app.audit, now().saturating_mul(1000))?;
        Ok(())
    })
    .await?
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    pub(crate) fn app() -> App {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE checkpoint(id INTEGER PRIMARY KEY,body TEXT NOT NULL)")
            .unwrap();
        audit::init(&db).unwrap();
        App {
            audit: audit::Retention::default(),
            nonces: actor::Nonces::default(),
            allow_expired_keep: 30 * 86_400,
            tls: None,
            checkpoint_failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            metrics_token: Some(Arc::new("metrics-test-token".into())),
            native_source: None,
            network_source: Arc::new(arc_swap::ArcSwapOption::empty()),
            network_source_phase: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            geo: Arc::new(arc_swap::ArcSwap::from_pointee(geoip::GeoCatalog::default())),
            geo_paths: Arc::new(geoip::GeoPaths::default()),
            geo_reload: Arc::new(tokio::sync::Semaphore::new(1)),
            max_http_requests: 4096,
            view: Arc::new(arc_swap::ArcSwap::from_pointee(
                Engine::new(Policy::default()).unwrap().decision_view(),
            )),
            inner: Arc::new(Mutex::new(Inner {
                engine: Engine::new(Policy::default()).unwrap(),
            })),
            db: Arc::new(Mutex::new(db)),
            workers: Arc::new(tokio::sync::Semaphore::new(1024)),
            collector: Arc::new("collector-test-token".into()),
            admin: Arc::new("admin-test-token".into()),
            update_status: None,
            update_request: None,
        }
    }

    async fn request(
        app: App,
        path: &str,
        method: &str,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let r = router(app)
            .oneshot(
                Request::builder()
                    .uri(path)
                    .method(method)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    #[tokio::test]
    async fn kubernetes_diagnostics_require_admin_and_refuse_absent_authority() {
        let state = app();
        for (path, method, body) in [
            ("/v1/kubernetes/status", "GET", json!({})),
            (
                "/v1/kubernetes/evaluate",
                "POST",
                json!({"namespace":"example","labels":{},"direction":"Ingress","peer":"192.0.2.1","protocol":"TCP","port":443}),
            ),
        ] {
            assert_eq!(
                request(
                    state.clone(),
                    path,
                    method,
                    "collector-test-token",
                    body.clone()
                )
                .await
                .0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                request(state.clone(), path, method, "admin-test-token", body)
                    .await
                    .0,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }
    #[tokio::test]
    async fn separated_credentials() {
        let a = app();
        assert_eq!(
            request(
                a.clone(),
                "/v1/status",
                "GET",
                "collector-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/snapshot",
                "GET",
                "admin-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(a, "/v1/status", "GET", "admin-test-token", json!(null))
                .await
                .0,
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn policy_document_parallel_publish_has_one_winner() {
        let a = app();
        let (_, document) = request(
            a.clone(),
            "/v1/policy/document",
            "GET",
            "admin-test-token",
            json!({}),
        )
        .await;
        let input =
            json!({"expected_revision": document["revision"], "policy": document["policy"]});
        let (one, two) = tokio::join!(
            request(
                a.clone(),
                "/v1/policy/document",
                "PUT",
                "admin-test-token",
                input.clone()
            ),
            request(
                a.clone(),
                "/v1/policy/document",
                "PUT",
                "admin-test-token",
                input
            )
        );
        assert!(
            (one.0 == StatusCode::OK && two.0 == StatusCode::CONFLICT)
                || (two.0 == StatusCode::OK && one.0 == StatusCode::CONFLICT)
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy/document",
                "GET",
                "collector-test-token",
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                a,
                "/v1/policy/document",
                "PUT",
                "collector-test-token",
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn policy_document_two_client_race_and_legacy_compatibility() {
        let a = app();
        let get = |a| {
            request(
                a,
                "/v1/policy/document",
                "GET",
                "admin-test-token",
                json!({}),
            )
        };
        // Both clients have read before either is allowed to publish. No sleeps.
        let (_, first) = get(a.clone()).await;
        let (_, second) = get(a.clone()).await;
        assert_eq!(first, second);
        let mut winner = second["policy"].clone();
        winner["mode"] = json!("enforce");
        winner["threshold"] = json!(77);
        let (status, published) = request(
            a.clone(),
            "/v1/policy/document",
            "PUT",
            "admin-test-token",
            json!({"expected_revision":second["revision"],"policy":winner}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Allow-save from an older GET cannot replace security settings.
        let mut stale = first["policy"].clone();
        stale["allow"] = json!(["203.0.113.1/32"]);
        let before = serde_json::to_value(a.inner.lock().unwrap().engine.state()).unwrap();
        let response = request(
            a.clone(),
            "/v1/policy/document",
            "PUT",
            "admin-test-token",
            json!({"expected_revision":first["revision"],"policy":stale}),
        )
        .await;
        assert_eq!(response.0, StatusCode::CONFLICT);
        assert_eq!(get(a.clone()).await.1, published);
        assert_eq!(
            serde_json::to_value(a.inner.lock().unwrap().engine.state()).unwrap(),
            before
        );
        // Explicit reconciliation keeps current settings and publishes a valid draft.
        let mut reconciled = published["policy"].clone();
        reconciled["allow"] = stale["allow"].clone();
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy/document",
                "PUT",
                "admin-test-token",
                json!({"expected_revision":published["revision"],"policy":reconciled})
            )
            .await
            .0,
            StatusCode::OK
        );
        let current = get(a.clone()).await.1;
        // Native wire remains compatible; every successful legacy writer invalidates drafts.
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy",
                "GET",
                "admin-test-token",
                json!({})
            )
            .await
            .1,
            current["policy"]
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy",
                "PUT",
                "admin-test-token",
                current["policy"].clone()
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_ne!(get(a.clone()).await.1["revision"], current["revision"]);
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy/document",
                "PUT",
                "admin-test-token",
                json!({"expected_revision":current["revision"],"policy":current["policy"]})
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let inner = a.inner.lock().unwrap();
        let restored = Engine::restore(inner.engine.state()).unwrap();
        assert_eq!(restored.policy_revision(), inner.engine.policy_revision());
    }
    #[tokio::test]
    async fn policy_checkpoint_and_failure_rollback() {
        let a = app();
        let p = json!({"mode":"enforce","auto_block":false});
        assert_eq!(
            request(a.clone(), "/v1/policy", "PUT", "admin-test-token", p)
                .await
                .0,
            StatusCode::OK
        );
        {
            let db = a.db.lock().unwrap();
            let body: String = db
                .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
                .unwrap();
            let restored = Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
            assert_eq!(restored.policy().mode, guard_core::Mode::Enforce);
            db.execute_batch("DROP TABLE checkpoint").unwrap();
        }
        let document = request(
            a.clone(),
            "/v1/policy/document",
            "GET",
            "admin-test-token",
            json!({}),
        )
        .await
        .1;
        let mut replacement = document["policy"].clone();
        replacement["mode"] = json!("observe");
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy/document",
                "PUT",
                "admin-test-token",
                json!({"expected_revision":document["revision"],"policy":replacement})
            )
            .await
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy/document",
                "GET",
                "admin-test-token",
                json!({})
            )
            .await
            .1,
            document
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/policy",
                "PUT",
                "admin-test-token",
                json!({"mode":"observe"})
            )
            .await
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            a.inner.lock().unwrap().engine.policy().mode,
            guard_core::Mode::Enforce
        );
    }
    #[tokio::test]
    async fn invalid_events_and_approval_persist() {
        let a = app();
        let time = now();
        assert_eq!(request(a.clone(),"/v1/events","POST","collector-test-token",json!({"source_id":"test","events":[{"ip":"192.0.2.1","kind":"honeypot","observed_at":time-301}]})).await.0,StatusCode::BAD_REQUEST);
        assert_eq!(request(a.clone(),"/v1/events","POST","collector-test-token",json!({"source_id":"test","events":[{"ip":"192.0.2.1","kind":"honeypot","observed_at":time}]})).await.0,StatusCode::OK);
        assert_eq!(
            request(
                a.clone(),
                "/v1/candidates/approve",
                "POST",
                "admin-test-token",
                json!({"ip":"192.0.2.1"})
            )
            .await
            .0,
            StatusCode::OK
        );
        let db = a.db.lock().unwrap();
        let body: String = db
            .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let mut restored = Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
        assert_eq!(restored.snapshot(time).blocks.len(), 1);
    }
    #[tokio::test]
    async fn rules_geo_lookup_durability_and_snapshot_rejection() {
        let a = app();
        let paths = geoip::GeoPaths {
            country: Some(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/GeoIP2-Country-Test.mmdb"),
            ),
            asn: None,
        };
        a.geo
            .store(Arc::new(geoip::GeoCatalog::load(&paths).unwrap()));
        assert_eq!(
            request(
                a.clone(),
                "/v1/lookup",
                "POST",
                "collector-test-token",
                json!({"ip":"81.2.69.160"})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let rules = json!({"version":1,"rules":[{"id":"gb","priority":10,"countries":["gb"],"action":"deny","score":10},{"id":"network-watch","network":"192.0.2.0/24","action":"observe","score":7}]});
        let (status, validated) = request(
            a.clone(),
            "/v1/rules/validate",
            "POST",
            "admin-test-token",
            json!({"rules":rules}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(validated["rules"]["rules"][0]["countries"][0], "GB");
        assert_eq!(a.inner.lock().unwrap().engine.rules().rules.len(), 0);
        request(
            a.clone(),
            "/v1/policy",
            "PUT",
            "admin-test-token",
            json!({"mode":"enforce"}),
        )
        .await;
        assert_eq!(
            request(a.clone(), "/v1/rules", "PUT", "admin-test-token", rules)
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/snapshot",
                "GET",
                "collector-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
        for kind in [None, Some("honeypot")] {
            let mut input = json!({"source_id":"test","ip":"81.2.69.160"});
            if let Some(kind) = kind {
                input["kind"] = json!(kind);
            }
            let (_, decision) = request(
                a.clone(),
                "/v1/decision",
                "POST",
                "collector-test-token",
                input,
            )
            .await;
            assert_eq!(decision["action"], "deny");
        }
        let (_, unknown) = request(
            a.clone(),
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1"}),
        )
        .await;
        assert_eq!(unknown["action"], "allow");
        let (_, found) = request(
            a.clone(),
            "/v1/lookup",
            "POST",
            "admin-test-token",
            json!({"ip":"81.2.69.160"}),
        )
        .await;
        assert_eq!(found["geoip"]["country_code"], "GB");
        assert_eq!(found["inspection"]["score"], 10);
        assert_eq!(found["inspection"]["suspicion"], "blocked");
        let (_, network) = request(
            a.clone(),
            "/v1/networks/inspect",
            "POST",
            "admin-test-token",
            json!({"network":"192.0.2.31/24"}),
        )
        .await;
        assert_eq!(network["network"], "192.0.2.0/24");
        assert_eq!(network["static_rule_score"], 7);
        let body: String =
            a.db.lock()
                .unwrap()
                .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
                .unwrap();
        let restored = Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
        assert_eq!(restored.rules().rules.len(), 2);
        let script = "return {version=1,rules={{id='lua-watch',network='192.0.2.0/24',action='observe',score=3}}}";
        assert_eq!(
            request(
                a.clone(),
                "/v1/rules/lua",
                "PUT",
                "admin-test-token",
                json!({"script":script})
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            a.inner.lock().unwrap().engine.rules().rules[0].id,
            "lua-watch"
        );
        assert_eq!(
            request(
                a,
                "/v1/rules/validate",
                "POST",
                "admin-test-token",
                json!({"rules":{"version":1,"rules":[]},"script":script})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn failed_geo_reload_preserves_last_good() {
        let mut a = app();
        let path = std::env::temp_dir().join(format!(
            "guard-geo-test-{}-{}.mmdb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/GeoIP2-Country-Test.mmdb"),
            &path,
        )
        .unwrap();
        a.geo_paths = Arc::new(geoip::GeoPaths {
            country: Some(path.clone()),
            asn: None,
        });
        assert_eq!(
            request(
                a.clone(),
                "/v1/geoip/reload",
                "POST",
                "admin-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::OK
        );
        std::fs::write(&path, b"invalid").unwrap();
        assert_eq!(
            request(
                a.clone(),
                "/v1/geoip/reload",
                "POST",
                "admin-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            a.geo.load().context("81.2.69.160".parse().unwrap()).country,
            Some("GB")
        );
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Deliberately prove queries bypass both held locks.
    async fn plain_decision_does_not_wait_for_engine_or_database() {
        let a = app();
        let held = a.clone();
        let engine_lock = held.inner.lock().unwrap();
        let database_lock = held.db.lock().unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            request(
                a,
                "/v1/decision",
                "POST",
                "collector-test-token",
                json!({"source_id":"test","ip":"192.0.2.1"}),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["action"], "allow");
        drop(engine_lock);
        drop(database_lock);
    }
    #[tokio::test]
    async fn active_blocks_admin_only_and_headers() {
        let a = app();
        assert_eq!(
            request(
                a.clone(),
                "/v1/blocks",
                "GET",
                "collector-test-token",
                json!(null)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request(
                a.clone(),
                "/v1/blocks",
                "POST",
                "admin-test-token",
                json!({"network":"192.0.2.0/24","expires_at":now()+300,"reason":"manual"})
            )
            .await
            .0,
            StatusCode::OK
        );
        let (status, blocks) = request(
            a.clone(),
            "/v1/blocks",
            "GET",
            "admin-test-token",
            json!(null),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(blocks[0]["network"], "192.0.2.0/24");
        let response = router(a.clone())
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let response = router(a)
            .oneshot(
                Request::builder()
                    .uri("/v1/blocks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    #[tokio::test]
    async fn remote_decision_blocks_without_renewal() {
        let a = app();
        assert_eq!(
            request(
                a.clone(),
                "/v1/decision",
                "POST",
                "admin-test-token",
                json!({"source_id":"test","ip":"192.0.2.1"})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        request(
            a.clone(),
            "/v1/policy",
            "PUT",
            "admin-test-token",
            json!({"mode":"enforce","auto_block":true}),
        )
        .await;
        let (_, first) = request(
            a.clone(),
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1","kind":"honeypot"}),
        )
        .await;
        assert_eq!(first["action"], "deny");
        assert!(first["ttl_ms"].as_u64().unwrap() <= 5000);
        let before = a.inner.lock().unwrap().engine.stats().accepted;
        let (_, second) = request(
            a.clone(),
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1","kind":"honeypot"}),
        )
        .await;
        assert_eq!(second["action"], "deny");
        assert_eq!(a.inner.lock().unwrap().engine.stats().accepted, before);
        request(
            a.clone(),
            "/v1/policy",
            "PUT",
            "admin-test-token",
            json!({"mode":"enforce","allow":["192.0.2.1/32"]}),
        )
        .await;
        let (_, allowed) = request(
            a,
            "/v1/decision",
            "POST",
            "collector-test-token",
            json!({"source_id":"test","ip":"192.0.2.1"}),
        )
        .await;
        assert_eq!(allowed["action"], "allow");
    }
    #[tokio::test]
    async fn body_and_batch_bounds() {
        let a = app();
        let response = router(a.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .method("POST")
                    .header("authorization", "Bearer collector-test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(vec![b' '; 4 * 1024 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let event = json!({"ip":"192.0.2.1","kind":"scanner","observed_at":now()});
        assert_eq!(
            request(
                a,
                "/v1/events",
                "POST",
                "collector-test-token",
                json!({"source_id":"test","events":vec![event;257]})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}
