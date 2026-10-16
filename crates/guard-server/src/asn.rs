//! ASN prefix pools and reviewed ASN block proposals (original requirements
//! steps 4–6).
//!
//! * Signed, versioned ASN prefix bundles (`sumunjang.asn-bundle.v1`, Ed25519
//!   under a dedicated bundle key, domain-separated from release manifests):
//!   offline import CLI, upload API and optional scheduled fetch from an
//!   operator-configured HTTPS URL (no default). Monotonic versions, last-good
//!   rollback, bounded size, per-refresh diff report, audited install.
//! * ASN block proposals: draft → pending → approved/rejected → active →
//!   expired/withdrawn, with impact analysis, a configurable two-person rule
//!   and audited transitions. Activation is always an explicit administrator
//!   action that compiles the reviewed networks into blocks with source
//!   `asn_proposal`; nothing activates automatically.
use crate::{
    ApiResult, App, MutationResult, PersistError, actor::Actor, audit, count, error, now,
    persist_with,
};
use axum::{
    Json,
    extract::{Path as UrlPath, State as HttpState},
    http::StatusCode,
    response::IntoResponse,
};
use guard_core::{
    AsnPrefix, Block, BlockOrigin, BlockSource, Engine, FieldError, Mode, canonical_ip,
    canonical_network, prefix::PrefixTrie, trace::NoTrace,
};
use guard_update::update::TrustKey;
use ipnet::IpNet;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

pub const BUNDLE_DOMAIN: &str = "sumunjang.asn-bundle.v1";
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PREVIOUS: i64 = 2;
const MAX_PROPOSALS: i64 = 1000;
const MAX_NETWORKS: usize = 4096;
const MAX_PROPOSAL_DAYS: u64 = 30;
const BLOCK_TTL_MAX: u64 = 604_800;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS asn_bundles(
 version INTEGER PRIMARY KEY,
 installed_at INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 envelope BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('current','previous','rolled_back')));
CREATE TABLE IF NOT EXISTS asn_proposals(
 id TEXT PRIMARY KEY,
 created_at INTEGER NOT NULL,
 state TEXT NOT NULL,
 body TEXT NOT NULL);";

// ===================================================================== config

#[derive(Default, Clone, Serialize)]
pub struct FetchStatus {
    pub last_attempt: Option<u64>,
    pub last_success: Option<u64>,
    pub last_error: Option<String>,
    pub last_version: Option<u64>,
    pub attempts: u64,
    pub failures: u64,
}

/// ASN configuration and fetch state shared by the router.
pub struct AsnState {
    pub key: Option<TrustKey>,
    pub url: Option<String>,
    pub ca: Option<std::path::PathBuf>,
    pub interval_secs: u64,
    pub required_approvals: u8,
    pub fetch: Mutex<FetchStatus>,
}
impl AsnState {
    pub fn new(
        key: Option<TrustKey>,
        url: Option<String>,
        ca: Option<std::path::PathBuf>,
        interval_secs: u64,
        required_approvals: u8,
    ) -> Arc<Self> {
        Arc::new(Self {
            key,
            url,
            ca,
            interval_secs,
            required_approvals,
            fetch: Mutex::new(FetchStatus::default()),
        })
    }
    #[cfg(test)]
    pub fn disabled() -> Arc<Self> {
        Self::new(None, None, None, 3600, 1)
    }
}
/// `HANGANG_GUARD_ASN_BUNDLE_KEY`: base64 Ed25519 public key for bundles.
pub fn key_from_env() -> anyhow::Result<Option<TrustKey>> {
    match std::env::var("HANGANG_GUARD_ASN_BUNDLE_KEY") {
        Ok(v) => Ok(Some(TrustKey::from_base64(&v)?)),
        Err(_) => Ok(None),
    }
}

// ===================================================================== bundles

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundlePayload {
    pub format: String,
    pub version: u64,
    pub created_at: u64,
    pub source: String,
    #[serde(default)]
    pub provenance: BTreeMap<String, String>,
    pub prefixes: Vec<AsnPrefix>,
}
fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn parse_payload(bytes: &[u8]) -> anyhow::Result<BundlePayload> {
    let p: BundlePayload = serde_json::from_slice(bytes)?;
    anyhow::ensure!(p.format == BUNDLE_DOMAIN, "unsupported bundle format");
    anyhow::ensure!(p.version > 0, "bundle version must be positive");
    anyhow::ensure!(p.created_at <= now() + 300, "bundle created in the future");
    anyhow::ensure!(text_ok(&p.source, 256), "invalid bundle source");
    anyhow::ensure!(
        p.provenance.len() <= 16
            && p.provenance
                .iter()
                .all(|(k, v)| text_ok(k, 64) && text_ok(v, 256)),
        "invalid bundle provenance"
    );
    anyhow::ensure!(
        p.prefixes.len() <= guard_core::MAX_BLOCKS,
        "bundle exceeds 100,000 prefixes"
    );
    Ok(p)
}
/// Verify a signed envelope and parse its payload.
pub fn verify_bundle(key: &TrustKey, envelope: &[u8]) -> anyhow::Result<BundlePayload> {
    let payload =
        guard_update::signed_bundle::verify(BUNDLE_DOMAIN, envelope, key, MAX_BUNDLE_BYTES)?;
    parse_payload(&payload)
}
/// Payload of a stored (already verified) envelope; re-verified when a key is set.
fn stored_payload(key: Option<&TrustKey>, envelope: &[u8]) -> anyhow::Result<BundlePayload> {
    match key {
        Some(k) => verify_bundle(k, envelope),
        None => {
            #[derive(Deserialize)]
            struct Env {
                payload: String,
            }
            use base64::Engine as _;
            let env: Env = serde_json::from_slice(envelope)?;
            parse_payload(&base64::engine::general_purpose::STANDARD.decode(env.payload)?)
        }
    }
}
fn current_row(db: &Connection) -> rusqlite::Result<Option<(u64, String, Vec<u8>)>> {
    db.query_row(
        "SELECT version, sha256, envelope FROM asn_bundles WHERE state='current'",
        [],
        |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?, r.get(2)?)),
    )
    .optional()
}
/// Load the installed bundle's catalog at startup (signed bundles win over
/// `--asn-catalog`).
pub fn load_installed(
    db: &Connection,
    engine: &mut Engine,
    key: Option<&TrustKey>,
) -> anyhow::Result<Option<u64>> {
    let Some((version, _, envelope)) = current_row(db)? else {
        return Ok(None);
    };
    let payload = stored_payload(key, &envelope)?;
    engine.set_asn_catalog(payload.prefixes)?;
    Ok(Some(version))
}

/// Per-refresh diff of two catalogs.
fn diff(before: &[AsnPrefix], after: &[AsnPrefix]) -> Value {
    let old: BTreeMap<&str, u32> = before.iter().map(|p| (p.network.as_str(), p.asn)).collect();
    let new: BTreeMap<&str, u32> = after.iter().map(|p| (p.network.as_str(), p.asn)).collect();
    let mut per_asn: BTreeMap<u32, (i64, i64)> = BTreeMap::new();
    let (mut added, mut removed, mut moved) = (Vec::new(), Vec::new(), Vec::new());
    for (n, a) in &new {
        match old.get(n) {
            None => {
                added.push(json!({"network": n, "asn": a}));
                per_asn.entry(*a).or_default().0 += 1;
            }
            Some(o) if o != a => {
                moved.push(json!({"network": n, "from": o, "to": a}));
                per_asn.entry(*a).or_default().0 += 1;
                per_asn.entry(*o).or_default().1 += 1;
            }
            _ => {}
        }
    }
    for (n, a) in &old {
        if !new.contains_key(n) {
            removed.push(json!({"network": n, "asn": a}));
            per_asn.entry(*a).or_default().1 += 1;
        }
    }
    let mut changes: Vec<(u32, i64, i64)> =
        per_asn.into_iter().map(|(a, (p, m))| (a, p, m)).collect();
    changes.sort_by_key(|(_, p, m)| std::cmp::Reverse(p + m));
    let (na, nr, nm) = (added.len(), removed.len(), moved.len());
    added.truncate(20);
    removed.truncate(20);
    moved.truncate(20);
    json!({
        "prefixes_before": before.len(), "prefixes_after": after.len(),
        "added": na, "removed": nr, "reassigned": nm,
        "samples": {"added": added, "removed": removed, "reassigned": moved},
        "top_asns": changes.iter().take(20).map(|(a, p, m)| json!({"asn": a, "added": p, "removed": m})).collect::<Vec<_>>(),
    })
}

pub enum Install {
    Envelope(Vec<u8>),
    Rollback,
}
fn refuse(code: StatusCode, m: impl ToString) -> (StatusCode, Json<Value>) {
    error(code, m)
}
/// Install a bundle (or roll back) on a locked database and engine clone, then
/// commit checkpoint + bundle rows + audit in one transaction. Shared by the
/// API, scheduled fetch and the offline CLI.
pub fn install_locked(
    db: &mut Connection,
    engine: &Engine,
    retention: audit::Retention,
    key: Option<&TrustKey>,
    actor: Actor,
    what: Install,
    reason: Option<String>,
) -> Result<(Engine, Value, String), (StatusCode, Json<Value>)> {
    let current = current_row(db)
        .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "bundle store unavailable"))?;
    let (payload, envelope, sha, rollback_from) = match what {
        Install::Envelope(envelope) => {
            let key = key
                .ok_or_else(|| refuse(StatusCode::CONFLICT, "ASN bundle key is not configured"))?;
            let payload = verify_bundle(key, &envelope)
                .map_err(|e| refuse(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
            let sha = crate::actor::sha256_hex(&envelope);
            if let Some((v, s, _)) = &current {
                if payload.version == *v && *s == sha {
                    return Err((
                        StatusCode::OK,
                        Json(json!({"changed": false, "version": v})),
                    ));
                }
                if payload.version <= *v {
                    return Err(refuse(
                        StatusCode::CONFLICT,
                        format!(
                            "bundle version {} is not newer than installed {v}; use rollback to go back",
                            payload.version
                        ),
                    ));
                }
            }
            let rolled_back: bool = db
                .query_row(
                    "SELECT 1 FROM asn_bundles WHERE version=?1 AND state='rolled_back'",
                    [payload.version as i64],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "bundle store unavailable"))?
                .unwrap_or(false);
            if rolled_back {
                return Err(refuse(
                    StatusCode::CONFLICT,
                    "bundle version was rolled back; publish a newer version",
                ));
            }
            (payload, envelope, sha, None)
        }
        Install::Rollback => {
            let (cv, _, _) = current
                .clone()
                .ok_or_else(|| refuse(StatusCode::CONFLICT, "no installed bundle"))?;
            let previous: Option<(i64, String, Vec<u8>)> = db
                .query_row("SELECT version, sha256, envelope FROM asn_bundles WHERE state='previous' ORDER BY version DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()
                .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "bundle store unavailable"))?;
            let (_, sha, envelope) = previous.ok_or_else(|| {
                refuse(StatusCode::CONFLICT, "no last-good bundle to roll back to")
            })?;
            let payload = stored_payload(key, &envelope).map_err(|e| {
                refuse(
                    StatusCode::CONFLICT,
                    format!("stored bundle invalid: {e:#}"),
                )
            })?;
            (payload, envelope, sha, Some(cv))
        }
    };
    let mut next = engine.clone();
    let action = if rollback_from.is_some() {
        "asn.bundle.rollback"
    } else {
        "asn.bundle.install"
    };
    let mut record = audit::Record::new(actor, action, format!("version={}", payload.version));
    record.reason = reason;
    record.revision_before = Some(engine.revision());
    record.before_digest = current.as_ref().map(|(_, s, _)| format!("sha256:{s}"));
    if let Err(e) = next.set_asn_catalog(payload.prefixes.clone()) {
        record.after_digest = record.before_digest.clone();
        crate::record_refusal_with(retention, db, record, format!("{e:#}"));
        return Err(refuse(StatusCode::BAD_REQUEST, format!("{e:#}")));
    }
    let report = diff(engine.asn_catalog(), next.asn_catalog());
    record.after_digest = Some(format!("sha256:{sha}"));
    record.revision_after = Some(next.revision());
    record.policy_revision = Some(next.policy_revision());
    record.summary = format!(
        "ASN bundle {} -> {} ({}): +{} -{} ~{} prefixes",
        current
            .as_ref()
            .map_or("none".into(), |(v, _, _)| v.to_string()),
        payload.version,
        payload.source,
        report["added"],
        report["removed"],
        report["reassigned"]
    );
    let version = payload.version as i64;
    let installed_at = now() as i64;
    let mut extra = |tx: &Connection| -> rusqlite::Result<()> {
        match rollback_from {
            Some(from) => {
                tx.execute(
                    "UPDATE asn_bundles SET state='rolled_back', envelope=X'' WHERE version=?1",
                    [from as i64],
                )?;
                tx.execute(
                    "UPDATE asn_bundles SET state='current', installed_at=?2 WHERE version=?1",
                    params![version, installed_at],
                )?;
            }
            None => {
                tx.execute(
                    "UPDATE asn_bundles SET state='previous' WHERE state='current'",
                    [],
                )?;
                tx.execute(
                    "INSERT INTO asn_bundles(version, installed_at, sha256, envelope, state) VALUES(?1,?2,?3,?4,'current')",
                    params![version, installed_at, sha, envelope],
                )?;
            }
        }
        tx.execute(
            "DELETE FROM asn_bundles WHERE state='previous' AND version NOT IN (SELECT version FROM asn_bundles WHERE state='previous' ORDER BY version DESC LIMIT ?1)",
            [MAX_PREVIOUS],
        )?;
        tx.execute(
            "DELETE FROM asn_bundles WHERE state='rolled_back' AND version NOT IN (SELECT version FROM asn_bundles WHERE state='rolled_back' ORDER BY version DESC LIMIT 16)",
            [],
        )?;
        Ok(())
    };
    if let Err(e) = persist_with(db, Some(&next.state()), &record, retention, &mut extra) {
        let message = match e {
            PersistError::Before(e) | PersistError::Commit(e) => format!("{e:#}"),
        };
        crate::record_refusal_with(
            retention,
            db,
            record,
            format!("bundle store or audit write failed: {message}"),
        );
        return Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "bundle install failed; catalog unchanged",
        ));
    }
    count(&guard_core::metrics::METRICS.admin_changes[0]);
    let id = record.id.clone();
    Ok((
        next,
        json!({"changed": true, "version": payload.version, "previous_version": current.map(|c| c.0),
               "rolled_back_from": rollback_from, "source": payload.source, "provenance": payload.provenance,
               "created_at": payload.created_at, "sha256": sha, "diff": report, "audit_id": id}),
        id,
    ))
}

fn install(
    app: &App,
    actor: Actor,
    what: Install,
    reason: Option<String>,
) -> Result<Value, (StatusCode, Json<Value>)> {
    if app.native_source.is_some() {
        return Err(refuse(
            StatusCode::CONFLICT,
            "exclusive Kubernetes policy owner",
        ));
    }
    let mut db = app
        .db
        .lock()
        .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
    let mut inner = app
        .inner
        .lock()
        .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
    match install_locked(
        &mut db,
        &inner.engine,
        app.audit,
        app.asn.key.as_ref(),
        actor,
        what,
        reason,
    ) {
        Ok((next, report, _)) => {
            inner.engine = next;
            app.view.store(Arc::new(inner.engine.decision_view()));
            Ok(report)
        }
        Err((StatusCode::OK, body)) => Ok(body.0),
        Err(e) => Err(e),
    }
}

/// `GET /v1/asn/bundle`
pub async fn bundle_get(HttpState(app): HttpState<App>) -> ApiResult {
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let db = a.db.lock().map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
        let mut stmt = db
            .prepare("SELECT version, installed_at, sha256, state, envelope FROM asn_bundles ORDER BY version DESC")
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "bundle store unavailable"))?;
        let rows: Vec<(i64, i64, String, String, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .and_then(Iterator::collect)
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "bundle store unavailable"))?;
        let describe = |(v, at, sha, state, env): &(i64, i64, String, String, Vec<u8>)| {
            let meta = (!env.is_empty())
                .then(|| stored_payload(None, env).ok())
                .flatten();
            json!({"version": v, "installed_at": at, "sha256": sha, "state": state,
                   "source": meta.as_ref().map(|m| m.source.clone()),
                   "created_at": meta.as_ref().map(|m| m.created_at),
                   "provenance": meta.as_ref().map(|m| m.provenance.clone()),
                   "prefixes": meta.as_ref().map(|m| m.prefixes.len())})
        };
        let current = rows.iter().find(|r| r.3 == "current").map(describe);
        let fetch = a.asn.fetch.lock().map(|f| f.clone()).unwrap_or_default();
        Ok(Json(json!({
            "schema": "sumunjang.asn_bundle.v1",
            "key_configured": a.asn.key.is_some(),
            "fetch": {"url_configured": a.asn.url.is_some(), "interval_secs": a.asn.interval_secs, "status": fetch},
            "current": current,
            "history": rows.iter().filter(|r| r.3 != "current").map(describe).collect::<Vec<_>>(),
        })))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}
/// `PUT /v1/asn/bundle` (body: signed envelope JSON).
pub async fn bundle_put(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<Actor>,
    body: axum::body::Bytes,
) -> MutationResult {
    let a = app.clone();
    let v = tokio::task::spawn_blocking(move || {
        install(&a, actor, Install::Envelope(body.to_vec()), None)
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))??;
    Ok(Json(v).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollback {
    expected_version: u64,
    reason: String,
}
/// `POST /v1/asn/bundle/rollback`: reinstall the last-good bundle.
pub async fn bundle_rollback(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<Rollback>,
) -> MutationResult {
    crate::check_reason(&Some(input.reason.clone()))?;
    let a = app.clone();
    let v = tokio::task::spawn_blocking(move || {
        let current =
            a.db.lock()
                .ok()
                .and_then(|db| current_row(&db).ok().flatten())
                .map(|c| c.0);
        if current != Some(input.expected_version) {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({"error": "bundle version conflict", "current_version": current})),
            ));
        }
        install(&a, actor, Install::Rollback, Some(input.reason))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))??;
    Ok(Json(v).into_response())
}

/// Fetch the configured URL once and install a newer bundle.
pub async fn fetch_once(app: &App, actor: Actor) -> Result<Value, (StatusCode, Json<Value>)> {
    let url = app
        .asn
        .url
        .clone()
        .ok_or_else(|| refuse(StatusCode::CONFLICT, "no ASN bundle URL is configured"))?;
    let started = now();
    let result = async {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30));
        if let Some(ca) = &app.asn.ca {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(
                &crate::read_bounded(ca, 128 * 1024)?,
            )?);
        }
        let mut response = builder
            .build()?
            .get(&url)
            .send()
            .await?
            .error_for_status()?;
        anyhow::ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_BUNDLE_BYTES as u64),
            "bundle exceeds size bound"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                bytes.len() + chunk.len() <= MAX_BUNDLE_BYTES,
                "bundle exceeds size bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok::<_, anyhow::Error>(bytes)
    }
    .await;
    let outcome = match result {
        Ok(bytes) => {
            let a = app.clone();
            tokio::task::spawn_blocking(move || {
                install(
                    &a,
                    actor,
                    Install::Envelope(bytes),
                    Some("scheduled or requested refresh".into()),
                )
            })
            .await
            .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))
            .and_then(|r| r)
        }
        Err(e) => Err(refuse(
            StatusCode::BAD_GATEWAY,
            format!("fetch failed: {e:#}"),
        )),
    };
    if let Ok(mut f) = app.asn.fetch.lock() {
        f.attempts += 1;
        f.last_attempt = Some(started);
        match &outcome {
            Ok(v) => {
                f.last_success = Some(now());
                f.last_error = None;
                f.last_version = v["version"].as_u64();
            }
            Err((_, body)) => {
                f.failures += 1;
                f.last_error = body.0["error"].as_str().map(str::to_owned);
            }
        }
    }
    outcome
}
/// `POST /v1/asn/refresh`
pub async fn refresh(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> MutationResult {
    Ok(Json(fetch_once(&app, actor).await?).into_response())
}
/// Scheduled refresh loop (never activates proposals; only updates the catalog).
pub async fn follow(app: App, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(app.asn.interval_secs));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err((_, body)) = fetch_once(&app, Actor::system()).await {
                    eprintln!("asn bundle refresh: {}", body.0["error"]);
                }
            }
            _ = stop.changed() => break,
        }
    }
}

/// Offline `--import-asn-bundle FILE`: verify and install without listeners.
pub fn import_offline(
    database: &std::path::Path,
    file: &std::path::Path,
    retention: audit::Retention,
) -> anyhow::Result<String> {
    let key = key_from_env()?
        .ok_or_else(|| anyhow::anyhow!("HANGANG_GUARD_ASN_BUNDLE_KEY is required"))?;
    let envelope = crate::read_bounded(file, MAX_BUNDLE_BYTES)?;
    let mut db = crate::open_database(database)?;
    let body: String = db
        .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
        .map_err(|_| anyhow::anyhow!("no checkpoint: start the service once before importing"))?;
    let mut engine = Engine::restore(serde_json::from_str(&body)?)?;
    load_installed(&db, &mut engine, Some(&key))?;
    let mut actor = Actor::local();
    actor.name = "asn-bundle-import".into();
    match install_locked(
        &mut db,
        &engine,
        retention,
        Some(&key),
        actor,
        Install::Envelope(envelope),
        Some("offline import".into()),
    ) {
        Ok((_, report, _)) => Ok(report.to_string()),
        Err((StatusCode::OK, body)) => Ok(body.0.to_string()),
        Err((_, body)) => anyhow::bail!("{}", body.0["error"]),
    }
}

// ================================================================== proposals

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PState {
    Draft,
    Pending,
    Approved,
    Rejected,
    Active,
    Expired,
    Withdrawn,
}
impl PState {
    fn terminal(self) -> bool {
        matches!(self, Self::Rejected | Self::Expired | Self::Withdrawn)
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Every catalog prefix of the ASN.
    Asn,
    /// Selected prefixes inside the ASN's catalog prefixes.
    Prefixes,
    /// /24 (IPv4) and /48 (IPv6) aggregates inside the ASN that contain tracked
    /// evidence addresses, plus listed aggregates.
    Aggregates,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    pub kind: ScopeKind,
    #[serde(default)]
    pub prefixes: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRef {
    pub kind: String,
    pub name: String,
    pub issuer: String,
    pub id: Option<i64>,
}
impl ActorRef {
    fn of(a: &Actor) -> Self {
        Self {
            kind: a.kind.into(),
            name: a.name.clone(),
            issuer: a.issuer.clone(),
            id: a.id,
        }
    }
    fn same(&self, o: &Self) -> bool {
        self.issuer == o.issuer && self.name == o.name && self.id == o.id
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mark {
    pub by: ActorRef,
    pub at: u64,
    pub reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activation {
    pub by: ActorRef,
    pub at: u64,
    pub block_expires_at: u64,
    pub blocked: Vec<String>,
    pub skipped_existing: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub revision: u64,
    pub asn: u32,
    pub scope: ScopeSpec,
    pub reason: String,
    pub expires_at: u64,
    pub state: PState,
    pub created_by: ActorRef,
    pub created_at: u64,
    pub required_approvals: u8,
    pub approvals: Vec<Mark>,
    pub rejection: Option<Mark>,
    pub withdrawal: Option<Mark>,
    pub activation: Option<Activation>,
    /// Reviewed networks (frozen when submitted; activation blocks exactly these).
    pub networks: Vec<String>,
    pub impact: Value,
    pub decision_log: Option<Value>,
    pub history: Vec<Value>,
}
fn load(db: &Connection, id: &str) -> rusqlite::Result<Option<Proposal>> {
    db.query_row("SELECT body FROM asn_proposals WHERE id=?1", [id], |r| {
        r.get::<_, String>(0)
    })
    .optional()
    .map(|b| b.and_then(|b| serde_json::from_str(&b).ok()))
}
fn store(tx: &Connection, p: &Proposal) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO asn_proposals(id, created_at, state, body) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET state=excluded.state, body=excluded.body",
        params![p.id, p.created_at as i64, p.state.as_str(), serde_json::to_string(p).unwrap_or_default()],
    )?;
    Ok(())
}

/// Networks of a scope, with located errors.
fn compile_scope(
    engine: &mut Engine,
    asn: u32,
    scope: &ScopeSpec,
    now: u64,
) -> Result<Vec<IpNet>, Vec<FieldError>> {
    let owned: Vec<IpNet> = engine
        .asn_catalog()
        .iter()
        .filter(|p| p.asn == asn)
        .filter_map(|p| canonical_network(&p.network).ok())
        .collect();
    if owned.is_empty() {
        return Err(vec![FieldError::new(
            "/asn",
            "ASN has no prefixes in the installed catalog",
        )]);
    }
    let inside = |n: &IpNet| owned.iter().any(|o| o.contains(n));
    let mut errors = Vec::new();
    let mut listed = Vec::new();
    for (i, p) in scope.prefixes.iter().enumerate() {
        match canonical_network(p) {
            Ok(n) if !inside(&n) => errors.push(FieldError::new(
                format!("/scope/prefixes/{i}"),
                "network is not inside the ASN's catalog prefixes",
            )),
            Ok(n)
                if scope.kind == ScopeKind::Aggregates
                    && !matches!((n, n.prefix_len()), (IpNet::V4(_), 24) | (IpNet::V6(_), 48)) =>
            {
                errors.push(FieldError::new(
                    format!("/scope/prefixes/{i}"),
                    "aggregates must be IPv4 /24 or IPv6 /48",
                ))
            }
            Ok(n) => listed.push(n),
            Err(e) => errors.push(FieldError::new(
                format!("/scope/prefixes/{i}"),
                e.to_string(),
            )),
        }
    }
    let mut nets: Vec<IpNet> = match scope.kind {
        ScopeKind::Asn => {
            if !scope.prefixes.is_empty() {
                errors.push(FieldError::new(
                    "/scope/prefixes",
                    "a full-ASN scope takes no prefixes",
                ));
            }
            owned.clone()
        }
        ScopeKind::Prefixes => {
            if scope.prefixes.is_empty() {
                errors.push(FieldError::new(
                    "/scope/prefixes",
                    "select at least one prefix",
                ));
            }
            listed
        }
        ScopeKind::Aggregates => {
            let mut nets = listed;
            for c in engine.candidates(now) {
                if let Ok(ip) = canonical_ip(&c.ip) {
                    let agg = match ip {
                        IpAddr::V4(_) => IpNet::new(ip, 24),
                        IpAddr::V6(_) => IpNet::new(ip, 48),
                    };
                    if let Ok(agg) = agg.map(|a| a.trunc())
                        && owned.iter().any(|o| o.contains(&ip))
                    {
                        // Clip to the ASN prefix when the prefix is narrower.
                        let clipped = owned
                            .iter()
                            .filter(|o| o.contains(&ip))
                            .map(|o| {
                                if o.prefix_len() > agg.prefix_len() {
                                    *o
                                } else {
                                    agg
                                }
                            })
                            .max_by_key(|n| n.prefix_len());
                        nets.push(clipped.unwrap_or(agg));
                    }
                }
            }
            if nets.is_empty() {
                errors.push(FieldError::new(
                    "/scope",
                    "no tracked addresses in this ASN to aggregate; list aggregates explicitly",
                ));
            }
            nets
        }
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    // Canonical, sorted, without networks nested in broader ones.
    nets.sort_by_key(|n| (matches!(n, IpNet::V6(_)), n.prefix_len(), n.network()));
    let mut kept: Vec<IpNet> = Vec::new();
    for n in nets {
        if !kept.iter().any(|k| k.contains(&n)) {
            kept.push(n);
        }
    }
    if kept.len() > MAX_NETWORKS {
        return Err(vec![FieldError::new(
            "/scope",
            format!(
                "scope compiles to {} networks; at most {MAX_NETWORKS}",
                kept.len()
            ),
        )]);
    }
    kept.sort();
    Ok(kept)
}
fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}
fn block_reason(id: &str) -> String {
    format!("asn proposal {id}")
}

/// Impact analysis of blocking `nets` (never stored as policy).
fn impact(app: &App, engine: &mut Engine, asn: u32, nets: &[IpNet], now: u64) -> Value {
    let mut trie = PrefixTrie::<()>::default();
    for n in nets {
        trie.insert(*n, ());
    }
    let in_scope = |ip: IpAddr| trie.longest(ip).is_some();
    let (mut v4, mut v6_64s) = (0u64, 0u64);
    for n in nets {
        match n {
            IpNet::V4(n) => v4 = v4.saturating_add(1u64 << (32 - n.prefix_len())),
            IpNet::V6(n) => {
                v6_64s = v6_64s.saturating_add(if n.prefix_len() >= 64 {
                    1
                } else {
                    1u64.checked_shl(64 - n.prefix_len() as u32)
                        .unwrap_or(u64::MAX)
                })
            }
        }
    }
    // Tracked evidence addresses in scope.
    let candidates: Vec<_> = engine
        .candidates(now)
        .into_iter()
        .filter(|c| canonical_ip(&c.ip).is_ok_and(in_scope))
        .collect();
    let mut signals = guard_core::history::SignalCounts::default();
    for c in &candidates {
        signals.merge(&c.signals);
    }
    let mut top: Vec<_> = candidates.iter().collect();
    top.sort_by_key(|c| std::cmp::Reverse(c.score));
    // History in scope.
    let history = engine.history();
    let (hist_addrs, hist_score, hist_events) = history.lock().map_or((0, 0, 0), |h| {
        h.addresses()
            .filter(|(ip, _, _)| in_scope(*ip))
            .fold((0u64, 0u64, 0u64), |(a, s, e), (_, sc, ev)| {
                (a + 1, s + sc, e + ev)
            })
    });
    // Decision preview on a never-published view with the proposal's blocks.
    let view = app.view.load_full();
    let blocks: Vec<Block> = nets
        .iter()
        .map(|n| Block {
            network: n.to_string(),
            expires_at: now + BLOCK_TTL_MAX,
            reason: "asn proposal preview".into(),
            origin: BlockOrigin {
                source: BlockSource::AsnProposal,
                created_at: Some(now),
                created_by: None,
            },
        })
        .collect();
    let preview = view.with_blocks(&blocks);
    let (mut cur_change, mut cur_already, mut cur_kept, mut enf_change, mut enf_kept) =
        (0, 0, 0, 0, 0);
    let mut samples = Vec::new();
    if let Ok(preview) = &preview {
        for c in &candidates {
            let Ok(ip) = canonical_ip(&c.ip) else {
                continue;
            };
            let geo = guard_core::GeoContext::default();
            let before = view.query_ip_context(ip, now, geo);
            let after = preview.query_ip_context(ip, now, geo);
            let enf_before = view.evaluate_as(Mode::Enforce, ip, now, geo, &mut NoTrace);
            let enf_after = preview.evaluate_as(Mode::Enforce, ip, now, geo, &mut NoTrace);
            match (before.action, after.action) {
                ("deny", _) => cur_already += 1,
                (_, "deny") => cur_change += 1,
                _ => cur_kept += 1,
            }
            if enf_before.action != "deny" {
                if enf_after.action == "deny" {
                    enf_change += 1
                } else {
                    enf_kept += 1
                }
            }
            if samples.len() < 50 {
                samples.push(json!({"ip": c.ip, "score": c.score, "before": before.action, "after": after.action,
                                    "enforce_after": enf_after.action, "reason_after": enf_after.code.as_str()}));
            }
        }
    }
    let p = engine.policy();
    let mut allow_collisions = Vec::new();
    for a in &p.allow {
        if let Ok(an) = canonical_network(a)
            && let Some(n) = nets.iter().find(|n| overlaps(n, &an))
        {
            allow_collisions.push(json!({"allow": a, "network": n.to_string(),
                "expires_at": p.allow_meta.get(a).and_then(|m| m.expires_at)}));
        }
    }
    let zones: Vec<Value> = engine
        .zones()
        .zones
        .values()
        .filter_map(|z| {
            let hits = z
                .prefixes
                .iter()
                .filter_map(|p| canonical_network(p).ok())
                .filter(|zp| nets.iter().any(|n| overlaps(n, zp)))
                .count();
            (hits > 0).then(|| json!({"zone": z.id, "overlapping_prefixes": hits}))
        })
        .collect();
    let existing: Vec<String> = engine
        .blocks()
        .filter_map(|b| {
            canonical_network(&b.network)
                .ok()
                .filter(|bn| nets.iter().any(|n| overlaps(n, bn)))
                .map(|bn| bn.to_string())
        })
        .take(50)
        .collect();
    let mode = engine.policy().mode;
    let mut warnings = Vec::new();
    if mode == Mode::Observe {
        warnings
            .push("observe mode: activation records blocks but does not deny until enforce mode");
    }
    if !allow_collisions.is_empty() {
        warnings.push("allowlist entries overlap the scope; allowlisted addresses stay allowed");
    }
    if !zones.is_empty() {
        warnings.push("network zones overlap the scope; review zone owners");
    }
    if nets.iter().any(|n| {
        matches!(n, IpNet::V4(n) if n.prefix_len() < 16)
            || matches!(n, IpNet::V6(n) if n.prefix_len() < 32)
    }) {
        warnings.push(
            "scope contains very large networks (IPv4 shorter than /16 or IPv6 shorter than /32)",
        );
    }
    json!({
        "computed_at": now, "asn": asn, "decision_revision": engine.revision(), "mode": if mode == Mode::Enforce {"enforce"} else {"observe"},
        "networks": nets.len(), "network_list": nets.iter().take(256).map(|n| n.to_string()).collect::<Vec<_>>(),
        "network_list_truncated": nets.len() > 256,
        "estimated": {"ipv4_addresses": v4, "ipv6_slash64s": v6_64s},
        "tracked": {"addresses": candidates.len(), "eligible": candidates.iter().filter(|c| c.eligible).count(), "signals": signals,
                    "top": top.iter().take(20).map(|c| json!({"ip": c.ip, "score": c.score, "suspicion": c.suspicion, "events": c.events})).collect::<Vec<_>>()},
        "history": {"addresses": hist_addrs, "score": hist_score, "events": hist_events},
        "preview": {"current_mode": {"allow_to_deny": cur_change, "already_denied": cur_already, "unchanged_allow": cur_kept},
                    "enforce": {"allow_to_deny": enf_change, "unchanged_allow": enf_kept}, "samples": samples},
        "collisions": {"allowlist": allow_collisions, "zones": zones, "existing_blocks": existing},
        "warnings": warnings,
        "decision_log": {"available": false, "note": "attach Hangang decision-log counts with the annotate action"},
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    asn: u32,
    scope: ScopeSpec,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expires_at: Option<u64>,
}
fn parse<T: for<'de> Deserialize<'de>>(body: Value) -> Result<T, (StatusCode, Json<Value>)> {
    serde_path_to_error::deserialize(body).map_err(|e| {
        let path: String = e.path().iter().map(|s| format!("/{s}")).collect();
        located(vec![FieldError::new(path, e.into_inner().to_string())])
    })
}
fn located(errors: Vec<FieldError>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "invalid ASN proposal", "errors": errors})),
    )
}

/// `POST /v1/asn/preview`: impact of a scope without storing anything.
pub async fn preview(HttpState(app): HttpState<App>, Json(body): Json<Value>) -> ApiResult {
    let d: Draft = parse(body)?;
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let mut inner = a
            .inner
            .lock()
            .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
        let t = now();
        let nets = compile_scope(&mut inner.engine, d.asn, &d.scope, t).map_err(located)?;
        let impact = impact(&a, &mut inner.engine, d.asn, &nets, t);
        Ok(Json(
            json!({"schema": "sumunjang.asn_preview.v1", "stored": false, "impact": impact}),
        ))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

fn proposal_id() -> String {
    format!("p-{}", &audit::new_id()[..20])
}
fn event(
    p: &mut Proposal,
    by: &ActorRef,
    action: &str,
    from: PState,
    reason: Option<&str>,
    at: u64,
) {
    p.history.push(json!({"at": at, "by": by.name, "action": action, "from": from.as_str(), "to": p.state.as_str(), "reason": reason}));
    if p.history.len() > 64 {
        p.history.remove(0);
    }
}
#[allow(clippy::too_many_arguments)]
fn commit_proposal(
    app: &App,
    db: &mut Connection,
    before: Option<&Proposal>,
    after: &Proposal,
    actor: Actor,
    action: &'static str,
    reason: Option<String>,
    summary: String,
    engine: Option<&Engine>,
) -> Result<String, (StatusCode, Json<Value>)> {
    let mut record = audit::Record::new(actor, action, after.id.clone());
    record.reason = reason;
    record.before_digest = before.map(audit::digest);
    record.after_digest = Some(audit::digest(after));
    record.summary = summary;
    if let Some(e) = engine {
        record.revision_after = Some(e.revision());
    }
    let mut extra = |tx: &Connection| store(tx, after);
    match persist_with(
        db,
        engine.map(|e| e.state()).as_ref(),
        &record,
        app.audit,
        &mut extra,
    ) {
        Ok(()) => {
            count(&guard_core::metrics::METRICS.admin_changes[0]);
            Ok(record.id)
        }
        Err(_) => Err(refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "proposal store or audit write failed; unchanged",
        )),
    }
}

/// `POST /v1/asn/proposals`: create a draft with its impact analysis.
pub async fn create(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(body): Json<Value>,
) -> MutationResult {
    let d: Draft = parse(body)?;
    let t = now();
    let mut errors = Vec::new();
    let reason = d.reason.clone().unwrap_or_default();
    if !text_ok(&reason, 256) {
        errors.push(FieldError::new(
            "/reason",
            "a reason of 1..256 bytes is required",
        ));
    }
    let expires_at = d.expires_at.unwrap_or(t + BLOCK_TTL_MAX);
    if expires_at <= t || expires_at > t + MAX_PROPOSAL_DAYS * 86_400 {
        errors.push(FieldError::new(
            "/expires_at",
            "expiry must be in the future and within 30 days",
        ));
    }
    if !errors.is_empty() {
        return Err(located(errors));
    }
    let a = app.clone();
    let response = tokio::task::spawn_blocking(move || {
        if a.native_source.is_some() {
            return Err(refuse(StatusCode::CONFLICT, "exclusive Kubernetes policy owner"));
        }
        let mut db = a.db.lock().map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
        let open: i64 = db
            .query_row("SELECT COUNT(*) FROM asn_proposals WHERE state NOT IN ('rejected','expired','withdrawn')", [], |r| r.get(0))
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "proposal store unavailable"))?;
        if open >= MAX_PROPOSALS {
            return Err(refuse(StatusCode::CONFLICT, "too many open ASN proposals (1000)"));
        }
        let (nets, impact) = {
            let mut inner = a.inner.lock().map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
            let nets = compile_scope(&mut inner.engine, d.asn, &d.scope, t).map_err(located)?;
            let impact = impact(&a, &mut inner.engine, d.asn, &nets, t);
            (nets, impact)
        };
        let by = ActorRef::of(&actor);
        let mut p = Proposal {
            id: proposal_id(),
            revision: 1,
            asn: d.asn,
            scope: d.scope,
            reason: reason.clone(),
            expires_at,
            state: PState::Draft,
            created_by: by.clone(),
            created_at: t,
            required_approvals: a.asn.required_approvals,
            approvals: vec![],
            rejection: None,
            withdrawal: None,
            activation: None,
            networks: nets.iter().map(ToString::to_string).collect(),
            impact,
            decision_log: None,
            history: vec![],
        };
        event(&mut p, &by, "create", PState::Draft, Some(&reason), t);
        let summary = format!("ASN {} proposal draft: {:?} scope, {} networks", p.asn, p.scope.kind, p.networks.len());
        let id = commit_proposal(&a, &mut db, None, &p, actor, "asn.proposal.create", Some(reason), summary, None)?;
        // Keep the store bounded: oldest terminal proposals beyond the cap go.
        let _ = db.execute(
            "DELETE FROM asn_proposals WHERE id IN (SELECT id FROM asn_proposals WHERE state IN ('rejected','expired','withdrawn') ORDER BY created_at DESC LIMIT -1 OFFSET ?1)",
            [MAX_PROPOSALS],
        );
        Ok((p, id))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))??;
    Ok(crate::audit_header(
        Json(serde_json::to_value(&response.0).unwrap_or_default()).into_response(),
        &response.1,
    ))
}

/// `GET /v1/asn/proposals`: newest first, summaries.
pub async fn list(HttpState(app): HttpState<App>) -> ApiResult {
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let db = a.db.lock().map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
        let mut stmt = db
            .prepare("SELECT body FROM asn_proposals ORDER BY created_at DESC LIMIT 1000")
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "proposal store unavailable"))?;
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .and_then(Iterator::collect)
            .map_err(|_| refuse(StatusCode::SERVICE_UNAVAILABLE, "proposal store unavailable"))?;
        let items: Vec<Value> = rows
            .iter()
            .filter_map(|b| serde_json::from_str::<Proposal>(b).ok())
            .map(|p| json!({"id": p.id, "revision": p.revision, "asn": p.asn, "scope": p.scope.kind, "state": p.state,
                            "reason": p.reason, "created_by": p.created_by.name, "created_at": p.created_at,
                            "expires_at": p.expires_at, "networks": p.networks.len(),
                            "approvals": p.approvals.len(), "required_approvals": p.required_approvals,
                            "tracked_addresses": p.impact["tracked"]["addresses"]}))
            .collect();
        Ok(Json(json!({"schema": "sumunjang.asn_proposals.v1", "required_approvals": a.asn.required_approvals, "proposals": items})))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

/// `GET /v1/asn/proposals/{id}`
pub async fn get(HttpState(app): HttpState<App>, UrlPath(id): UrlPath<String>) -> ApiResult {
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let db =
            a.db.lock()
                .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
        let p = load(&db, &id)
            .map_err(|_| {
                refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "proposal store unavailable",
                )
            })?
            .ok_or_else(|| refuse(StatusCode::NOT_FOUND, "unknown proposal"))?;
        Ok(Json(serde_json::to_value(p).unwrap_or_default()))
    })
    .await
    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Act {
    action: String,
    expected_revision: u64,
    #[serde(default)]
    reason: Option<String>,
    /// For `annotate`: Hangang decision-log aggregate counts (integers only).
    #[serde(default)]
    decision_log: Option<BTreeMap<String, u64>>,
}

/// `POST /v1/asn/proposals/{id}`: submit, approve, reject, activate,
/// withdraw, analyze or annotate, with compare-and-set on the proposal revision.
pub async fn act(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<Actor>,
    UrlPath(id): UrlPath<String>,
    Json(body): Json<Value>,
) -> MutationResult {
    let input: Act = parse(body)?;
    crate::check_reason(&input.reason)?;
    let a = app.clone();
    let (p, audit_id) = tokio::task::spawn_blocking(move || transition(&a, actor, &id, input))
        .await
        .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))??;
    Ok(crate::audit_header(
        Json(serde_json::to_value(p).unwrap_or_default()).into_response(),
        &audit_id,
    ))
}

fn transition(
    app: &App,
    actor: Actor,
    id: &str,
    input: Act,
) -> Result<(Proposal, String), (StatusCode, Json<Value>)> {
    if app.native_source.is_some() {
        return Err(refuse(
            StatusCode::CONFLICT,
            "exclusive Kubernetes policy owner",
        ));
    }
    let t = now();
    let mut db = app
        .db
        .lock()
        .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "database unavailable"))?;
    let before = load(&db, id)
        .map_err(|_| {
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "proposal store unavailable",
            )
        })?
        .ok_or_else(|| refuse(StatusCode::NOT_FOUND, "unknown proposal"))?;
    if before.revision != input.expected_revision {
        return Err((
            StatusCode::CONFLICT,
            Json(
                json!({"error": "proposal revision conflict; reload and retry", "current_revision": before.revision}),
            ),
        ));
    }
    let by = ActorRef::of(&actor);
    let mut p = before.clone();
    let from = p.state;
    let reason = input.reason.clone();
    let deny = |m: &str| Err(refuse(StatusCode::CONFLICT, m));
    let mut engine_next: Option<Engine> = None;
    // Held from clone to swap so concurrent evidence ingestion cannot be lost.
    let mut held: Option<std::sync::MutexGuard<'_, crate::Inner>> = None;
    let action: &'static str;
    let summary: String;
    match input.action.as_str() {
        "submit" => {
            if from != PState::Draft {
                return deny("only drafts can be submitted");
            }
            let mut inner = app
                .inner
                .lock()
                .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
            let nets = compile_scope(&mut inner.engine, p.asn, &p.scope, t).map_err(located)?;
            p.impact = impact(app, &mut inner.engine, p.asn, &nets, t);
            p.networks = nets.iter().map(ToString::to_string).collect();
            p.state = PState::Pending;
            action = "asn.proposal.submit";
            summary = format!("submitted for review: {} networks frozen", p.networks.len());
        }
        "analyze" => {
            if !matches!(from, PState::Draft | PState::Pending | PState::Approved) {
                return deny("analysis is available before activation");
            }
            let mut inner = app
                .inner
                .lock()
                .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
            let nets: Vec<IpNet> = if from == PState::Draft {
                let nets = compile_scope(&mut inner.engine, p.asn, &p.scope, t).map_err(located)?;
                p.networks = nets.iter().map(ToString::to_string).collect();
                nets
            } else {
                // Reviewed networks stay frozen; only the analysis refreshes.
                p.networks
                    .iter()
                    .filter_map(|n| canonical_network(n).ok())
                    .collect()
            };
            p.impact = impact(app, &mut inner.engine, p.asn, &nets, t);
            action = "asn.proposal.analyze";
            summary = "impact analysis refreshed".into();
        }
        "annotate" => {
            if from.terminal() {
                return deny("proposal is closed");
            }
            let counts = input.decision_log.clone().ok_or_else(|| {
                refuse(
                    StatusCode::BAD_REQUEST,
                    "annotate requires decision_log counts",
                )
            })?;
            if counts.len() > 16
                || counts.keys().any(|k| {
                    k.len() > 64 || !k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })
            {
                return Err(refuse(
                    StatusCode::BAD_REQUEST,
                    "decision_log takes at most 16 lowercase count names",
                ));
            }
            p.decision_log = Some(
                json!({"counts": counts, "attached_by": by.name, "attached_at": t,
                                         "note": "aggregate counts supplied from the Hangang decision log (pseudonymized source)"}),
            );
            action = "asn.proposal.annotate";
            summary = "decision-log counts attached".into();
        }
        "approve" => {
            if from != PState::Pending {
                return deny("only pending proposals can be approved");
            }
            if by.same(&p.created_by) {
                return deny("two-person rule: the proposer cannot approve");
            }
            if p.approvals.iter().any(|m| m.by.same(&by)) {
                return deny("already approved by this administrator");
            }
            p.approvals.push(Mark {
                by: by.clone(),
                at: t,
                reason: reason.clone(),
            });
            if p.approvals.len() >= p.required_approvals as usize {
                p.state = PState::Approved;
            }
            action = "asn.proposal.approve";
            summary = format!("approval {}/{}", p.approvals.len(), p.required_approvals);
        }
        "reject" => {
            if !matches!(from, PState::Pending | PState::Approved) {
                return deny("only pending or approved proposals can be rejected");
            }
            if reason.as_deref().is_none_or(str::is_empty) {
                return Err(refuse(StatusCode::BAD_REQUEST, "reject requires a reason"));
            }
            p.rejection = Some(Mark {
                by: by.clone(),
                at: t,
                reason: reason.clone(),
            });
            p.state = PState::Rejected;
            action = "asn.proposal.reject";
            summary = "rejected".into();
        }
        "activate" => {
            if from != PState::Approved {
                return deny("only approved proposals can be activated");
            }
            if p.expires_at <= t {
                return deny("proposal expired");
            }
            let inner = app
                .inner
                .lock()
                .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
            let mut next = inner.engine.clone();
            held = Some(inner);
            let block_expires_at = p.expires_at.min(t + BLOCK_TTL_MAX);
            let (mut blocked, mut skipped) = (Vec::new(), Vec::new());
            for n in &p.networks {
                if next
                    .blocks()
                    .any(|b| b.network == *n && b.expires_at >= block_expires_at)
                {
                    skipped.push(n.clone());
                    continue;
                }
                next.add_block(
                    Block {
                        network: n.clone(),
                        expires_at: block_expires_at,
                        reason: block_reason(&p.id),
                        origin: BlockOrigin {
                            source: BlockSource::AsnProposal,
                            created_at: Some(t),
                            created_by: Some(by.name.chars().take(64).collect()),
                        },
                    },
                    t,
                )
                .map_err(|e| refuse(StatusCode::CONFLICT, format!("activation refused: {e:#}")))?;
                blocked.push(n.clone());
            }
            p.activation = Some(Activation {
                by: by.clone(),
                at: t,
                block_expires_at,
                blocked: blocked.clone(),
                skipped_existing: skipped,
            });
            p.state = PState::Active;
            action = "asn.proposal.activate";
            summary = format!(
                "activated: {} blocks until {block_expires_at}",
                blocked.len()
            );
            engine_next = Some(next);
        }
        "withdraw" => {
            if from.terminal() {
                return deny("proposal is closed");
            }
            if from == PState::Active {
                let inner = app
                    .inner
                    .lock()
                    .map_err(|_| refuse(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
                let mut next = inner.engine.clone();
                held = Some(inner);
                let ours: Vec<String> = next
                    .blocks()
                    .filter(|b| {
                        b.origin.source == BlockSource::AsnProposal
                            && b.reason == block_reason(&p.id)
                    })
                    .map(|b| b.network.clone())
                    .collect();
                for n in &ours {
                    next.remove_block(n)
                        .map_err(|e| refuse(StatusCode::INTERNAL_SERVER_ERROR, e))?;
                }
                engine_next = Some(next);
            }
            p.withdrawal = Some(Mark {
                by: by.clone(),
                at: t,
                reason: reason.clone(),
            });
            p.state = PState::Withdrawn;
            action = "asn.proposal.withdraw";
            summary = format!("withdrawn from {}", from.as_str());
        }
        _ => {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "action must be submit, analyze, annotate, approve, reject, activate or withdraw",
            ));
        }
    }
    p.revision += 1;
    event(&mut p, &by, &input.action, from, reason.as_deref(), t);
    let audit_id = commit_proposal(
        app,
        &mut db,
        Some(&before),
        &p,
        actor,
        action,
        reason,
        summary,
        engine_next.as_ref(),
    )?;
    if let (Some(next), Some(mut inner)) = (engine_next, held) {
        inner.engine = next;
        app.view.store(Arc::new(inner.engine.decision_view()));
    }
    Ok((p, audit_id))
}

/// Expire due proposals (maintenance task; audited as the `system` actor).
pub fn expire_due(app: &App) {
    if app.native_source.is_some() {
        return;
    }
    let t = now();
    let Ok(mut db) = app.db.lock() else { return };
    let due: Vec<Proposal> = match db.prepare(
        "SELECT body FROM asn_proposals WHERE state IN ('draft','pending','approved','active')",
    ) {
        Ok(mut stmt) => stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map(|rows| {
                rows.filter_map(Result::ok)
                    .filter_map(|b| serde_json::from_str::<Proposal>(&b).ok())
                    .collect()
            })
            .unwrap_or_default(),
        Err(_) => return,
    };
    for before in due {
        let ends = match &before.activation {
            Some(a) if before.state == PState::Active => a.block_expires_at,
            _ => before.expires_at,
        };
        if ends > t {
            continue;
        }
        let mut p = before.clone();
        let by = ActorRef::of(&Actor::system());
        p.state = PState::Expired;
        p.revision += 1;
        event(&mut p, &by, "expire", before.state, None, t);
        let _ = commit_proposal(
            app,
            &mut db,
            Some(&before),
            &p,
            Actor::system(),
            "asn.proposal.expire",
            None,
            format!("expired from {}", before.state.as_str()),
            None,
        );
    }
}
