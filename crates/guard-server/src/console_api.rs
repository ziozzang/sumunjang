//! Read and write APIs used by the console Network pages: per-address signal
//! history, offline ASN catalog listing, allowlist entries with compare-and-set
//! and block provenance rendering.
use crate::{
    ApiResult, App, Change, MutationResult, Scope, actor, check_reason, conflict, error, mutation,
    now, operation,
};
use axum::{
    Json,
    extract::{Query, State as HttpState, rejection::QueryRejection},
    http::StatusCode,
};
use guard_core::{AllowMeta, Block, Engine, canonical_ip, canonical_network, history};
use serde::Deserialize;
use serde_json::{Value, json};

/// Block wire fields plus provenance (additive to the legacy block JSON).
pub fn block_json(b: &Block) -> Value {
    json!({
        "network": b.network, "expires_at": b.expires_at, "reason": b.reason,
        "source": b.origin.source, "created_at": b.origin.created_at,
        "created_by": b.origin.created_by,
    })
}

fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, (StatusCode, Json<Value>)> {
    q.map(|Query(v)| v)
        .map_err(|e| error(StatusCode::BAD_REQUEST, format!("invalid query: {e}")))
}

// ----- per-address signal history -----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    ip: String,
    /// Inclusive Unix seconds; default: start of retention.
    since: Option<u64>,
    /// Exclusive Unix seconds; default: now.
    until: Option<u64>,
}
pub async fn history_get(
    HttpState(app): HttpState<App>,
    q: Result<Query<HistoryQuery>, QueryRejection>,
) -> ApiResult {
    history(app, query(q)?).await
}
pub async fn history_post(
    HttpState(app): HttpState<App>,
    Json(q): Json<HistoryQuery>,
) -> ApiResult {
    history(app, q).await
}
async fn history(app: App, q: HistoryQuery) -> ApiResult {
    let ip = canonical_ip(&q.ip).map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
    operation(app, move |e| {
        let time = now();
        let window_score = e.signal_score(ip, time);
        let policy = e.policy().clone();
        let h = e.history();
        let mut h = h
            .lock()
            .map_err(|_| anyhow::anyhow!("history unavailable"))?;
        let retention = h.retention_secs();
        let since = q.since.unwrap_or(time.saturating_sub(retention));
        let until = q.until.unwrap_or(time + 1);
        anyhow::ensure!(since < until, "since must be before until");
        let buckets = h.series(ip, since, until, time);
        let mut totals = history::SignalCounts::default();
        let mut score = 0u64;
        for b in &buckets {
            totals.merge(&b.signals);
            score = score.saturating_add(b.score);
        }
        Ok(json!({
            "schema": "sumunjang.history.v1",
            "ip": ip.to_string(),
            "since": since,
            "until": until,
            "bucket_secs": history::BUCKET_SECS,
            "retention_secs": retention,
            "buckets": buckets,
            "totals": {"score": score, "signals": totals},
            "window": {"signal_score": window_score, "threshold": policy.threshold,
                       "window_secs": policy.window_secs},
            "stats": h.stats(),
        }))
    })
    .await
}

// ----- offline ASN catalog -----

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AsnQuery {
    /// Only this ASN.
    asn: Option<u32>,
    /// Prefix rows per page, 1..=1000 (default 200).
    limit: Option<u32>,
    cursor: Option<String>,
}
pub async fn asn_get(
    HttpState(app): HttpState<App>,
    q: Result<Query<AsnQuery>, QueryRejection>,
) -> ApiResult {
    asn(app, query(q)?).await
}
pub async fn asn_post(HttpState(app): HttpState<App>, Json(q): Json<AsnQuery>) -> ApiResult {
    asn(app, q).await
}
fn parse_cursor(c: &str) -> Option<(u32, String)> {
    let (asn, network) = c.strip_prefix('c')?.split_once('_')?;
    Some((
        asn.parse().ok()?,
        canonical_network(network).ok()?.to_string(),
    ))
}
async fn asn(app: App, q: AsnQuery) -> ApiResult {
    let limit = q.limit.unwrap_or(200);
    if !(1..=1000).contains(&limit) {
        return Err(error(StatusCode::BAD_REQUEST, "limit must be 1..=1000"));
    }
    let after = match &q.cursor {
        Some(c) => {
            Some(parse_cursor(c).ok_or_else(|| error(StatusCode::BAD_REQUEST, "invalid cursor"))?)
        }
        None => None,
    };
    operation(app, move |e| {
        let catalog = e.asn_catalog();
        let total_asns = catalog.windows(2).filter(|w| w[0].asn != w[1].asn).count()
            + usize::from(!catalog.is_empty());
        // Catalog is sorted by (asn, network); position after the cursor key.
        let start = match &after {
            Some((asn, network)) => {
                catalog.partition_point(|p| (p.asn, p.network.as_str()) <= (*asn, network.as_str()))
            }
            None => q.asn.map_or(0, |a| catalog.partition_point(|p| p.asn < a)),
        };
        let mut groups: Vec<Value> = Vec::new();
        let mut last = None;
        let mut more = false;
        // Sorted by ASN: with an ASN filter, stop at the first other ASN.
        for (rows, p) in catalog[start..]
            .iter()
            .take_while(|p| q.asn.is_none_or(|a| a == p.asn))
            .enumerate()
        {
            if rows == limit as usize {
                more = true;
                break;
            }
            match groups.last_mut() {
                Some(g) if g["asn"] == p.asn => {
                    g["prefixes"].as_array_mut().unwrap().push(json!(p.network))
                }
                _ => groups.push(json!({"asn": p.asn, "prefixes": [p.network]})),
            }
            last = Some((p.asn, p.network.clone()));
        }
        Ok(json!({
            "schema": "sumunjang.asn_catalog.v1",
            "source": "offline_catalog",
            "total_prefixes": catalog.len(),
            "total_asns": total_asns,
            "entries": groups,
            "next_cursor": if more { last.map(|(a, n)| format!("c{a}_{n}")) } else { None },
        }))
    })
    .await
}

// ----- allowlist entries -----

fn allowlist_document(e: &Engine, time: u64) -> Value {
    let p = e.policy();
    let entries: Vec<Value> = p
        .allow
        .iter()
        .map(|n| {
            let m = p.allow_meta.get(n).cloned().unwrap_or_default();
            json!({"network": n, "expires_at": m.expires_at, "reason": m.reason,
                   "created_at": m.created_at, "created_by": m.created_by,
                   "expired": m.expires_at.is_some_and(|x| x <= time)})
        })
        .collect();
    json!({"schema": "sumunjang.allowlist.v1", "revision": e.policy_revision(), "entries": entries})
}
pub async fn allowlist_get(HttpState(app): HttpState<App>) -> ApiResult {
    operation(app, |e| Ok(allowlist_document(e, now()))).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowAdd {
    expected_revision: String,
    network: String,
    #[serde(default)]
    expires_at: Option<u64>,
    /// Entry reason (≤ 128 bytes), also recorded as the audit reason.
    #[serde(default)]
    reason: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRemove {
    expected_revision: String,
    network: String,
    #[serde(default)]
    reason: Option<String>,
}
const CONFLICT: &str = "policy revision conflict;";
/// Add or update one allow entry (compare-and-set on the policy revision).
pub async fn allowlist_add(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<actor::Actor>,
    Json(input): Json<AllowAdd>,
) -> MutationResult {
    check_reason(&input.reason)?;
    let network = canonical_network(&input.network)
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?
        .to_string();
    let time = now();
    if input.expires_at.is_some_and(|x| x <= time) {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "expires_at must be in the future",
        ));
    }
    let by: String = actor.name.chars().take(64).collect();
    let mut change = Change::new(actor, "allowlist.add", Scope::Policy, network.clone());
    change.reason = input.reason.clone();
    let on_conflict = conflict(&app, CONFLICT, Engine::policy_revision);
    mutation(app, change, move |e| {
        anyhow::ensure!(
            e.policy_revision() == input.expected_revision,
            "policy revision conflict; reload the allowlist and retry."
        );
        let mut policy = e.policy().clone();
        if !policy.allow.contains(&network) {
            policy.allow.push(network.clone());
        }
        policy.allow_meta.insert(
            network,
            AllowMeta {
                expires_at: input.expires_at,
                reason: input.reason,
                created_at: Some(time),
                created_by: Some(by),
            },
        );
        e.set_policy(policy)?;
        Ok(allowlist_document(e, time))
    })
    .await
    .map_err(on_conflict)
}
pub async fn allowlist_remove(
    HttpState(app): HttpState<App>,
    axum::Extension(actor): axum::Extension<actor::Actor>,
    Json(input): Json<AllowRemove>,
) -> MutationResult {
    check_reason(&input.reason)?;
    let network = canonical_network(&input.network)
        .map_err(|e| error(StatusCode::BAD_REQUEST, e))?
        .to_string();
    let mut change = Change::new(actor, "allowlist.remove", Scope::Policy, network.clone());
    change.reason = input.reason.clone();
    let on_conflict = conflict(&app, CONFLICT, Engine::policy_revision);
    mutation(app, change, move |e| {
        anyhow::ensure!(
            e.policy_revision() == input.expected_revision,
            "policy revision conflict; reload the allowlist and retry."
        );
        let mut policy = e.policy().clone();
        let before = policy.allow.len();
        policy.allow.retain(|n| *n != network);
        anyhow::ensure!(policy.allow.len() != before, "network is not allowlisted");
        policy.allow_meta.remove(&network);
        e.set_policy(policy)?;
        Ok(allowlist_document(e, now()))
    })
    .await
    .map_err(on_conflict)
}
