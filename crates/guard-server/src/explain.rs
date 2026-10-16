//! Administrative explain / what-if and decision evidence.
//!
//! Explain evaluates one address with the **same** decision function as live
//! HTTP/HGD1/gRPC decisions (`DecisionView::evaluate`), instantiated with a
//! bounded `VecTrace` instead of the zero-sized production `NoTrace`. It can
//! evaluate the published view or a candidate policy and/or rule set that is
//! validated exactly like a publication but never stored, published or audited
//! as a change. Simulated evidence, GeoIP metadata and evaluation time are
//! labelled as simulated in the response.
use crate::{ApiResult, App, error, now};
use axum::{Json, extract::State as HttpState, http::StatusCode};
use guard_core::{
    DecisionRef, DecisionView, FieldError, GeoContext, Mode, Policy, RuleAction, RuleSet,
    Suspicion, canonical_ip,
    trace::{AUTOMATIC_BLOCK_REASON, DecidingStage, Evidence, TraceEvent, VecTrace, reason_code},
};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{net::IpAddr, sync::Arc};

/// Maximum addresses in one batch explain.
pub const MAX_BATCH: usize = 1024;
/// Maximum simulated signals per kind.
const MAX_SIMULATED_SIGNALS: u32 = 10_000;
/// Simulated evaluation time window around now (30 days).
const MAX_TIME_SHIFT: u64 = 30 * 86_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    #[serde(default)]
    policy: Option<Policy>,
    #[serde(default)]
    rules: Option<RuleSet>,
    #[serde(default)]
    script: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulatedEvidence {
    #[serde(default)]
    honeypot: u32,
    #[serde(default)]
    scanner: u32,
    #[serde(default)]
    auth_failure: u32,
    #[serde(default)]
    invalid_request: u32,
    /// Add the currently observed bounded signal score (default true).
    #[serde(default = "yes")]
    include_observed: bool,
}
fn yes() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulatedGeo {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    asn: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainRequest {
    ip: IpAddr,
    #[serde(default)]
    candidate: Option<Candidate>,
    #[serde(default)]
    evidence: Option<SimulatedEvidence>,
    #[serde(default)]
    geo: Option<SimulatedGeo>,
    /// Simulated evaluation time (Unix seconds, within 30 days of now).
    #[serde(default)]
    at: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    ips: Vec<IpAddr>,
    #[serde(default)]
    candidate: Option<Candidate>,
    #[serde(default)]
    at: Option<u64>,
}

type Refusal = (StatusCode, Json<Value>);
fn invalid(errors: Vec<FieldError>) -> Refusal {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "invalid explain request", "errors": errors})),
    )
}
fn pointer(path: &serde_path_to_error::Path) -> String {
    let mut out = String::new();
    for segment in path.iter() {
        use serde_path_to_error::Segment;
        match segment {
            Segment::Seq { index } => out.push_str(&format!("/{index}")),
            Segment::Map { key } => {
                out.push_str(&format!("/{}", key.replace('~', "~0").replace('/', "~1")))
            }
            Segment::Enum { variant } => out.push_str(&format!("/{variant}")),
            Segment::Unknown => {}
        }
    }
    out
}
fn parse<T: for<'de> Deserialize<'de>>(body: Value) -> Result<T, Refusal> {
    serde_path_to_error::deserialize(body).map_err(|e| {
        let path = pointer(e.path());
        invalid(vec![FieldError::new(path, e.into_inner().to_string())])
    })
}
fn prefixed(prefix: &str, errors: Vec<FieldError>) -> Vec<FieldError> {
    errors
        .into_iter()
        .map(|e| FieldError::new(format!("{prefix}{}", e.path), e.message))
        .collect()
}
fn evaluation_time(at: Option<u64>) -> Result<(u64, bool), Refusal> {
    let current = now();
    match at {
        None => Ok((current, false)),
        Some(t) if t.abs_diff(current) <= MAX_TIME_SHIFT => Ok((t, true)),
        Some(_) => Err(invalid(vec![FieldError::new(
            "/at",
            "evaluation time must be within 30 days of now",
        )])),
    }
}

/// A validated, never-stored candidate.
struct PreparedCandidate {
    policy: Option<Policy>,
    rules: Option<RuleSet>,
    rules_source: &'static str,
    digest: String,
}
async fn prepare(
    app: &App,
    candidate: Option<Candidate>,
) -> Result<Option<PreparedCandidate>, Refusal> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let mut errors = Vec::new();
    if candidate.policy.is_none() && candidate.rules.is_none() && candidate.script.is_none() {
        errors.push(FieldError::new(
            "/candidate",
            "candidate needs policy, rules or script",
        ));
    }
    if candidate.rules.is_some() && candidate.script.is_some() {
        errors.push(FieldError::new(
            "/candidate/script",
            "provide at most one of rules or script",
        ));
    }
    if let Some(p) = &candidate.policy {
        errors.extend(prefixed("/candidate/policy", p.diagnose()));
    }
    if let Some(r) = &candidate.rules {
        errors.extend(prefixed("/candidate/rules", r.diagnose()));
    }
    if !errors.is_empty() {
        return Err(invalid(errors));
    }
    let (rules, rules_source) = match (candidate.rules, candidate.script) {
        (Some(mut rules), None) => {
            rules
                .validate()
                .map_err(|e| invalid(vec![FieldError::new("/candidate/rules", e.to_string())]))?;
            (Some(rules), "json")
        }
        (None, Some(script)) => {
            let compiled = crate::compile_script(app, script)
                .await
                .map_err(|(_, body)| {
                    invalid(vec![FieldError::new(
                        "/candidate/script",
                        body.0["error"].as_str().unwrap_or("Lua compilation failed"),
                    )])
                })?;
            (Some(compiled), "lua")
        }
        _ => (None, "published"),
    };
    let policy =
        match candidate.policy {
            Some(policy) => {
                let inner = app
                    .inner
                    .lock()
                    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
                Some(inner.engine.check_policy(policy).map_err(|e| {
                    invalid(vec![FieldError::new("/candidate/policy", e.to_string())])
                })?)
            }
            None => None,
        };
    let digest = crate::audit::digest(&json!({"policy": policy, "rules": rules}));
    Ok(Some(PreparedCandidate {
        policy,
        rules,
        rules_source,
        digest,
    }))
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
    }
}
fn action_name(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Observe => "observe",
        RuleAction::Allow => "allow",
        RuleAction::Deny => "deny",
    }
}
fn country_text(c: Option<[u8; 2]>) -> Option<String> {
    c.map(|c| String::from_utf8_lossy(&c).into_owned())
}
fn prefix_text(ip: IpAddr, bits: u8) -> Option<String> {
    let ip = canonical_ip(&ip.to_string()).ok()?;
    IpNet::new(ip, bits).ok().map(|n| n.trunc().to_string())
}
fn stage_value(stage: DecidingStage) -> Value {
    serde_json::to_value(stage).unwrap_or(Value::Null)
}
fn verdict(d: &DecisionRef<'_>) -> &'static str {
    if d.mode == Mode::Observe {
        "observe"
    } else {
        d.action
    }
}

/// Ordered stage list from a trace; stages not reached are omitted.
fn stages(
    ip: IpAddr,
    view: &DecisionView,
    trace: &VecTrace<'_>,
    now: u64,
    geo_simulated: bool,
) -> (Vec<Value>, Value) {
    let mut out = Vec::new();
    let mut rules_reached = false;
    let mut rules_pushed = false;
    let mut matched = Vec::new();
    let mut expired_rules = Vec::new();
    let mut winner = None;
    let mut expired_blocks = Vec::new();
    let mut outcome = json!({});
    for event in trace.events() {
        match *event {
            TraceEvent::Mode { mode } => out.push(json!({
                "stage": "mode", "mode": mode_name(mode),
                "code": format!("sumunjang.stage.mode.{}", mode_name(mode)), "params": {}})),
            TraceEvent::Allowlist { prefix_len } => {
                let network = prefix_len.and_then(|b| prefix_text(ip, b));
                out.push(json!({
                    "stage": "allowlist", "matched": prefix_len.is_some(), "network": network,
                    "code": if prefix_len.is_some() {"sumunjang.stage.allowlist.match"} else {"sumunjang.stage.allowlist.miss"},
                    "params": {"network": network}}));
            }
            TraceEvent::Geo {
                country,
                asn,
                asn_source,
            } => {
                rules_reached = true;
                out.push(json!({
                    "stage": "geo", "country": country_text(country), "asn": asn,
                    "asn_source": asn_source, "simulated": geo_simulated,
                    "required": view.requires_geo(),
                    "code": "sumunjang.stage.geo.context",
                    "params": {"country": country_text(country).unwrap_or_else(|| "-".into()),
                               "asn": asn.map_or("-".into(), |a| a.to_string()),
                               "source": serde_json::to_value(asn_source).unwrap_or(Value::Null)}}));
            }
            TraceEvent::RuleExpired { rule } => expired_rules.push(json!({
                "id": rule.id, "action": action_name(rule.action), "priority": rule.priority,
                "expires_at": rule.expires_at, "code": "sumunjang.stage.rule.expired",
                "params": {"rule": rule.id}})),
            TraceEvent::RuleMatched {
                rule,
                winner: first,
            } => {
                if first {
                    winner = Some(rule);
                }
                matched.push(json!({
                    "id": rule.id, "action": action_name(rule.action), "priority": rule.priority,
                    "score": rule.score, "winner": first, "expires_at": rule.expires_at,
                    "description": rule.description,
                    "code": "sumunjang.stage.rule.matched",
                    "params": {"rule": rule.id, "score": rule.score}}));
            }
            TraceEvent::BlockExpired { block } => expired_blocks.push(json!({
                "network": block.network, "expires_at": block.expires_at, "reason": block.reason,
                "code": "sumunjang.stage.block.expired", "params": {"network": block.network}})),
            TraceEvent::Block { block } => {
                if !rules_pushed {
                    push_rules(&mut out, view, &matched, &expired_rules, winner);
                    rules_pushed = true;
                }
                let block_json = block.map(|b| {
                    json!({
                    "network": b.network, "reason": b.reason, "expires_at": b.expires_at,
                    "remaining_secs": b.expires_at.saturating_sub(now)})
                });
                out.push(json!({
                    "stage": "blocklist", "block": block_json, "expired": expired_blocks,
                    "code": if block.is_some() {"sumunjang.stage.block.match"} else {"sumunjang.stage.block.miss"},
                    "params": {"network": block.map(|b| b.network.clone())}}));
                expired_blocks = Vec::new();
            }
            TraceEvent::Outcome { stage } => {
                if rules_reached && !rules_pushed {
                    push_rules(&mut out, view, &matched, &expired_rules, winner);
                    rules_pushed = true;
                }
                outcome = json!({"stage": "outcome", "deciding_stage": stage_value(stage)});
            }
        }
    }
    (out, outcome)
}
fn push_rules(
    out: &mut Vec<Value>,
    view: &DecisionView,
    matched: &[Value],
    expired: &[Value],
    winner: Option<&guard_core::Rule>,
) {
    let configured = view.compiled_rules().len();
    let (code, params) = match winner {
        _ if configured == 0 => ("sumunjang.stage.rules.none", json!({})),
        None => ("sumunjang.stage.rules.no_match", json!({})),
        Some(r) if r.action == RuleAction::Observe => (
            "sumunjang.stage.rules.observe_winner",
            json!({"rule": r.id}),
        ),
        Some(r) => (
            "sumunjang.stage.rules.winner",
            json!({"rule": r.id, "action": action_name(r.action), "priority": r.priority}),
        ),
    };
    out.push(json!({
        "stage": "rules", "configured": configured, "winner": winner.map(|r| r.id.clone()),
        "matched": matched, "expired": expired, "code": code, "params": params}));
}

/// One complete traced evaluation rendered as JSON.
fn render(
    view: &DecisionView,
    ip: IpAddr,
    now: u64,
    geo: GeoContext<'_>,
    mode: Mode,
    geo_simulated: bool,
) -> (Value, DecidingStage) {
    let mut trace = VecTrace::default();
    let d = view.evaluate_as(mode, ip, now, geo, &mut trace);
    let (mut stages, mut outcome) = stages(ip, view, &trace, now, geo_simulated);
    let mut ev = Evidence::default();
    for event in trace.events() {
        guard_core::trace::Tracer::event(&mut ev, *event);
    }
    let stage = ev.stage.unwrap_or(DecidingStage::Default);
    let code = reason_code(stage, ev.winner, ev.block);
    let params = json!({
        "rule": ev.winner.map(|r| r.id.clone()),
        "network": ev.block.map(|b| b.network.clone())
            .or_else(|| trace.events().iter().find_map(|e| match e {
                TraceEvent::Allowlist { prefix_len: Some(b) } => prefix_text(ip, *b),
                _ => None,
            })),
    });
    outcome["action"] = json!(d.action);
    outcome["code"] = json!(code);
    outcome["params"] = params.clone();
    stages.push(outcome);
    let matched: Vec<_> = ev.rules().map(|r| r.id.clone()).collect();
    (
        json!({
            "decision": d,
            "verdict": verdict(&d),
            "reason_code": code,
            "message_key": code,
            "params": params,
            "matched_rules": matched,
            "stages": stages,
            "trace_truncated": trace.truncated(),
        }),
        stage,
    )
}

/// `POST /v1/explain`
pub async fn explain(HttpState(app): HttpState<App>, Json(body): Json<Value>) -> ApiResult {
    let input: ExplainRequest = parse(body)?;
    let (time, time_simulated) = evaluation_time(input.at)?;
    let mut errors = Vec::new();
    if let Some(e) = &input.evidence {
        for (name, n) in [
            ("honeypot", e.honeypot),
            ("scanner", e.scanner),
            ("auth_failure", e.auth_failure),
            ("invalid_request", e.invalid_request),
        ] {
            if n > MAX_SIMULATED_SIGNALS {
                errors.push(FieldError::new(
                    format!("/evidence/{name}"),
                    "at most 10000 simulated signals",
                ));
            }
        }
    }
    if let Some(g) = &input.geo {
        if g.country
            .as_ref()
            .is_some_and(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            errors.push(FieldError::new(
                "/geo/country",
                "country must be two ASCII letters",
            ));
        }
        if g.asn == Some(0) {
            errors.push(FieldError::new("/geo/asn", "ASN must be positive"));
        }
    }
    if !errors.is_empty() {
        return Err(invalid(errors));
    }
    let candidate = prepare(&app, input.candidate).await?;
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let ip = input.ip;
        let published = app.view.load_full();
        let (observed, published_policy, policy_revision) = {
            let mut inner = app
                .inner
                .lock()
                .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "state unavailable"))?;
            let ip = canonical_ip(&ip.to_string()).map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
            (
                inner.engine.signal_score(ip, time),
                inner.engine.policy().clone(),
                inner.engine.policy_revision(),
            )
        };
        let view = match &candidate {
            Some(c) => Arc::new(
                published
                    .with_candidate(c.policy.as_ref(), c.rules.as_ref())
                    .map_err(|e| error(StatusCode::BAD_REQUEST, e))?,
            ),
            None => published.clone(),
        };
        let policy = candidate
            .as_ref()
            .and_then(|c| c.policy.clone())
            .unwrap_or(published_policy);
        let catalog = app.geo.load_full();
        let looked_up = catalog.context(ip);
        let simulated_country = input.geo.as_ref().and_then(|g| g.country.as_ref().map(|c| c.to_ascii_uppercase()));
        let full_geo = GeoContext {
            country: simulated_country.as_deref().or(looked_up.country),
            asn: input.geo.as_ref().and_then(|g| g.asn).or(looked_up.asn),
        };
        // Same geo input rule as live decisions: metadata reaches rule
        // evaluation only when the evaluated rule set requires it.
        let rule_geo = if view.requires_geo() { full_geo } else { GeoContext::default() };
        let geo_simulated = input.geo.is_some();
        let (mut result, stage) = render(&view, ip, time, rule_geo, view.mode, geo_simulated);
        let decision_action = result["decision"]["action"].as_str().unwrap_or("allow") == "deny";
        if view.mode == Mode::Observe {
            let (preview, _) = render(&view, ip, time, rule_geo, Mode::Enforce, geo_simulated);
            result["enforce_preview"] = preview;
        }
        // Informational risk score (not part of the decision), as /v1/lookup.
        let simulated = input.evidence.as_ref();
        let weights = &policy.weights;
        let simulated_score = simulated.map_or(0u64, |e| {
            [
                (e.honeypot, weights.honeypot),
                (e.scanner, weights.scanner),
                (e.auth_failure, weights.auth_failure),
                (e.invalid_request, weights.invalid_request),
            ]
            .iter()
            .fold(0u64, |s, (n, w)| s.saturating_add(u64::from(*n) * u64::from(*w)))
        });
        let observed_score = if simulated.is_none_or(|e| e.include_observed) { observed } else { 0 };
        let signal = observed_score.saturating_add(simulated_score);
        let (rule_score, scored_rules) = view.rule_score(ip, time, full_geo);
        let total = signal.saturating_add(rule_score);
        let suspicion = Suspicion::from_score(total, policy.threshold, decision_action);
        let suspicion_name = serde_json::to_value(suspicion).unwrap_or(Value::Null);
        let stages = result["stages"].as_array_mut().expect("stages array");
        stages.push(json!({
            "stage": "score", "informational": true,
            "signal_score": signal, "observed_signal_score": observed_score,
            "simulated_signal_score": simulated_score, "static_rule_score": rule_score,
            "scored_rules": scored_rules, "total": total, "threshold": policy.threshold,
            "suspicion": suspicion_name,
            "code": format!("sumunjang.stage.score.{}", suspicion_name.as_str().unwrap_or("normal")),
            "params": {"score": total, "threshold": policy.threshold}}));
        let would_trigger = policy.mode == Mode::Enforce
            && policy.auto_block
            && signal >= policy.threshold
            && stage == DecidingStage::Default;
        stages.push(json!({
            "stage": "auto_block", "informational": true, "enabled": policy.auto_block,
            "would_trigger": would_trigger,
            "projected": would_trigger.then(|| json!({
                "action": "deny", "reason": AUTOMATIC_BLOCK_REASON,
                "reason_code": "sumunjang.deny.block_automatic",
                "block_ttl_secs": policy.block_ttl_secs})),
            "code": if would_trigger {"sumunjang.stage.auto_block.would_trigger"} else {"sumunjang.stage.auto_block.not_triggered"},
            "params": {}}));
        result["schema"] = json!("sumunjang.explain.v1");
        result["ip"] = json!(ip.to_string());
        result["at"] = json!(time);
        result["simulated"] = json!({"time": time_simulated, "geo": geo_simulated, "evidence": simulated.is_some()});
        result["geoip"] = json!({"country": full_geo.country, "asn": full_geo.asn.or_else(|| view.catalog_asn(ip))});
        result["evaluated"] = json!({
            "source": if candidate.is_some() {"candidate"} else {"published"},
            "revision": view.revision,
            "policy_revision": policy_revision,
            "mode": mode_name(view.mode),
            "candidate_digest": candidate.as_ref().map(|c| c.digest.clone()),
            "rules_source": candidate.as_ref().map_or("published", |c| c.rules_source),
            "source_available": app.source_remaining(&published).is_some(),
            "stored": false,
        });
        Ok(Json(result))
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

/// Compact allocation-light evaluation for batch impact analysis.
fn compact(
    view: &DecisionView,
    ip: IpAddr,
    now: u64,
    geo: GeoContext<'_>,
) -> (Value, &'static str, &'static str) {
    let mut ev = Evidence::default();
    let d = view.evaluate(ip, now, geo, &mut ev);
    let stage = ev.stage.unwrap_or(DecidingStage::Default);
    let code = reason_code(stage, ev.winner, ev.block);
    let v = verdict(&d);
    (
        json!({"action": d.action, "verdict": v, "reason_code": code,
               "rules": ev.rules().map(|r| r.id.clone()).collect::<Vec<_>>(),
               "block": ev.block.map(|b| b.network.clone())}),
        d.action,
        code,
    )
}

/// `POST /v1/explain/batch`: bounded impact analysis of a candidate.
pub async fn batch(HttpState(app): HttpState<App>, Json(body): Json<Value>) -> ApiResult {
    let input: BatchRequest = parse(body)?;
    if input.ips.is_empty() || input.ips.len() > MAX_BATCH {
        return Err(invalid(vec![FieldError::new(
            "/ips",
            "provide 1..=1024 addresses",
        )]));
    }
    let (time, time_simulated) = evaluation_time(input.at)?;
    let candidate = prepare(&app, input.candidate).await?;
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "worker capacity reached"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let published = app.view.load_full();
        let proposed = candidate
            .as_ref()
            .map(|c| published.with_candidate(c.policy.as_ref(), c.rules.as_ref()))
            .transpose()
            .map_err(|e| error(StatusCode::BAD_REQUEST, e))?;
        let catalog = app.geo.load_full();
        let mut results = Vec::with_capacity(input.ips.len());
        let (mut changed, mut allow_to_deny, mut deny_to_allow, mut reason_changed) = (0, 0, 0, 0);
        for ip in &input.ips {
            let geo_for = |v: &DecisionView| {
                if v.requires_geo() {
                    catalog.context(*ip)
                } else {
                    GeoContext::default()
                }
            };
            let (p, p_action, p_code) = compact(&published, *ip, time, geo_for(&published));
            let mut entry = json!({"ip": ip.to_string(), "published": p});
            if let Some(view) = &proposed {
                let (c, c_action, c_code) = compact(view, *ip, time, geo_for(view));
                let action_changed = p_action != c_action;
                let differs = action_changed
                    || p_code != c_code
                    || entry["published"]["verdict"] != c["verdict"];
                if differs {
                    changed += 1;
                }
                if action_changed && c_action == "deny" {
                    allow_to_deny += 1;
                } else if action_changed {
                    deny_to_allow += 1;
                } else if p_code != c_code {
                    reason_changed += 1;
                }
                entry["candidate"] = c;
                entry["changed"] = json!(differs);
            }
            results.push(entry);
        }
        Ok(Json(json!({
            "schema": "sumunjang.explain.batch.v1",
            "at": time,
            "simulated": {"time": time_simulated},
            "evaluated": {
                "published_revision": published.revision,
                "candidate_digest": candidate.as_ref().map(|c| c.digest.clone()),
                "rules_source": candidate.as_ref().map_or("published", |c| c.rules_source),
                "stored": false,
            },
            "summary": candidate.as_ref().map(|_| json!({
                "total": input.ips.len(), "changed": changed, "allow_to_deny": allow_to_deny,
                "deny_to_allow": deny_to_allow, "reason_changed": reason_changed})),
            "results": results,
        })))
    })
    .await
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "worker failed"))?
}

/// `GET /v1/reasons`: registered reason codes and en/ko catalogs.
pub async fn reasons() -> Json<Value> {
    use guard_core::reasons::*;
    let en: Value = serde_json::from_str(MESSAGES_EN).unwrap_or(Value::Null);
    let ko: Value = serde_json::from_str(MESSAGES_KO).unwrap_or(Value::Null);
    Json(json!({
        "schema": "sumunjang.reasons.v1",
        "codes": {"decision": DECISION_CODES, "stage": STAGE_CODES, "audit": AUDIT_CODES},
        "messages": {"en": en, "ko": ko},
    }))
}

/// Decision evidence shared by gRPC and HTTP `/v1/decision`.
pub struct DecisionEvidence {
    pub reason_code: &'static str,
    pub stage: DecidingStage,
    pub rules: Vec<String>,
    pub rules_truncated: bool,
    pub block_network: Option<String>,
    pub asn: Option<u32>,
    pub country: Option<String>,
    pub enforce_action: &'static str,
    pub enforce_reason_code: &'static str,
}
/// Evaluate `ip` on `view` with the live geo input and collect evidence. In
/// observe mode the matched rules and enforce outcome come from evaluating the
/// same published view as enforce (what enforcement would decide).
pub fn decision_evidence(
    view: &DecisionView,
    catalog: &crate::geoip::GeoCatalog,
    ip: IpAddr,
    time: u64,
) -> (DecisionEvidence, &'static str) {
    let full = catalog.context(ip);
    let rule_geo = if view.requires_geo() {
        full
    } else {
        GeoContext::default()
    };
    let mut enforce = Evidence::default();
    let e = view.evaluate_as(Mode::Enforce, ip, time, rule_geo, &mut enforce);
    let enforce_stage = enforce.stage.unwrap_or(DecidingStage::Default);
    let enforce_code = reason_code(enforce_stage, enforce.winner, enforce.block);
    let (stage, code, action) = if view.mode == Mode::Observe {
        (DecidingStage::Observe, "sumunjang.observe.mode", "allow")
    } else {
        (enforce_stage, enforce_code, e.action)
    };
    (
        DecisionEvidence {
            reason_code: code,
            stage,
            rules: enforce.rules().map(|r| r.id.clone()).collect(),
            rules_truncated: enforce.rules_truncated,
            block_network: enforce.block.map(|b| b.network.clone()),
            asn: enforce.asn.or(full.asn).or_else(|| view.catalog_asn(ip)),
            country: country_text(enforce.country).or_else(|| full.country.map(str::to_owned)),
            enforce_action: e.action,
            enforce_reason_code: enforce_code,
        },
        action,
    )
}
impl DecisionEvidence {
    pub fn to_json(&self, mode: Mode, revision: u64) -> Value {
        json!({
            "schema": "sumunjang.evidence.v1",
            "verdict": if mode == Mode::Observe {"observe"} else if self.enforce_action == "deny" {"deny"} else {"allow"},
            "mode": mode_name(mode),
            "reason_code": self.reason_code,
            "deciding_stage": stage_value(self.stage),
            "rules": self.rules,
            "rules_truncated": self.rules_truncated,
            "block": self.block_network,
            "asn": self.asn,
            "country": self.country,
            "revision": revision,
            "enforce": {"action": self.enforce_action, "reason_code": self.enforce_reason_code},
        })
    }
}
