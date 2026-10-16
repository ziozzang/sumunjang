//! Durable, bounded audit of administrative policy changes.
//!
//! Every committed policy change is written in the **same SQLite transaction** as
//! the policy checkpoint, so a change cannot become durable without its audit row
//! and an audit write failure refuses the change. Refused attempts are recorded
//! best-effort in their own transaction (nothing changed, so a failure there does
//! not alter the refusal). Changes with effects outside SQLite (signed update
//! requests) are first recorded as `uncertain` and then finalized; a crash in
//! between leaves `uncertain`, which is the truthful state.
use crate::actor::{Actor, sha256_hex};
use guard_core::{Block, Engine, Policy, RuleSet};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const DEFAULT_MAX_ROWS: u64 = 100_000;
pub const DEFAULT_MAX_DAYS: u64 = 365;
pub const MAX_PAGE: u32 = 200;
const MAX_SUMMARY: usize = 1024;
const MAX_LISTED: usize = 8;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS audit(
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 time_ms INTEGER NOT NULL,
 actor_kind TEXT NOT NULL,
 actor_id INTEGER,
 actor TEXT NOT NULL,
 issuer TEXT NOT NULL,
 client_ip TEXT,
 request_sha256 TEXT,
 action TEXT NOT NULL,
 target TEXT NOT NULL,
 result TEXT NOT NULL CHECK(result IN ('committed','refused','uncertain')),
 revision_before INTEGER,
 revision_after INTEGER,
 policy_revision TEXT,
 before_digest TEXT,
 after_digest TEXT,
 summary TEXT NOT NULL,
 reason TEXT,
 error TEXT);
CREATE INDEX IF NOT EXISTS audit_time ON audit(time_ms);";

/// Retention bounds: whichever is reached first removes the oldest rows.
#[derive(Clone, Copy, Debug)]
pub struct Retention {
    pub max_rows: u64,
    pub max_days: u64,
}
impl Default for Retention {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_MAX_ROWS,
            max_days: DEFAULT_MAX_DAYS,
        }
    }
}
impl Retention {
    fn oldest_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.max_days.saturating_mul(86_400_000))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Committed,
    Refused,
    Uncertain,
}
impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
        }
    }
}

/// One audit row before insertion.
#[derive(Clone, Debug)]
pub struct Record {
    pub id: String,
    pub actor: Actor,
    pub action: &'static str,
    pub target: String,
    pub result: Outcome,
    pub revision_before: Option<u64>,
    pub revision_after: Option<u64>,
    pub policy_revision: Option<String>,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub summary: String,
    pub reason: Option<String>,
    pub error: Option<String>,
}
impl Record {
    pub fn new(actor: Actor, action: &'static str, target: impl Into<String>) -> Self {
        Self {
            id: new_id(),
            actor,
            action,
            target: bounded(target.into(), 256),
            result: Outcome::Committed,
            revision_before: None,
            revision_after: None,
            policy_revision: None,
            before_digest: None,
            after_digest: None,
            summary: String::new(),
            reason: None,
            error: None,
        }
    }
}

pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    // A failure leaves a time-derived ID; IDs are correlation handles, not secrets.
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
        bytes[..8].copy_from_slice(&now_ms().to_be_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn bounded(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max.saturating_sub(3);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push_str("...");
    }
    s
}

pub fn init(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(SCHEMA)
}

/// Insert a record and enforce retention, inside the caller's transaction.
pub fn insert(db: &Connection, retention: Retention, record: &Record) -> rusqlite::Result<()> {
    let now = now_ms();
    db.execute(
        "INSERT INTO audit(id,time_ms,actor_kind,actor_id,actor,issuer,client_ip,request_sha256,action,target,result,revision_before,revision_after,policy_revision,before_digest,after_digest,summary,reason,error) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
            record.id,
            now as i64,
            record.actor.kind,
            record.actor.id,
            record.actor.name,
            record.actor.issuer,
            record.actor.client_ip,
            record.actor.request_sha256,
            record.action,
            record.target,
            record.result.as_str(),
            record.revision_before.map(|v| v as i64),
            record.revision_after.map(|v| v as i64),
            record.policy_revision,
            record.before_digest,
            record.after_digest,
            bounded(record.summary.clone(), MAX_SUMMARY),
            record.reason.clone().map(|r| bounded(r, 256)),
            record.error.clone().map(|e| bounded(e, 512)),
        ],
    )?;
    prune(db, retention, now)
}

/// Remove rows beyond the row or age bound.
pub fn prune(db: &Connection, retention: Retention, now_ms: u64) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM audit WHERE time_ms < ?1",
        [retention.oldest_ms(now_ms) as i64],
    )?;
    db.execute(
        "DELETE FROM audit WHERE seq <= (SELECT MAX(seq) FROM audit) - ?1",
        [retention.max_rows as i64],
    )?;
    Ok(())
}

/// Best-effort standalone insert (refusals and two-phase starts).
pub fn insert_alone(
    db: &mut Connection,
    retention: Retention,
    record: &Record,
) -> anyhow::Result<()> {
    let tx = db.transaction()?;
    insert(&tx, retention, record)?;
    tx.commit()?;
    Ok(())
}

/// Finalize a two-phase (`uncertain`) record.
pub fn finish(
    db: &Connection,
    id: &str,
    result: Outcome,
    error: Option<&str>,
) -> anyhow::Result<()> {
    let changed = db.execute(
        "UPDATE audit SET result=?2, error=?3 WHERE id=?1 AND result='uncertain'",
        params![id, result.as_str(), error],
    )?;
    anyhow::ensure!(changed == 1, "audit record missing");
    Ok(())
}

/// Query filters shared by `GET /v1/audit` (query string) and
/// `POST /v1/audit/query` (JSON body, for the console broker which forwards no
/// query strings).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// Inclusive lower bound, Unix seconds.
    pub since: Option<u64>,
    /// Exclusive upper bound, Unix seconds.
    pub until: Option<u64>,
    /// Exact actor name.
    pub actor: Option<String>,
    /// Exact action, or a prefix ending in `.*` (for example `blocks.*`).
    pub action: Option<String>,
    pub result: Option<Outcome>,
    /// Exact target.
    pub target: Option<String>,
    /// 1..=200, default 50.
    pub limit: Option<u32>,
    /// Opaque cursor from a previous page's `next_cursor`.
    pub cursor: Option<String>,
}

pub fn query(db: &Connection, retention: Retention, filter: &Filter) -> anyhow::Result<Value> {
    let limit = filter.limit.unwrap_or(50);
    anyhow::ensure!((1..=MAX_PAGE).contains(&limit), "limit must be 1..=200");
    for value in [&filter.actor, &filter.action, &filter.target]
        .into_iter()
        .flatten()
    {
        anyhow::ensure!(
            !value.is_empty() && value.len() <= 256,
            "filter value must be 1..=256 bytes"
        );
    }
    let cursor = match &filter.cursor {
        None => i64::MAX,
        Some(c) => c
            .strip_prefix("a")
            .and_then(|n| n.parse::<i64>().ok())
            .filter(|n| *n > 0)
            .ok_or_else(|| anyhow::anyhow!("invalid cursor"))?,
    };
    let oldest = retention.oldest_ms(now_ms()) as i64;
    let since = filter
        .since
        .map_or(oldest, |s| (s.saturating_mul(1000) as i64).max(oldest));
    let until = filter.until.map_or(i64::MAX, |u| {
        u.saturating_mul(1000).min(i64::MAX as u64) as i64
    });
    let (action_exact, action_prefix) = match filter.action.as_deref() {
        Some(a) if a.ends_with(".*") => (None, Some(format!("{}.", &a[..a.len() - 2]))),
        Some(a) => (Some(a.to_owned()), None),
        None => (None, None),
    };
    let mut stmt = db.prepare_cached(
        "SELECT seq,id,time_ms,actor_kind,actor_id,actor,issuer,client_ip,request_sha256,action,target,result,revision_before,revision_after,policy_revision,before_digest,after_digest,summary,reason,error FROM audit
         WHERE seq < ?1 AND time_ms >= ?2 AND time_ms < ?3
           AND (?4 IS NULL OR actor = ?4)
           AND (?5 IS NULL OR action = ?5)
           AND (?6 IS NULL OR substr(action,1,length(?6)) = ?6)
           AND (?7 IS NULL OR result = ?7)
           AND (?8 IS NULL OR target = ?8)
         ORDER BY seq DESC LIMIT ?9",
    )?;
    let mut entries = Vec::new();
    let mut last = None;
    let mut more = false;
    let rows = stmt.query_map(
        params![
            cursor,
            since,
            until,
            filter.actor,
            action_exact,
            action_prefix,
            filter.result.map(Outcome::as_str),
            filter.target,
            limit as i64 + 1
        ],
        |r| {
            let time_ms: i64 = r.get(2)?;
            Ok((
                r.get::<_, i64>(0)?,
                json!({
                    "id": r.get::<_, String>(1)?,
                    "time": time_ms / 1000,
                    "time_ms": time_ms,
                    "actor": {"kind": r.get::<_, String>(3)?, "id": r.get::<_, Option<i64>>(4)?,
                              "name": r.get::<_, String>(5)?, "issuer": r.get::<_, String>(6)?,
                              "client_ip": r.get::<_, Option<String>>(7)?,
                              "request_sha256": r.get::<_, Option<String>>(8)?},
                    "action": r.get::<_, String>(9)?,
                    "target": r.get::<_, String>(10)?,
                    "result": r.get::<_, String>(11)?,
                    "revision_before": r.get::<_, Option<i64>>(12)?,
                    "revision_after": r.get::<_, Option<i64>>(13)?,
                    "policy_revision": r.get::<_, Option<String>>(14)?,
                    "before_digest": r.get::<_, Option<String>>(15)?,
                    "after_digest": r.get::<_, Option<String>>(16)?,
                    "summary": r.get::<_, String>(17)?,
                    "reason": r.get::<_, Option<String>>(18)?,
                    "error": r.get::<_, Option<String>>(19)?,
                }),
            ))
        },
    )?;
    for row in rows {
        let (seq, mut entry) = row?;
        if entries.len() == limit as usize {
            more = true;
            break;
        }
        let result = entry["result"].as_str().unwrap_or("").to_owned();
        entry["message_key"] = json!(format!("sumunjang.audit.result.{result}"));
        entries.push(entry);
        last = Some(seq);
    }
    let total: i64 = db.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))?;
    let oldest_retained: Option<i64> = db
        .query_row("SELECT MIN(time_ms) FROM audit", [], |r| r.get(0))
        .optional()?
        .flatten();
    Ok(json!({
        "schema": "sumunjang.audit.v1",
        "entries": entries,
        "next_cursor": if more { last.map(|s| format!("a{s}")) } else { None },
        "retention": {"max_rows": retention.max_rows, "max_days": retention.max_days,
                      "retained_rows": total, "oldest_retained_ms": oldest_retained},
    }))
}
// ----- digests and human-readable change summaries -----

pub fn digest(value: &impl Serialize) -> String {
    format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(value).unwrap_or_default())
    )
}
pub fn policy_digest(e: &Engine) -> String {
    digest(e.policy())
}
pub fn rules_digest(e: &Engine) -> String {
    digest(e.rules())
}
pub fn blocks_digest(e: &Engine) -> String {
    digest(&e.blocks().collect::<Vec<_>>())
}
/// Digest of everything a native source publishes.
pub fn state_digest(e: &Engine) -> String {
    digest(
        &json!({"policy": e.policy(), "rules": e.rules(), "blocks": e.blocks().collect::<Vec<_>>()}),
    )
}

fn list(items: &[String]) -> String {
    let mut s = items
        .iter()
        .take(MAX_LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > MAX_LISTED {
        s.push_str(&format!(", ... (+{})", items.len() - MAX_LISTED));
    }
    s
}

pub fn policy_summary(before: &Policy, after: &Policy) -> String {
    let mut parts = Vec::new();
    let mut field = |name: &str, a: String, b: String| {
        if a != b {
            parts.push(format!("{name} {a} -> {b}"));
        }
    };
    let mode = |p: &Policy| {
        serde_json::to_value(p.mode)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    field("mode", mode(before), mode(after));
    field(
        "auto_block",
        before.auto_block.to_string(),
        after.auto_block.to_string(),
    );
    field(
        "window_secs",
        before.window_secs.to_string(),
        after.window_secs.to_string(),
    );
    field(
        "threshold",
        before.threshold.to_string(),
        after.threshold.to_string(),
    );
    field(
        "block_ttl_secs",
        before.block_ttl_secs.to_string(),
        after.block_ttl_secs.to_string(),
    );
    for (name, a, b) in [
        (
            "weights.honeypot",
            before.weights.honeypot,
            after.weights.honeypot,
        ),
        (
            "weights.scanner",
            before.weights.scanner,
            after.weights.scanner,
        ),
        (
            "weights.auth_failure",
            before.weights.auth_failure,
            after.weights.auth_failure,
        ),
        (
            "weights.invalid_request",
            before.weights.invalid_request,
            after.weights.invalid_request,
        ),
    ] {
        field(name, a.to_string(), b.to_string());
    }
    let old: std::collections::BTreeSet<_> = before.allow.iter().collect();
    let new: std::collections::BTreeSet<_> = after.allow.iter().collect();
    let added: Vec<String> = new.difference(&old).map(|s| s.to_string()).collect();
    let removed: Vec<String> = old.difference(&new).map(|s| s.to_string()).collect();
    if !added.is_empty() {
        parts.push(format!("allow +{}: {}", added.len(), list(&added)));
    }
    if !removed.is_empty() {
        parts.push(format!("allow -{}: {}", removed.len(), list(&removed)));
    }
    if parts.is_empty() {
        "policy republished without effective change".into()
    } else {
        parts.join("; ")
    }
}

pub fn rules_summary(before: &RuleSet, after: &RuleSet) -> String {
    let index = |r: &RuleSet| -> BTreeMap<String, Value> {
        r.rules
            .iter()
            .map(|r| (r.id.clone(), serde_json::to_value(r).unwrap_or(Value::Null)))
            .collect()
    };
    let (old, new) = (index(before), index(after));
    let added: Vec<String> = new
        .keys()
        .filter(|k| !old.contains_key(*k))
        .cloned()
        .collect();
    let removed: Vec<String> = old
        .keys()
        .filter(|k| !new.contains_key(*k))
        .cloned()
        .collect();
    let changed: Vec<String> = new
        .iter()
        .filter(|(k, v)| old.get(*k).is_some_and(|o| o != *v))
        .map(|(k, _)| k.clone())
        .collect();
    let mut parts = vec![format!("rules {} -> {}", old.len(), new.len())];
    for (label, ids) in [("added", added), ("removed", removed), ("changed", changed)] {
        if !ids.is_empty() {
            parts.push(format!("{label} {}", list(&ids)));
        }
    }
    if parts.len() == 1 {
        parts.push("no effective change".into());
    }
    parts.join("; ")
}

pub fn blocks_summary<'a>(
    before: impl Iterator<Item = &'a Block>,
    after: impl Iterator<Item = &'a Block>,
) -> String {
    let old: BTreeMap<&str, &Block> = before.map(|b| (b.network.as_str(), b)).collect();
    let new: BTreeMap<&str, &Block> = after.map(|b| (b.network.as_str(), b)).collect();
    let describe = |b: &Block| {
        format!(
            "{} (expires {}, reason {:?})",
            b.network, b.expires_at, b.reason
        )
    };
    let added: Vec<String> = new
        .iter()
        .filter(|(k, _)| !old.contains_key(*k))
        .map(|(_, b)| describe(b))
        .collect();
    let removed: Vec<String> = old
        .keys()
        .filter(|k| !new.contains_key(*k))
        .map(|k| k.to_string())
        .collect();
    let changed: Vec<String> = new
        .iter()
        .filter(|(k, b)| {
            old.get(*k)
                .is_some_and(|o| o.expires_at != b.expires_at || o.reason != b.reason)
        })
        .map(|(_, b)| describe(b))
        .collect();
    let mut parts = Vec::new();
    for (label, items) in [
        ("block added", added),
        ("block removed", removed),
        ("block changed", changed),
    ] {
        if !items.is_empty() {
            parts.push(format!("{label} {}", list(&items)));
        }
    }
    if parts.is_empty() {
        "no block change".into()
    } else {
        parts.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        init(&db).unwrap();
        db
    }
    fn record(action: &'static str, actor: &str, result: Outcome) -> Record {
        let mut a = Actor::credential();
        a.name = actor.into();
        let mut r = Record::new(a, action, "policy");
        r.result = result;
        r.summary = "s".into();
        r
    }
    #[test]
    fn row_retention_filters_and_cursor_pagination() {
        let mut db = db();
        let retention = Retention {
            max_rows: 5,
            max_days: 1,
        };
        for i in 0..8 {
            let action = if i % 2 == 0 {
                "blocks.add"
            } else {
                "policy.replace"
            };
            let result = if i == 7 {
                Outcome::Refused
            } else {
                Outcome::Committed
            };
            insert_alone(
                &mut db,
                retention,
                &record(action, if i < 4 { "a" } else { "b" }, result),
            )
            .unwrap();
        }
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 5);
        let page = query(
            &db,
            retention,
            &Filter {
                limit: Some(2),
                ..Filter::default()
            },
        )
        .unwrap();
        assert_eq!(page["entries"].as_array().unwrap().len(), 2);
        let cursor = page["next_cursor"].as_str().unwrap().to_owned();
        let mut seen = 2;
        let mut next = Some(cursor);
        while let Some(c) = next {
            let p = query(
                &db,
                retention,
                &Filter {
                    limit: Some(2),
                    cursor: Some(c),
                    ..Filter::default()
                },
            )
            .unwrap();
            seen += p["entries"].as_array().unwrap().len();
            next = p["next_cursor"].as_str().map(str::to_owned);
        }
        assert_eq!(seen, 5);
        let f = |filter: Filter| {
            query(&db, retention, &filter).unwrap()["entries"]
                .as_array()
                .unwrap()
                .len()
        };
        assert_eq!(
            f(Filter {
                action: Some("blocks.*".into()),
                ..Filter::default()
            }),
            2
        );
        assert_eq!(
            f(Filter {
                action: Some("policy.replace".into()),
                ..Filter::default()
            }),
            3
        );
        assert_eq!(
            f(Filter {
                result: Some(Outcome::Refused),
                ..Filter::default()
            }),
            1
        );
        assert_eq!(
            f(Filter {
                actor: Some("a".into()),
                ..Filter::default()
            }),
            1
        );
        assert_eq!(
            f(Filter {
                since: Some(u64::MAX / 2000),
                ..Filter::default()
            }),
            0
        );
        assert!(
            query(
                &db,
                retention,
                &Filter {
                    limit: Some(201),
                    ..Filter::default()
                }
            )
            .is_err()
        );
        assert!(
            query(
                &db,
                retention,
                &Filter {
                    cursor: Some("x".into()),
                    ..Filter::default()
                }
            )
            .is_err()
        );
        // Age retention: an old row disappears from reads and on the next prune.
        db.execute(
            "UPDATE audit SET time_ms = 1 WHERE seq = (SELECT MAX(seq) FROM audit)",
            [],
        )
        .unwrap();
        assert_eq!(f(Filter::default()), 4);
        prune(&db, retention, now_ms()).unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 4);
    }
    #[test]
    fn two_phase_finish_and_summaries() {
        let mut db = db();
        let mut r = record("update.check", "a", Outcome::Uncertain);
        r.target = "update".into();
        insert_alone(&mut db, Retention::default(), &r).unwrap();
        finish(&db, &r.id, Outcome::Committed, None).unwrap();
        assert!(finish(&db, &r.id, Outcome::Refused, None).is_err());
        let before = Policy::default();
        let after = Policy {
            threshold: 20,
            allow: vec!["192.0.2.0/24".into()],
            ..Policy::default()
        };
        assert_eq!(
            policy_summary(&before, &after),
            "threshold 10 -> 20; allow +1: 192.0.2.0/24"
        );
        assert_eq!(
            policy_summary(&before, &before),
            "policy republished without effective change"
        );
        let long = "x".repeat(2000);
        assert!(bounded(long, MAX_SUMMARY).len() <= MAX_SUMMARY);
    }
}
