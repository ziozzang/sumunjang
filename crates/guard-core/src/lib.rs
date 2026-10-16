pub mod reasons;
pub mod rules;
pub mod trace;
use rules::CompiledRules;
pub use rules::{GeoContext, Rule, RuleAction, RuleSet, Suspicion};
use trace::{AsnSource, DecidingStage, NoTrace, TraceEvent, Tracer};
pub mod network_policy;
pub mod pod_peers;
pub mod prefix;
pub mod selector;
use anyhow::{Result, ensure};
use ipnet::IpNet;
use prefix::PrefixTrie;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

pub const MAX_CANDIDATES: usize = 10_000;
pub const MAX_BLOCKS: usize = 100_000;
pub const MAX_BATCH: usize = 256;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Enforce,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Honeypot,
    Scanner,
    AuthFailure,
    InvalidRequest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub ip: String,
    pub kind: EventKind,
    pub observed_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    pub source_id: String,
    pub events: Vec<Event>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub network: String,
    pub expires_at: u64,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub revision: u64,
    pub generated_at: u64,
    pub valid_until: u64,
    pub mode: Mode,
    pub allow: Vec<String>,
    pub blocks: Vec<Block>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    pub honeypot: u32,
    pub scanner: u32,
    pub auth_failure: u32,
    pub invalid_request: u32,
}
impl Default for Weights {
    fn default() -> Self {
        Self {
            honeypot: 10,
            scanner: 5,
            auth_failure: 1,
            invalid_request: 2,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    pub auto_block: bool,
    pub window_secs: u64,
    pub threshold: u64,
    pub block_ttl_secs: u64,
    pub allow: Vec<String>,
    pub weights: Weights,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            auto_block: false,
            window_secs: 60,
            threshold: 10,
            block_ttl_secs: 900,
            allow: vec![],
            weights: Weights::default(),
        }
    }
}
pub fn canonical_ip(value: &str) -> Result<IpAddr> {
    let ip: IpAddr = value.parse()?;
    Ok(match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    })
}
pub fn canonical_network(value: &str) -> Result<IpNet> {
    let net: IpNet = value.parse()?;
    if let IpNet::V6(v) = net
        && let Some(ip) = v.addr().to_ipv4_mapped()
    {
        ensure!(v.prefix_len() >= 96, "mapped prefix must be at least /96");
        return Ok(IpNet::new(IpAddr::V4(ip), v.prefix_len() - 96)?.trunc());
    }
    Ok(net.trunc())
}
/// A validation problem located by a JSON Pointer relative to the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    pub path: String,
    pub message: String,
}
impl FieldError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}
/// Maximum diagnostics reported for one document.
pub const MAX_FIELD_ERRORS: usize = 64;
impl Policy {
    /// Every validation problem with its JSON Pointer, without normalizing.
    /// An empty result means [`Policy::validate`] accepts the policy.
    pub fn diagnose(&self) -> Vec<FieldError> {
        let mut errors = Vec::new();
        if !(1..=3600).contains(&self.window_secs) {
            errors.push(FieldError::new("/window_secs", "window outside 1..3600"));
        }
        if !(1..=1_000_000).contains(&self.threshold) {
            errors.push(FieldError::new("/threshold", "invalid threshold"));
        }
        if !(1..=604800).contains(&self.block_ttl_secs) {
            errors.push(FieldError::new("/block_ttl_secs", "invalid block TTL"));
        }
        if self.allow.len() > MAX_BLOCKS {
            errors.push(FieldError::new("/allow", "too many allow rules"));
        }
        for (name, w) in [
            ("honeypot", self.weights.honeypot),
            ("scanner", self.weights.scanner),
            ("auth_failure", self.weights.auth_failure),
            ("invalid_request", self.weights.invalid_request),
        ] {
            if w > 1000 {
                errors.push(FieldError::new(
                    format!("/weights/{name}"),
                    "weight exceeds 1000",
                ));
            }
        }
        let mut seen = HashSet::new();
        for (i, n) in self.allow.iter().enumerate() {
            if errors.len() >= MAX_FIELD_ERRORS {
                break;
            }
            match canonical_network(n) {
                Ok(n) if !seen.insert(n) => errors.push(FieldError::new(
                    format!("/allow/{i}"),
                    "duplicate allow rule",
                )),
                Ok(_) => {}
                Err(e) => errors.push(FieldError::new(format!("/allow/{i}"), e.to_string())),
            }
        }
        errors.truncate(MAX_FIELD_ERRORS);
        errors
    }
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            (1..=3600).contains(&self.window_secs),
            "window outside 1..3600"
        );
        ensure!(
            (1..=1_000_000).contains(&self.threshold),
            "invalid threshold"
        );
        ensure!(
            (1..=604800).contains(&self.block_ttl_secs),
            "invalid block TTL"
        );
        ensure!(self.allow.len() <= MAX_BLOCKS, "too many allow rules");
        for w in [
            self.weights.honeypot,
            self.weights.scanner,
            self.weights.auth_failure,
            self.weights.invalid_request,
        ] {
            ensure!(w <= 1000, "weight exceeds 1000");
        }
        let mut seen = HashSet::new();
        for n in &mut self.allow {
            *n = canonical_network(n)?.to_string();
            ensure!(seen.insert(n.clone()), "duplicate allow rule");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub ip: String,
    pub score: u64,
    pub suspicion: Suspicion,
    pub eligible: bool,
    pub events: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub asn: Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregate {
    pub ip: String,
    pub buckets: BTreeMap<u64, (u64, u64)>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub policy: Policy,
    pub revision: u64,
    pub blocks: Vec<Block>,
    pub aggregates: Vec<Aggregate>,
    pub stats: Stats,
    #[serde(default)]
    pub rules: RuleSet,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub accepted: u64,
    pub dropped_capacity: u64,
    pub block_capacity_rejections: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    pub accepted: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnPrefix {
    pub network: String,
    pub asn: u32,
}
#[derive(Clone)]
pub struct Engine {
    policy: Policy,
    // Deliberately absent from checkpoints: restored processes reject old drafts.
    policy_epoch: String,
    policy_sequence: u64,
    revision: u64,
    blocks: BTreeMap<String, Arc<Block>>,
    aggregates: BTreeMap<String, Aggregate>,
    stats: Stats,
    asns: Arc<PrefixTrie<u32>>,
    allow_index: PrefixTrie<()>,
    block_index: PrefixTrie<Arc<Block>>,
    last_pruned: Option<u64>,
    snapshot_bytes: usize,
    rules: RuleSet,
    compiled_rules: Arc<CompiledRules>,
}
impl Engine {
    pub fn new(mut policy: Policy) -> Result<Self> {
        policy.validate()?;
        ensure!(
            snapshot_budget(&policy, std::iter::empty()) <= 4_000_000,
            "policy snapshot byte budget exceeded"
        );
        let mut allow_index = PrefixTrie::default();
        for n in &policy.allow {
            allow_index.insert(canonical_network(n)?, ());
        }
        let snapshot_bytes = snapshot_budget(&policy, std::iter::empty());
        let mut epoch = [0u8; 32];
        getrandom::getrandom(&mut epoch)
            .map_err(|e| anyhow::anyhow!("policy epoch unavailable: {e}"))?;
        Ok(Self {
            policy_epoch: epoch.iter().map(|b| format!("{b:02x}")).collect(),
            policy_sequence: 1,
            policy,
            revision: 1,
            blocks: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            stats: Stats::default(),
            asns: Arc::new(PrefixTrie::default()),
            allow_index,
            block_index: PrefixTrie::default(),
            last_pruned: None,
            snapshot_bytes,
            rules: RuleSet::default(),
            compiled_rules: Arc::new(CompiledRules::default()),
        })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn policy_revision(&self) -> String {
        format!("{}:{}", self.policy_epoch, self.policy_sequence)
    }
    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }
    /// Validate a policy exactly as [`Engine::set_policy`] would, without applying it.
    pub fn check_policy(&self, mut policy: Policy) -> Result<Policy> {
        policy.validate()?;
        ensure!(
            snapshot_budget(&policy, self.blocks.values().map(AsRef::as_ref)) <= 4_000_000,
            "snapshot byte budget exceeded"
        );
        Ok(policy)
    }
    /// Current signal score of an exact IP from bounded aggregates.
    pub fn signal_score(&mut self, ip: IpAddr, now: u64) -> u64 {
        self.prune(now);
        self.aggregates.get(&ip.to_string()).map_or(0, |a| {
            a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0))
        })
    }
    /// Active blocks (for audit digests and summaries).
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.blocks.values().map(AsRef::as_ref)
    }
    pub fn set_policy(&mut self, mut policy: Policy) -> Result<()> {
        policy.validate()?;
        let mut allow_index = PrefixTrie::default();
        for n in &policy.allow {
            allow_index.insert(canonical_network(n)?, ());
        }
        ensure!(
            snapshot_budget(&policy, self.blocks.values().map(AsRef::as_ref)) <= 4_000_000,
            "snapshot byte budget exceeded"
        );
        let sequence = self
            .policy_sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("policy revision exhausted"))?;
        self.snapshot_bytes = snapshot_budget(&policy, self.blocks.values().map(AsRef::as_ref));
        self.policy_sequence = sequence;
        self.allow_index = allow_index;
        self.policy = policy;
        self.aggregates.clear();
        self.last_pruned = None;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
    pub fn capacity(&self) -> (usize, usize) {
        (self.aggregates.len(), self.blocks.len())
    }
    fn prune(&mut self, now: u64) {
        if self.last_pruned == Some(now) {
            return;
        }
        self.last_pruned = Some(now);
        let window = self.policy.window_secs;
        self.aggregates.retain(|_, a| {
            a.buckets.retain(|t, _| *t <= now && now - *t < window);
            !a.buckets.is_empty()
        });
        self.blocks.retain(|_, b| {
            if b.expires_at <= now {
                self.snapshot_bytes = self.snapshot_bytes.saturating_sub(block_cost(b));
                if let Ok(n) = canonical_network(&b.network) {
                    self.block_index.remove(n);
                }
                false
            } else {
                true
            }
        });
    }
    fn allowed(&self, ip: IpAddr) -> bool {
        self.allow_index.longest(ip).is_some()
    }
    pub fn ingest(&mut self, batch: EventBatch, now: u64) -> Result<IngestResult> {
        ensure!(
            !batch.source_id.is_empty() && batch.source_id.len() <= 64,
            "invalid source ID"
        );
        ensure!(batch.events.len() <= MAX_BATCH, "batch exceeds 256");
        let parsed: Vec<_> = batch
            .events
            .iter()
            .map(|e| {
                ensure!(
                    e.observed_at.abs_diff(now) <= 300,
                    "timestamp outside receiver tolerance"
                );
                canonical_ip(&e.ip)
            })
            .collect::<Result<_>>()?;
        self.prune(now);
        let mut accepted = 0;
        for (e, ip) in batch.events.into_iter().zip(parsed) {
            if self.allowed(ip) || self.decision(&ip.to_string(), now)?.action == "deny" {
                continue;
            }
            let weight = match e.kind {
                EventKind::Honeypot => self.policy.weights.honeypot,
                EventKind::Scanner => self.policy.weights.scanner,
                EventKind::AuthFailure => self.policy.weights.auth_failure,
                EventKind::InvalidRequest => self.policy.weights.invalid_request,
            } as u64;
            if weight == 0 {
                continue;
            }
            let key = ip.to_string();
            if !self.aggregates.contains_key(&key) && self.aggregates.len() >= MAX_CANDIDATES {
                self.stats.dropped_capacity = self.stats.dropped_capacity.saturating_add(1);
                continue;
            }
            let a = self
                .aggregates
                .entry(key.clone())
                .or_insert_with(|| Aggregate {
                    ip: key.clone(),
                    buckets: BTreeMap::new(),
                });
            let b = a
                .buckets
                .entry(
                    now / self.policy.window_secs.div_ceil(64)
                        * self.policy.window_secs.div_ceil(64),
                )
                .or_default();
            b.0 = b.0.saturating_add(weight);
            b.1 = b.1.saturating_add(1);
            let score = a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0));
            accepted += 1;
            if score >= self.policy.threshold
                && self.policy.mode == Mode::Enforce
                && self.policy.auto_block
                && !self.blocks.contains_key(&exact(ip))
            {
                if self.blocks.len() < MAX_BLOCKS {
                    let block_result = self.add_block(
                        Block {
                            network: exact(ip),
                            expires_at: now.saturating_add(self.policy.block_ttl_secs),
                            reason: "automatic threshold".into(),
                        },
                        now,
                    );
                    if block_result.is_err() {
                        self.stats.block_capacity_rejections =
                            self.stats.block_capacity_rejections.saturating_add(1);
                    }
                } else {
                    self.stats.block_capacity_rejections =
                        self.stats.block_capacity_rejections.saturating_add(1);
                }
            }
        }
        self.stats.accepted = self.stats.accepted.saturating_add(accepted as u64);
        Ok(IngestResult { accepted })
    }
    pub fn snapshot(&mut self, now: u64) -> Snapshot {
        self.prune(now);
        Snapshot {
            version: 1,
            revision: self.revision,
            generated_at: now,
            valid_until: now.saturating_add(30),
            mode: self.policy.mode,
            allow: self.policy.allow.clone(),
            blocks: self.blocks.values().map(|b| b.as_ref().clone()).collect(),
        }
    }
    pub fn candidates(&mut self, now: u64) -> Vec<Candidate> {
        self.prune(now);
        self.aggregates
            .values()
            .map(|a| {
                let ip = canonical_ip(&a.ip).ok();
                Candidate {
                    ip: a.ip.clone(),
                    score: a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0)),
                    suspicion: Suspicion::from_score(
                        a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0)),
                        self.policy.threshold,
                        ip.is_some_and(|ip| {
                            query_rules(
                                &self.allow_index,
                                &self.block_index,
                                &self.compiled_rules,
                                &self.asns,
                                self.revision,
                                self.policy.mode,
                                ip,
                                now,
                                GeoContext::default(),
                            )
                            .action
                                == "deny"
                        }),
                    ),
                    eligible: a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0))
                        >= self.policy.threshold,
                    events: a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.1)),
                    first_seen: a.buckets.first_key_value().map_or(now, |(t, _)| *t),
                    last_seen: a.buckets.last_key_value().map_or(now, |(t, _)| *t),
                    asn: ip.and_then(|ip| self.asns.longest(ip).copied()),
                }
            })
            .collect()
    }
    pub fn add_block(&mut self, mut block: Block, now: u64) -> Result<()> {
        self.prune(now);
        block.network = canonical_network(&block.network)?.to_string();
        ensure!(block.reason.len() <= 128, "reason exceeds 128 bytes");
        ensure!(
            block.expires_at > now && block.expires_at - now <= 604800,
            "invalid block expiry"
        );
        ensure!(
            self.blocks.contains_key(&block.network) || self.blocks.len() < MAX_BLOCKS,
            "block capacity reached"
        );
        let old_cost = self.blocks.get(&block.network).map_or(0, |b| block_cost(b));
        ensure!(
            self.snapshot_bytes
                .saturating_sub(old_cost)
                .saturating_add(block_cost(&block))
                <= 4_000_000,
            "snapshot byte budget exceeded"
        );
        self.snapshot_bytes = self
            .snapshot_bytes
            .saturating_sub(old_cost)
            .saturating_add(block_cost(&block));
        let block = Arc::new(block);
        self.block_index
            .insert(canonical_network(&block.network)?, block.clone());
        self.blocks.insert(block.network.clone(), block);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
    pub fn remove_block(&mut self, network: &str) -> Result<bool> {
        let n = canonical_network(network)?.to_string();
        self.block_index.remove(canonical_network(&n)?);
        let old = self.blocks.remove(&n);
        if let Some(b) = &old {
            self.snapshot_bytes = self.snapshot_bytes.saturating_sub(block_cost(b));
        }
        let removed = old.is_some();
        if removed {
            self.revision = self.revision.saturating_add(1);
        }
        Ok(removed)
    }
    pub fn approve(&mut self, ip: &str, now: u64) -> Result<Block> {
        self.prune(now);
        let ip = canonical_ip(ip)?;
        ensure!(
            self.aggregates.contains_key(&ip.to_string()),
            "candidate not found"
        );
        ensure!(!self.allowed(ip), "candidate is allowlisted");
        ensure!(
            self.aggregates[&ip.to_string()]
                .buckets
                .values()
                .fold(0u64, |s, b| s.saturating_add(b.0))
                >= self.policy.threshold,
            "candidate below threshold"
        );
        let block = Block {
            network: exact(ip),
            expires_at: now.saturating_add(self.policy.block_ttl_secs),
            reason: "manual candidate approval".into(),
        };
        self.add_block(block.clone(), now)?;
        Ok(block)
    }
    pub fn set_asn_catalog(&mut self, prefixes: Vec<AsnPrefix>) -> Result<()> {
        ensure!(prefixes.len() <= MAX_BLOCKS, "ASN catalog exceeds capacity");
        let mut values = PrefixTrie::default();
        for p in prefixes {
            ensure!(p.asn > 0, "invalid ASN");
            let network = canonical_network(&p.network)?;
            ensure!(
                values.insert(network, p.asn).is_none(),
                "duplicate ASN prefix"
            );
        }
        self.asns = Arc::new(values);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
    pub fn state(&self) -> State {
        State {
            policy: self.policy.clone(),
            revision: self.revision,
            blocks: self.blocks.values().map(|b| b.as_ref().clone()).collect(),
            aggregates: self.aggregates.values().cloned().collect(),
            stats: self.stats.clone(),
            rules: self.rules.clone(),
        }
    }
    pub fn restore(state: State) -> Result<Self> {
        ensure!(
            state.blocks.len() <= MAX_BLOCKS && state.aggregates.len() <= MAX_CANDIDATES,
            "state exceeds capacity"
        );
        let mut engine = Self::new(state.policy)?;
        engine.revision = state.revision;
        engine.stats = state.stats;
        let revision = engine.revision;
        engine.set_rules(state.rules)?;
        engine.revision = revision;
        for mut b in state.blocks {
            b.network = canonical_network(&b.network)?.to_string();
            ensure!(b.reason.len() <= 128, "invalid reason");
            let b = Arc::new(b);
            engine
                .block_index
                .insert(canonical_network(&b.network)?, b.clone());
            ensure!(
                engine.blocks.insert(b.network.clone(), b).is_none(),
                "duplicate block"
            );
        }
        for mut a in state.aggregates {
            a.ip = canonical_ip(&a.ip)?.to_string();
            ensure!(a.buckets.len() <= 64, "aggregate exceeds window capacity");
            ensure!(
                engine.aggregates.insert(a.ip.clone(), a).is_none(),
                "duplicate aggregate"
            );
        }
        ensure!(
            snapshot_budget(&engine.policy, engine.blocks.values().map(AsRef::as_ref)) <= 4_000_000,
            "state snapshot byte budget exceeded"
        );
        engine.snapshot_bytes =
            snapshot_budget(&engine.policy, engine.blocks.values().map(AsRef::as_ref));
        Ok(engine)
    }
}
fn exact(ip: IpAddr) -> String {
    format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
}

/// Immutable bounded prefix lookup, with allow precedence and local expiration.
pub struct PrefixIndex {
    allow: PrefixTrie<()>,
    blocks: PrefixTrie<u64>,
    mode: Mode,
    valid_until: u64,
}
impl PrefixIndex {
    pub fn new(snapshot: &Snapshot, now: u64) -> Result<Self> {
        ensure!(snapshot.version == 1, "unsupported version");
        ensure!(
            snapshot.generated_at <= now.saturating_add(5)
                && snapshot.valid_until > now
                && snapshot.valid_until > snapshot.generated_at
                && snapshot.valid_until - snapshot.generated_at <= 300,
            "invalid validity"
        );
        ensure!(
            snapshot.allow.len() <= MAX_BLOCKS && snapshot.blocks.len() <= MAX_BLOCKS,
            "too many prefixes"
        );
        let mut allow = PrefixTrie::default();
        for n in &snapshot.allow {
            ensure!(
                allow.insert(canonical_network(n)?, ()).is_none(),
                "duplicate allow"
            );
        }
        let mut blocks = PrefixTrie::default();
        for b in &snapshot.blocks {
            ensure!(b.reason.len() <= 128, "invalid reason");
            ensure!(
                blocks
                    .insert(canonical_network(&b.network)?, b.expires_at)
                    .is_none(),
                "duplicate block"
            );
        }
        Ok(Self {
            allow,
            blocks,
            mode: snapshot.mode,
            valid_until: snapshot.valid_until,
        })
    }
    pub fn is_blocked(&self, ip: IpAddr, now: u64) -> bool {
        if self.mode != Mode::Enforce || now >= self.valid_until {
            return false;
        }
        self.allow.longest(ip).is_none()
            && self
                .blocks
                .longest_where(ip, |expiry| *expiry > now)
                .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn batch(ip: &str, time: u64, kind: EventKind) -> EventBatch {
        EventBatch {
            source_id: "test".into(),
            events: vec![Event {
                ip: ip.into(),
                observed_at: time,
                kind,
            }],
        }
    }
    #[test]
    fn policy_revision_is_independent_and_validated() {
        let mut e = Engine::new(Policy::default()).unwrap();
        let initial = e.policy_revision();
        e.ingest(batch("192.0.2.1", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert_eq!(e.policy_revision(), initial);
        let mut invalid = e.policy().clone();
        invalid.threshold = 0;
        assert!(e.set_policy(invalid).is_err());
        assert_eq!(e.policy_revision(), initial);
        e.set_policy(e.policy().clone()).unwrap();
        assert_ne!(e.policy_revision(), initial);
        assert_ne!(
            Engine::restore(e.state()).unwrap().policy_revision(),
            e.policy_revision()
        );
    }
    #[test]
    fn threshold_window_and_observe() {
        let mut e = Engine::new(Policy::default()).unwrap();
        e.ingest(batch("1.2.3.4", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert_eq!(e.candidates(100)[0].score, 10);
        assert!(e.snapshot(100).blocks.is_empty());
        assert!(e.candidates(160).is_empty());
    }
    #[test]
    fn enforce_allow_and_mapped() {
        let mut p = Policy {
            mode: Mode::Enforce,
            auto_block: true,
            ..Policy::default()
        };
        p.allow = vec!["10.0.0.1/8".into()];
        let mut e = Engine::new(p).unwrap();
        e.ingest(batch("::ffff:10.0.0.1", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert!(e.candidates(100).is_empty());
        e.ingest(batch("::ffff:1.2.3.4", 100, EventKind::Honeypot), 100)
            .unwrap();
        assert_eq!(e.snapshot(100).blocks[0].network, "1.2.3.4/32");
        assert_eq!(
            e.ingest(batch("1.2.3.4", 101, EventKind::Honeypot), 101)
                .unwrap()
                .accepted,
            0
        );
        assert_eq!(e.candidates(101)[0].score, 10);
        let idx = PrefixIndex::new(&e.snapshot(100), 100).unwrap();
        assert!(idx.is_blocked("::ffff:1.2.3.4".parse().unwrap(), 100));
        assert!(!idx.is_blocked("1.2.3.4".parse().unwrap(), 130));
        assert!(e.snapshot(1000).blocks.is_empty());
    }
    #[test]
    fn validation_atomic_batch() {
        let mut e = Engine::new(Policy::default()).unwrap();
        let mut b = batch("1.2.3.4", 100, EventKind::Honeypot);
        b.events.push(Event {
            ip: "bad".into(),
            observed_at: 100,
            kind: EventKind::Scanner,
        });
        assert!(e.ingest(b, 100).is_err());
        assert!(e.candidates(100).is_empty());
        assert!(
            Engine::new(Policy {
                window_secs: 0,
                ..Policy::default()
            })
            .is_err()
        );
        assert!(
            e.ingest(batch("1.2.3.4", 0, EventKind::Scanner), 500)
                .is_err()
        );
    }
    #[test]
    fn manual_prefix_allow_and_restore_asn() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            allow: vec!["192.0.2.42/32".into()],
            ..Policy::default()
        })
        .unwrap();
        e.ingest(batch("192.0.2.1", 100, EventKind::Scanner), 100)
            .unwrap();
        e.add_block(
            Block {
                network: "192.0.2.19/24".into(),
                expires_at: 200,
                reason: "test".into(),
            },
            100,
        )
        .unwrap();
        e.set_asn_catalog(vec![
            AsnPrefix {
                network: "192.0.0.0/16".into(),
                asn: 1,
            },
            AsnPrefix {
                network: "192.0.2.0/24".into(),
                asn: 2,
            },
        ])
        .unwrap();
        assert_eq!(e.candidates(100)[0].asn, Some(2));
        let idx = PrefixIndex::new(&e.snapshot(100), 100).unwrap();
        assert!(idx.is_blocked("192.0.2.1".parse().unwrap(), 100));
        assert!(!idx.is_blocked("192.0.2.42".parse().unwrap(), 100));
        let mut restored = Engine::restore(e.state()).unwrap();
        assert_eq!(restored.candidates(100)[0].score, 5);
        assert_eq!(restored.snapshot(100).blocks.len(), 1);
        assert!(restored.remove_block("192.0.2.0/24").unwrap());
    }
    #[test]
    fn capacity_and_receiver_time() {
        let mut e = Engine::new(Policy::default()).unwrap();
        for i in 0..MAX_CANDIDATES {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from((i as u32) + 1));
            e.ingest(batch(&ip.to_string(), 100, EventKind::Scanner), 100)
                .unwrap();
        }
        assert_eq!(
            e.ingest(batch("255.255.255.255", 100, EventKind::Scanner), 100)
                .unwrap()
                .accepted,
            0
        );
        assert_eq!(e.stats().dropped_capacity, 1);
        assert_eq!(
            e.ingest(batch("255.255.255.255", 100, EventKind::Scanner), 160)
                .unwrap()
                .accepted,
            1
        );
        assert_eq!(e.candidates(160)[0].first_seen, 160);
    }
    #[test]
    fn ipv6_prefix() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        e.add_block(
            Block {
                network: "2001:db8::123/32".into(),
                expires_at: 200,
                reason: "ipv6".into(),
            },
            100,
        )
        .unwrap();
        let idx = PrefixIndex::new(&e.snapshot(100), 100).unwrap();
        assert!(idx.is_blocked("2001:db8:abcd::1".parse().unwrap(), 100));
        assert!(!idx.is_blocked("2001:db9::1".parse().unwrap(), 100));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub version: u32,
    pub revision: u64,
    pub action: String,
    pub mode: Mode,
    pub reason: Option<String>,
    pub ttl_ms: u64,
}
#[derive(Clone)]
pub struct DecisionView {
    pub revision: u64,
    pub mode: Mode,
    allow: PrefixTrie<()>,
    blocks: PrefixTrie<Arc<Block>>,
    rules: Arc<CompiledRules>,
    asns: Arc<PrefixTrie<u32>>,
}
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DecisionRef<'a> {
    pub version: u32,
    pub revision: u64,
    pub action: &'static str,
    pub mode: Mode,
    pub reason: Option<&'a str>,
    pub ttl_ms: u64,
}
impl DecisionView {
    pub fn query_ip(&self, ip: IpAddr, now: u64) -> DecisionRef<'_> {
        self.query_ip_context(ip, now, GeoContext::default())
    }
    pub fn requires_geo(&self) -> bool {
        self.rules.requires_geo()
    }
    pub fn query_ip_context(&self, ip: IpAddr, now: u64, geo: GeoContext<'_>) -> DecisionRef<'_> {
        query_rules(
            &self.allow,
            &self.blocks,
            &self.rules,
            &self.asns,
            self.revision,
            self.mode,
            ip,
            now,
            geo,
        )
    }
    pub fn decision(&self, ip: IpAddr, now: u64) -> DecisionRef<'_> {
        self.query_ip(ip, now)
    }
    /// Live decision with a tracer. `query_ip_context` is exactly this with
    /// [`NoTrace`]; explain and decision evidence pass their own sink.
    pub fn evaluate<'a, T: Tracer<'a>>(
        &'a self,
        ip: IpAddr,
        now: u64,
        geo: GeoContext<'_>,
        trace: &mut T,
    ) -> DecisionRef<'a> {
        self.evaluate_as(self.mode, ip, now, geo, trace)
    }
    /// Evaluate as if the view were in `mode` (used to show what enforcement of
    /// the same published policy would decide while it is observed).
    pub fn evaluate_as<'a, T: Tracer<'a>>(
        &'a self,
        mode: Mode,
        ip: IpAddr,
        now: u64,
        geo: GeoContext<'_>,
        trace: &mut T,
    ) -> DecisionRef<'a> {
        evaluate(
            &self.allow,
            &self.blocks,
            &self.rules,
            &self.asns,
            self.revision,
            mode,
            ip,
            now,
            geo,
            trace,
        )
    }
    /// Offline ASN catalog fallback for evidence/explain display.
    pub fn catalog_asn(&self, ip: IpAddr) -> Option<u32> {
        self.asns.longest(ip).copied()
    }
    /// Sum of scores and IDs of every active matching rule, independent of the
    /// decision (the inspection score used by `POST /v1/lookup`).
    pub fn rule_score(&self, ip: IpAddr, now: u64, geo: GeoContext<'_>) -> (u64, Vec<String>) {
        let geo = GeoContext {
            country: geo.country,
            asn: geo.asn.or_else(|| self.asns.longest(ip).copied()),
        };
        let m = self.rules.matching(ip, now, geo);
        (m.score, self.rules.matching_ids(&m))
    }
    /// Rule set compiled into this view, in precedence order.
    pub fn compiled_rules(&self) -> &[Rule] {
        &self.rules.rules
    }
    /// A never-published view combining a candidate policy (mode and allowlist)
    /// and/or candidate rules with this view's blocks and ASN catalog. Inputs must
    /// already be validated (see [`Engine::check_policy`] and [`RuleSet::validate`]).
    pub fn with_candidate(&self, policy: Option<&Policy>, rules: Option<&RuleSet>) -> Result<Self> {
        let mut view = self.clone();
        if let Some(policy) = policy {
            let mut allow = PrefixTrie::default();
            for n in &policy.allow {
                allow.insert(canonical_network(n)?, ());
            }
            view.allow = allow;
            view.mode = policy.mode;
        }
        if let Some(rules) = rules {
            view.rules = Arc::new(CompiledRules::new(rules)?);
        }
        Ok(view)
    }
    pub fn allocated_bytes(&self) -> usize {
        self.allow.allocated_bytes() + self.blocks.allocated_bytes()
    }
}
impl Engine {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Assign a fresh publication revision without rebuilding or losing native indexes.
    pub fn advance_revision_past(&mut self, previous: u64) -> Result<()> {
        self.revision = self
            .revision
            .max(previous)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("decision revision exhausted"))?;
        Ok(())
    }
    pub fn decision_view(&self) -> DecisionView {
        DecisionView {
            revision: self.revision,
            mode: self.policy.mode,
            allow: self.allow_index.clone(),
            blocks: self.block_index.clone(),
            rules: self.compiled_rules.clone(),
            asns: self.asns.clone(),
        }
    }
    pub fn decision(&self, ip: &str, now: u64) -> Result<Decision> {
        self.decision_context(ip, now, GeoContext::default())
    }
    pub fn decision_context(&self, ip: &str, now: u64, geo: GeoContext<'_>) -> Result<Decision> {
        let d = query_rules(
            &self.allow_index,
            &self.block_index,
            &self.compiled_rules,
            &self.asns,
            self.revision,
            self.policy.mode,
            canonical_ip(ip)?,
            now,
            geo,
        );
        Ok(Decision {
            version: d.version,
            revision: d.revision,
            action: d.action.into(),
            mode: d.mode,
            reason: d.reason.map(str::to_owned),
            ttl_ms: d.ttl_ms,
        })
    }
}

fn block_cost(b: &Block) -> usize {
    100 + b.network.len() + b.reason.len() * 6
}
fn snapshot_budget<'a>(p: &Policy, blocks: impl Iterator<Item = &'a Block>) -> usize {
    1024 + p.allow.iter().map(|s| s.len() + 4).sum::<usize>()
        + blocks.map(block_cost).sum::<usize>()
}
#[cfg(test)]
mod bounded_tests {
    use super::*;
    #[test]
    fn long_window_has_only_64_buckets() {
        let mut e = Engine::new(Policy {
            window_secs: 3600,
            ..Policy::default()
        })
        .unwrap();
        for now in 10000..13600 {
            e.ingest(
                EventBatch {
                    source_id: "test".into(),
                    events: vec![Event {
                        ip: "203.0.113.1".into(),
                        kind: EventKind::Scanner,
                        observed_at: now,
                    }],
                },
                now,
            )
            .unwrap();
        }
        assert!(e.state().aggregates[0].buckets.len() <= 64);
        assert!(e.candidates(17200).is_empty());
    }
    #[test]
    fn remote_decision_expiry_and_restore() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        e.add_block(
            Block {
                network: "203.0.113.0/24".into(),
                expires_at: 103,
                reason: "manual".into(),
            },
            100,
        )
        .unwrap();
        let e = Engine::restore(e.state()).unwrap();
        let d = e.decision("::ffff:203.0.113.4", 100).unwrap();
        assert_eq!(d.action, "deny");
        assert_eq!(d.ttl_ms, 2000);
        assert_eq!(e.decision("203.0.113.4", 103).unwrap().action, "allow");
    }
    #[test]
    fn escaped_json_budget_is_conservative() {
        let b = Block {
            network: "203.0.113.4/32".into(),
            expires_at: 100,
            reason: "\0".repeat(128),
        };
        assert!(block_cost(&b) > 768);
    }
}

#[cfg(test)]
mod asn_index_tests {
    use super::*;
    #[test]
    fn duplicate_rejected_atomically_and_longest_ipv6_mapped_prefix() {
        let mut e = Engine::new(Policy::default()).unwrap();
        e.set_asn_catalog(vec![
            AsnPrefix {
                network: "2001:db8::/32".into(),
                asn: 1,
            },
            AsnPrefix {
                network: "2001:db8:1::/48".into(),
                asn: 2,
            },
            AsnPrefix {
                network: "::ffff:192.0.2.0/120".into(),
                asn: 3,
            },
        ])
        .unwrap();
        assert!(
            e.set_asn_catalog(vec![
                AsnPrefix {
                    network: "2001:db8::/32".into(),
                    asn: 9
                },
                AsnPrefix {
                    network: "2001:db8::123/32".into(),
                    asn: 10
                }
            ])
            .is_err()
        );
        assert!(
            e.set_asn_catalog(vec![
                AsnPrefix {
                    network: "192.0.2.0/24".into(),
                    asn: 3
                },
                AsnPrefix {
                    network: "::ffff:192.0.2.1/120".into(),
                    asn: 3
                }
            ])
            .is_err()
        );
        e.ingest(
            EventBatch {
                source_id: "test".into(),
                events: ["2001:db8:1::42", "2001:db8:2::42", "::ffff:192.0.2.42"]
                    .into_iter()
                    .map(|ip| Event {
                        ip: ip.into(),
                        kind: EventKind::Scanner,
                        observed_at: 100,
                    })
                    .collect(),
            },
            100,
        )
        .unwrap();
        let c = e.candidates(100);
        assert_eq!(
            c.iter().find(|c| c.ip == "2001:db8:1::42").unwrap().asn,
            Some(2)
        );
        assert_eq!(
            c.iter().find(|c| c.ip == "2001:db8:2::42").unwrap().asn,
            Some(1)
        );
        assert_eq!(
            c.iter().find(|c| c.ip == "192.0.2.42").unwrap().asn,
            Some(3)
        );
    }
}

#[allow(clippy::too_many_arguments)]
#[inline]
fn query_rules<'a>(
    allow: &PrefixTrie<()>,
    blocks: &'a PrefixTrie<Arc<Block>>,
    rules: &'a CompiledRules,
    catalog: &PrefixTrie<u32>,
    revision: u64,
    mode: Mode,
    ip: IpAddr,
    now: u64,
    geo: GeoContext<'_>,
) -> DecisionRef<'a> {
    evaluate(
        allow,
        blocks,
        rules,
        catalog,
        revision,
        mode,
        ip,
        now,
        geo,
        &mut NoTrace,
    )
}

/// The single network decision function. Every live transport (HTTP, HGD1, gRPC),
/// decision evidence and administrative explain call it; only the tracer differs.
#[allow(clippy::too_many_arguments)]
#[inline]
fn evaluate<'a, T: Tracer<'a>>(
    allow: &PrefixTrie<()>,
    blocks: &'a PrefixTrie<Arc<Block>>,
    rules: &'a CompiledRules,
    catalog: &PrefixTrie<u32>,
    revision: u64,
    mode: Mode,
    ip: IpAddr,
    now: u64,
    geo: GeoContext<'_>,
    trace: &mut T,
) -> DecisionRef<'a> {
    let mut d = DecisionRef {
        version: 1,
        revision,
        action: "allow",
        mode,
        reason: None,
        ttl_ms: 5000,
    };
    trace.event(TraceEvent::Mode { mode });
    if mode != Mode::Enforce {
        trace.event(TraceEvent::Outcome {
            stage: DecidingStage::Observe,
        });
        return d;
    }
    let allowed = allow.longest_prefix_where(ip, |_| true);
    trace.event(TraceEvent::Allowlist {
        prefix_len: allowed.map(|(bits, _)| bits),
    });
    if allowed.is_some() {
        trace.event(TraceEvent::Outcome {
            stage: DecidingStage::Allowlist,
        });
        return d;
    }
    if !rules.rules.is_empty() {
        let mut asn_source = if geo.asn.is_some() {
            AsnSource::Geoip
        } else {
            AsnSource::None
        };
        let geo = if geo.asn.is_none() && rules.requires_asn() {
            let asn = catalog.longest(ip).copied();
            if asn.is_some() {
                asn_source = AsnSource::Catalog;
            }
            GeoContext {
                country: geo.country,
                asn,
            }
        } else {
            geo
        };
        trace.event(TraceEvent::Geo {
            country: geo.country.and_then(rules::country_key),
            asn: geo.asn,
            asn_source,
        });
        let matched = rules.matching_traced(ip, now, geo, trace);
        if let Some(rule) = matched.winner {
            if let Some(e) = rule.expires_at {
                d.ttl_ms = d
                    .ttl_ms
                    .min(e.saturating_sub(now).saturating_sub(1).saturating_mul(1000));
            }
            match rule.action {
                RuleAction::Observe => {}
                RuleAction::Allow => {
                    trace.event(TraceEvent::Outcome {
                        stage: DecidingStage::Rule,
                    });
                    return d;
                }
                RuleAction::Deny => {
                    d.action = "deny";
                    d.reason = Some(&rule.id);
                    trace.event(TraceEvent::Outcome {
                        stage: DecidingStage::Rule,
                    });
                    return d;
                }
            }
        }
    }
    let block = blocks.longest_where(ip, |b| {
        let active = b.expires_at > now;
        if !active {
            trace.event(TraceEvent::BlockExpired { block: b.as_ref() });
        }
        active
    });
    trace.event(TraceEvent::Block {
        block: block.map(AsRef::as_ref),
    });
    if let Some(block) = block {
        d.action = "deny";
        d.reason = Some(&block.reason);
        d.ttl_ms = d.ttl_ms.min(
            block
                .expires_at
                .saturating_sub(now)
                .saturating_sub(1)
                .saturating_mul(1000),
        );
        trace.event(TraceEvent::Outcome {
            stage: DecidingStage::Block,
        });
    } else {
        trace.event(TraceEvent::Outcome {
            stage: DecidingStage::Default,
        });
    }
    d
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub ip: String,
    pub asn: Option<u32>,
    pub score: u64,
    pub signal_score: u64,
    pub static_rule_score: u64,
    pub suspicion: Suspicion,
    pub matched_rules: Vec<String>,
    pub decision: Decision,
}
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInspection {
    pub network: String,
    pub score: u64,
    pub signal_score: u64,
    pub static_rule_score: u64,
    pub matched_rules: Vec<String>,
    pub events: u64,
    pub unique_ips: usize,
    pub max_ip_score: u64,
    pub suspicion: Suspicion,
}
impl Engine {
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
    pub fn set_rules(&mut self, mut rules: RuleSet) -> Result<()> {
        rules.validate()?;
        let compiled = CompiledRules::new(&rules)?;
        self.rules = rules;
        self.compiled_rules = Arc::new(compiled);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
    pub fn inspect_ip(&mut self, ip: &str, now: u64, geo: GeoContext<'_>) -> Result<Inspection> {
        self.prune(now);
        let ip = canonical_ip(ip)?;
        let key = ip.to_string();
        let signal_score = self.aggregates.get(&key).map_or(0, |a| {
            a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0))
        });
        let geo = GeoContext {
            country: geo.country,
            asn: geo.asn.or_else(|| self.asns.longest(ip).copied()),
        };
        let matches = self.compiled_rules.matching(ip, now, geo);
        let score = signal_score.saturating_add(matches.score);
        let d = query_rules(
            &self.allow_index,
            &self.block_index,
            &self.compiled_rules,
            &self.asns,
            self.revision,
            self.policy.mode,
            ip,
            now,
            geo,
        );
        Ok(Inspection {
            ip: key,
            asn: geo.asn,
            score,
            signal_score,
            static_rule_score: matches.score,
            suspicion: Suspicion::from_score(score, self.policy.threshold, d.action == "deny"),
            matched_rules: self.compiled_rules.matching_ids(&matches),
            decision: Decision {
                version: d.version,
                revision: d.revision,
                action: d.action.into(),
                mode: d.mode,
                reason: d.reason.map(str::to_owned),
                ttl_ms: d.ttl_ms,
            },
        })
    }
    pub fn inspect_network(&mut self, network: &str, now: u64) -> Result<NetworkInspection> {
        self.prune(now);
        let network = canonical_network(network)?;
        let mut result = NetworkInspection {
            network: network.to_string(),
            score: 0,
            signal_score: 0,
            static_rule_score: 0,
            matched_rules: vec![],
            events: 0,
            unique_ips: 0,
            max_ip_score: 0,
            suspicion: Suspicion::Normal,
        };
        for a in self.aggregates.values() {
            if canonical_ip(&a.ip).is_ok_and(|ip| network.contains(&ip)) {
                let score = a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.0));
                result.score = result.score.saturating_add(score);
                result.events = result
                    .events
                    .saturating_add(a.buckets.values().fold(0u64, |s, b| s.saturating_add(b.1)));
                result.unique_ips += 1;
                result.max_ip_score = result.max_ip_score.max(score);
            }
        }
        result.signal_score = result.score;
        for r in &self.compiled_rules.rules {
            if !r.countries.is_empty()
                || !r.asns.is_empty()
                || r.expires_at.is_some_and(|e| e <= now)
            {
                continue;
            }
            if let Some(n) = &r.network
                && let Ok(n) = canonical_network(n)
                && n.prefix_len() <= network.prefix_len()
                && n.contains(&network.addr())
            {
                result.static_rule_score = result.static_rule_score.saturating_add(r.score as u64);
                result.matched_rules.push(r.id.clone());
            }
        }
        result.score = result.signal_score.saturating_add(result.static_rule_score);
        result.suspicion = Suspicion::from_score(result.score, self.policy.threshold, false);
        Ok(result)
    }
}

#[cfg(test)]
mod publication_revision_tests {
    use super::*;
    #[test]
    fn rebase_preserves_asn_rule_and_refuses_overflow() {
        let mut engine = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        engine
            .set_asn_catalog(vec![AsnPrefix {
                network: "192.0.2.0/24".into(),
                asn: 64512,
            }])
            .unwrap();
        engine
            .set_rules(RuleSet {
                version: 1,
                rules: vec![Rule {
                    id: "asn-deny".into(),
                    priority: 0,
                    network: None,
                    countries: vec![],
                    asns: vec![64512],
                    action: RuleAction::Deny,
                    score: 0,
                    expires_at: None,
                    description: String::new(),
                }],
            })
            .unwrap();
        engine.advance_revision_past(100).unwrap();
        assert_eq!(engine.revision(), 101);
        assert_eq!(engine.decision("192.0.2.1", 1).unwrap().action, "deny");
        engine.advance_revision_past(1).unwrap();
        assert_eq!(engine.revision(), 102);
        assert!(engine.advance_revision_past(u64::MAX).is_err());
        assert_eq!(engine.revision(), 102);
        assert_eq!(engine.decision("192.0.2.1", 1).unwrap().action, "deny");
    }
}

#[cfg(test)]
mod explain_support_tests {
    use super::*;
    use trace::{Evidence, reason_code};
    #[test]
    fn diagnostics_locate_every_problem_and_agree_with_validation() {
        let policy = Policy {
            window_secs: 0,
            allow: vec!["192.0.2.0/24".into(), "bad".into(), "192.0.2.9/24".into()],
            weights: Weights {
                scanner: 1001,
                ..Weights::default()
            },
            ..Policy::default()
        };
        let paths: Vec<_> = policy.diagnose().into_iter().map(|e| e.path).collect();
        assert_eq!(
            paths,
            ["/window_secs", "/weights/scanner", "/allow/1", "/allow/2"]
        );
        assert!(policy.clone().validate().is_err());
        assert!(Policy::default().diagnose().is_empty());
        let ok = RuleSet {
            version: 1,
            rules: vec![Rule {
                id: "a".into(),
                priority: 0,
                network: Some("192.0.2.1/24".into()),
                countries: vec!["kr".into()],
                asns: vec![1],
                action: RuleAction::Deny,
                score: 0,
                expires_at: None,
                description: String::new(),
            }],
        };
        assert!(ok.diagnose().is_empty());
        ok.clone().validate().unwrap();
        let mut bad = ok.clone();
        bad.rules.push(bad.rules[0].clone());
        bad.rules[1].countries = vec!["KR".into(), "kr".into(), "K1".into()];
        bad.rules[1].asns = vec![0];
        bad.rules[1].network = Some("x".into());
        let errors = bad.diagnose();
        let paths: Vec<_> = errors.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/rules/1/id",
                "/rules/1/network",
                "/rules/1/countries/1",
                "/rules/1/countries/2",
                "/rules/1/asns/0"
            ]
        );
        assert!(bad.validate().is_err());
    }
    #[test]
    fn candidate_view_is_isolated_and_reason_codes_are_stable() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        e.add_block(
            Block {
                network: "203.0.113.0/24".into(),
                expires_at: 1000,
                reason: trace::AUTOMATIC_BLOCK_REASON.into(),
            },
            100,
        )
        .unwrap();
        let view = e.decision_view();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let candidate = e
            .check_policy(Policy {
                mode: Mode::Enforce,
                allow: vec!["203.0.113.0/28".into()],
                ..Policy::default()
            })
            .unwrap();
        let cv = view.with_candidate(Some(&candidate), None).unwrap();
        assert_eq!(cv.query_ip(ip, 100).action, "allow");
        assert_eq!(view.query_ip(ip, 100).action, "deny");
        assert_eq!(e.decision(&ip.to_string(), 100).unwrap().action, "deny");
        let mut ev = Evidence::default();
        view.evaluate(ip, 100, GeoContext::default(), &mut ev);
        assert_eq!(
            reason_code(ev.stage.unwrap(), ev.winner, ev.block),
            "sumunjang.deny.block_automatic"
        );
        let mut ev = Evidence::default();
        cv.evaluate(ip, 100, GeoContext::default(), &mut ev);
        assert!(ev.allowlisted);
        assert_eq!(
            reason_code(ev.stage.unwrap(), ev.winner, ev.block),
            "sumunjang.allow.allowlist"
        );
        for code in [
            reason_code(trace::DecidingStage::Observe, None, None),
            reason_code(trace::DecidingStage::Default, None, None),
        ] {
            assert!(reasons::DECISION_CODES.contains(&code));
        }
    }
}
