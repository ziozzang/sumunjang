use crate::{
    canonical_network,
    prefix::PrefixTrie,
    trace::{NoTrace, TraceEvent, Tracer},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

pub const MAX_RULES: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Observe,
    Allow,
    Deny,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default)]
    pub asns: Vec<u32>,
    pub action: RuleAction,
    #[serde(default)]
    pub score: u32,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub description: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub version: u32,
    pub rules: Vec<Rule>,
}
impl Default for RuleSet {
    fn default() -> Self {
        Self {
            version: 1,
            rules: vec![],
        }
    }
}
impl RuleSet {
    /// Every validation problem with its JSON Pointer, without normalizing.
    /// An empty result means [`RuleSet::validate`] accepts the rule set.
    pub fn diagnose(&self) -> Vec<crate::FieldError> {
        use crate::FieldError as E;
        let mut errors = Vec::new();
        if self.version != 1 {
            errors.push(E::new("/version", "unsupported rules version"));
        }
        if self.rules.len() > MAX_RULES {
            errors.push(E::new("/rules", "rules capacity exceeded"));
        }
        let mut ids = HashSet::new();
        for (i, r) in self.rules.iter().enumerate() {
            if errors.len() >= crate::MAX_FIELD_ERRORS {
                break;
            }
            let at = |field: &str| format!("/rules/{i}/{field}");
            if r.id.is_empty()
                || r.id.len() > 64
                || !r
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                errors.push(E::new(at("id"), "invalid rule ID"));
            } else if !ids.insert(r.id.as_str()) {
                errors.push(E::new(at("id"), "duplicate rule ID"));
            }
            if r.description.len() > 256 {
                errors.push(E::new(at("description"), "rule description exceeds 256 bytes"));
            }
            if r.score > 1_000_000 {
                errors.push(E::new(at("score"), "rule score exceeds 1000000"));
            }
            if r.countries.len() > 256 {
                errors.push(E::new(at("countries"), "rule matcher capacity exceeded"));
            }
            if r.asns.len() > 256 {
                errors.push(E::new(at("asns"), "rule matcher capacity exceeded"));
            }
            if r.network.is_none() && r.countries.is_empty() && r.asns.is_empty() {
                errors.push(E::new(format!("/rules/{i}"), "rule needs a condition"));
            }
            if let Some(n) = &r.network
                && let Err(e) = canonical_network(n)
            {
                errors.push(E::new(at("network"), e.to_string()));
            }
            let mut countries = HashSet::new();
            for (j, c) in r.countries.iter().enumerate().take(256) {
                if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_alphabetic()) {
                    errors.push(E::new(
                        format!("/rules/{i}/countries/{j}"),
                        "country must be two ASCII letters",
                    ));
                } else if !countries.insert(c.to_ascii_uppercase()) {
                    errors.push(E::new(
                        format!("/rules/{i}/countries/{j}"),
                        "duplicate country",
                    ));
                }
            }
            let mut asns = HashSet::new();
            for (j, a) in r.asns.iter().enumerate().take(256) {
                if *a == 0 || !asns.insert(*a) {
                    errors.push(E::new(
                        format!("/rules/{i}/asns/{j}"),
                        "invalid or duplicate ASN",
                    ));
                }
            }
        }
        errors.truncate(crate::MAX_FIELD_ERRORS);
        errors
    }
    pub fn validate(&mut self) -> Result<()> {
        ensure!(self.version == 1, "unsupported rules version");
        ensure!(self.rules.len() <= MAX_RULES, "rules capacity exceeded");
        let mut ids = HashSet::new();
        for r in &mut self.rules {
            ensure!(
                !r.id.is_empty()
                    && r.id.len() <= 64
                    && r.id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid rule ID"
            );
            ensure!(ids.insert(r.id.clone()), "duplicate rule ID");
            ensure!(
                r.description.len() <= 256,
                "rule description exceeds 256 bytes"
            );
            ensure!(r.score <= 1_000_000, "rule score exceeds 1000000");
            ensure!(
                r.countries.len() <= 256 && r.asns.len() <= 256,
                "rule matcher capacity exceeded"
            );
            ensure!(
                r.network.is_some() || !r.countries.is_empty() || !r.asns.is_empty(),
                "rule needs a condition"
            );
            if let Some(n) = &mut r.network {
                *n = canonical_network(n)?.to_string();
            }
            let mut countries = HashSet::new();
            for c in &mut r.countries {
                ensure!(
                    c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()),
                    "country must be two ASCII letters"
                );
                c.make_ascii_uppercase();
                ensure!(countries.insert(c.clone()), "duplicate country");
            }
            let mut asns = HashSet::new();
            for a in &r.asns {
                ensure!(*a > 0 && asns.insert(*a), "invalid or duplicate ASN");
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Default)]
pub struct GeoContext<'a> {
    pub country: Option<&'a str>,
    pub asn: Option<u32>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Suspicion {
    Normal,
    Watch,
    Suspicious,
    High,
    Blocked,
}
impl Suspicion {
    pub fn from_score(score: u64, threshold: u64, blocked: bool) -> Self {
        if blocked {
            Self::Blocked
        } else if score == 0 {
            Self::Normal
        } else if score < threshold {
            Self::Watch
        } else if score < threshold.saturating_mul(3) {
            Self::Suspicious
        } else {
            Self::High
        }
    }
}
type Bits = [u64; 4];
fn bit_set(bits: &mut Bits, i: usize) {
    bits[i / 64] |= 1u64 << (i % 64);
}
pub(crate) fn country_key(s: &str) -> Option<[u8; 2]> {
    let b = s.as_bytes();
    if b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic) {
        Some([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
    } else {
        None
    }
}
#[derive(Clone, Default)]
pub(crate) struct CompiledRules {
    pub rules: Vec<Rule>,
    network: PrefixTrie<Bits>,
    countries: HashMap<[u8; 2], Bits>,
    asns: HashMap<u32, Bits>,
    requires_geo: bool,
    has_network: Bits,
    has_country: Bits,
    has_asn: Bits,
}
pub(crate) struct RuleMatches<'a> {
    pub winner: Option<&'a Rule>,
    pub score: u64,
    pub bits: Bits,
}
impl CompiledRules {
    pub fn new(rules: &RuleSet) -> Result<Self> {
        let mut result = Self {
            rules: rules.rules.clone(),
            ..Self::default()
        };
        result
            .rules
            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
        for (i, r) in result.rules.iter().enumerate() {
            result.requires_geo |= !r.countries.is_empty() || !r.asns.is_empty();
            if let Some(n) = &r.network {
                bit_set(&mut result.has_network, i);
                let n = canonical_network(n)?;
                let mut bits = result.network.remove(n).unwrap_or_default();
                bit_set(&mut bits, i);
                result.network.insert(n, bits);
            }
            if !r.countries.is_empty() {
                bit_set(&mut result.has_country, i);
                for c in &r.countries {
                    if let Some(c) = country_key(c) {
                        bit_set(result.countries.entry(c).or_default(), i);
                    }
                }
            }
            if !r.asns.is_empty() {
                bit_set(&mut result.has_asn, i);
                for a in &r.asns {
                    bit_set(result.asns.entry(*a).or_default(), i);
                }
            }
        }
        Ok(result)
    }
    pub fn requires_asn(&self) -> bool {
        !self.asns.is_empty()
    }
    pub fn requires_geo(&self) -> bool {
        self.requires_geo
    }
    pub fn matching(&self, ip: IpAddr, now: u64, geo: GeoContext<'_>) -> RuleMatches<'_> {
        self.matching_traced(ip, now, geo, &mut NoTrace)
    }
    /// The one rule matcher; `trace` only observes matched and expired rules.
    #[inline]
    pub fn matching_traced<'a, T: Tracer<'a>>(
        &'a self,
        ip: IpAddr,
        now: u64,
        geo: GeoContext<'_>,
        trace: &mut T,
    ) -> RuleMatches<'a> {
        let mut network = Bits::default();
        self.network.visit_matches(ip, |bits| {
            for (n, b) in network.iter_mut().zip(bits) {
                *n |= *b;
            }
        });
        let country = geo
            .country
            .and_then(country_key)
            .and_then(|c| self.countries.get(&c))
            .copied()
            .unwrap_or_default();
        let asn = geo
            .asn
            .and_then(|a| self.asns.get(&a))
            .copied()
            .unwrap_or_default();
        let mut candidates = Bits::default();
        for i in 0..4 {
            candidates[i] = (network[i] | country[i] | asn[i])
                & (!self.has_network[i] | network[i])
                & (!self.has_country[i] | country[i])
                & (!self.has_asn[i] | asn[i]);
        }
        let mut result = RuleMatches {
            winner: None,
            score: 0,
            bits: Bits::default(),
        };
        for (word, bits) in candidates.iter().enumerate() {
            let mut bits = *bits;
            while bits != 0 {
                let i = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let r = &self.rules[i];
                if r.expires_at.is_some_and(|e| e <= now) {
                    trace.event(TraceEvent::RuleExpired { rule: r });
                    continue;
                }
                trace.event(TraceEvent::RuleMatched {
                    rule: r,
                    winner: result.winner.is_none(),
                });
                if result.winner.is_none() {
                    result.winner = Some(r);
                }
                result.score = result.score.saturating_add(r.score as u64);
                bit_set(&mut result.bits, i);
            }
        }
        result
    }
    pub fn matching_ids(&self, m: &RuleMatches<'_>) -> Vec<String> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(i, _)| m.bits[i / 64] & (1u64 << (i % 64)) != 0)
            .map(|(_, r)| r.id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Block, Engine, Event, EventBatch, EventKind, Mode, Policy};
    fn rule(id: &str, action: RuleAction, priority: i32) -> Rule {
        Rule {
            id: id.into(),
            priority,
            network: Some("192.0.2.0/24".into()),
            countries: vec![],
            asns: vec![],
            action,
            score: 5,
            expires_at: None,
            description: String::new(),
        }
    }
    #[test]
    fn priority_tie_allow_override_and_policy_snapshot_immutability() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            allow: vec!["192.0.2.42/32".into()],
            ..Policy::default()
        })
        .unwrap();
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![
                rule("z-deny", RuleAction::Deny, 1),
                rule("a-allow", RuleAction::Allow, 1),
            ],
        })
        .unwrap();
        let old = e.decision_view();
        assert_eq!(
            old.query_ip("192.0.2.1".parse().unwrap(), 100).action,
            "allow"
        );
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![
                rule("z-deny", RuleAction::Deny, 2),
                rule("a-allow", RuleAction::Allow, 1),
            ],
        })
        .unwrap();
        let view = e.decision_view();
        assert_eq!(
            view.query_ip("192.0.2.1".parse().unwrap(), 100).action,
            "deny"
        );
        assert_eq!(
            view.query_ip("192.0.2.42".parse().unwrap(), 100).action,
            "allow"
        );
        assert_eq!(
            old.query_ip("192.0.2.1".parse().unwrap(), 100).action,
            "allow"
        );
        let restored = Engine::restore(e.state()).unwrap();
        assert_eq!(restored.revision(), e.revision());
        assert_eq!(restored.decision("192.0.2.1", 100).unwrap().action, "deny");
    }
    #[test]
    fn geo_and_categories_unknown_expiry_observe_score() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        let mut r = rule("geo", RuleAction::Deny, 10);
        r.countries = vec!["kr".into()];
        r.asns = vec![64500];
        r.expires_at = Some(103);
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![r, rule("observe", RuleAction::Observe, 0)],
        })
        .unwrap();
        let view = e.decision_view();
        let ip = "192.0.2.1".parse().unwrap();
        assert!(view.requires_geo());
        assert_eq!(view.query_ip(ip, 100).action, "allow");
        assert_eq!(
            view.query_ip_context(
                ip,
                100,
                GeoContext {
                    country: Some("KR"),
                    asn: None
                }
            )
            .action,
            "allow"
        );
        let geo = GeoContext {
            country: Some("kr"),
            asn: Some(64500),
        };
        assert_eq!(view.query_ip_context(ip, 100, geo).action, "deny");
        assert_eq!(view.query_ip_context(ip, 103, geo).action, "allow");
        let inspect = e.inspect_ip("192.0.2.1", 100, geo).unwrap();
        assert_eq!(inspect.static_rule_score, 10);
        assert_eq!(inspect.suspicion, Suspicion::Blocked);
        assert_eq!(inspect.matched_rules, vec!["geo", "observe"]);
        let inspect = e.inspect_ip("192.0.2.1", 103, geo).unwrap();
        assert_eq!(inspect.static_rule_score, 5);
        assert_eq!(inspect.suspicion, Suspicion::Watch);
    }
    #[test]
    fn observe_mode_and_cidr_aggregation_window_and_no_auto_subnet_ban() {
        let mut e = Engine::new(Policy::default()).unwrap();
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![rule("deny", RuleAction::Deny, 0)],
        })
        .unwrap();
        assert_eq!(e.decision("192.0.2.1", 100).unwrap().action, "allow");
        e.ingest(
            EventBatch {
                source_id: "test".into(),
                events: ["192.0.2.1", "192.0.2.2", "198.51.100.1"]
                    .into_iter()
                    .map(|ip| Event {
                        ip: ip.into(),
                        observed_at: 100,
                        kind: EventKind::Scanner,
                    })
                    .collect(),
            },
            100,
        )
        .unwrap();
        let n = e.inspect_network("192.0.2.9/24", 100).unwrap();
        assert_eq!(n.network, "192.0.2.0/24");
        assert_eq!(
            (n.score, n.events, n.unique_ips, n.max_ip_score),
            (15, 2, 2, 5)
        );
        assert_eq!(n.suspicion, Suspicion::Suspicious);
        assert!(e.snapshot(100).blocks.is_empty());
        assert_eq!(
            e.inspect_network("192.0.2.0/24", 160).unwrap().signal_score,
            0
        );
    }
    #[test]
    fn reject_duplicate_and_unconditioned_rules_atomically() {
        let mut e = Engine::new(Policy::default()).unwrap();
        let mut r = rule("test", RuleAction::Observe, 0);
        r.network = None;
        assert!(
            e.set_rules(RuleSet {
                version: 1,
                rules: vec![r]
            })
            .is_err()
        );
        let r = rule("test", RuleAction::Observe, 0);
        assert!(
            e.set_rules(RuleSet {
                version: 1,
                rules: vec![r.clone(), r]
            })
            .is_err()
        );
        assert!(e.rules().rules.is_empty());
        let mut r = rule("bad-country", RuleAction::Observe, 0);
        r.countries = vec!["K0".into()];
        assert!(
            e.set_rules(RuleSet {
                version: 1,
                rules: vec![r]
            })
            .is_err()
        );
    }
    #[test]
    fn all_matching_prefixes_and_allow_rule_override_existing_block() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        e.add_block(
            Block {
                network: "192.0.2.0/24".into(),
                expires_at: 200,
                reason: "manual".into(),
            },
            100,
        )
        .unwrap();
        let mut narrow = rule("narrow", RuleAction::Allow, 10);
        narrow.network = Some("192.0.2.42/32".into());
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![rule("broad", RuleAction::Observe, 0), narrow],
        })
        .unwrap();
        let i = e
            .inspect_ip("192.0.2.42", 100, GeoContext::default())
            .unwrap();
        assert_eq!(i.decision.action, "allow");
        assert_eq!(i.static_rule_score, 10);
        assert_eq!(i.matched_rules, vec!["narrow", "broad"]);
        assert_eq!(e.decision("192.0.2.43", 100).unwrap().action, "deny");
    }
}
#[cfg(test)]
mod geo_dispatch_tests {
    use super::*;
    use crate::{Engine, Mode, Policy};
    fn rule(id: &str, action: RuleAction) -> Rule {
        Rule {
            id: id.into(),
            priority: 1,
            network: None,
            countries: vec![],
            asns: vec![],
            action,
            score: 7,
            expires_at: None,
            description: String::new(),
        }
    }
    #[test]
    fn country_and_asn_only_index_and_expiring_observe_winner() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        let mut country = rule("country", RuleAction::Deny);
        country.countries = vec!["KR".into()];
        country.asns = vec![64500];
        let mut asn = rule("asn", RuleAction::Deny);
        asn.asns = vec![64501];
        let mut observe = rule("observe", RuleAction::Observe);
        observe.network = Some("0.0.0.0/0".into());
        observe.priority = 10;
        observe.expires_at = Some(103);
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![country, asn, observe],
        })
        .unwrap();
        let view = e.decision_view();
        let ip = "203.0.113.42".parse().unwrap();
        let kr = GeoContext {
            country: Some("kr"),
            asn: Some(64500),
        };
        assert_eq!(view.query_ip_context(ip, 100, kr).action, "allow");
        assert_eq!(view.query_ip_context(ip, 100, kr).ttl_ms, 2000);
        assert_eq!(view.query_ip_context(ip, 103, kr).action, "deny");
        assert_eq!(
            view.query_ip_context(
                ip,
                103,
                GeoContext {
                    country: Some("KR"),
                    asn: None
                }
            )
            .action,
            "allow"
        );
        assert_eq!(
            view.query_ip_context(
                ip,
                103,
                GeoContext {
                    country: None,
                    asn: Some(64501)
                }
            )
            .action,
            "deny"
        );
        assert_eq!(view.query_ip(ip, 103).action, "allow");
    }
}
#[cfg(test)]
mod cidr_score_tests {
    use super::*;
    use crate::{Engine, Policy};
    #[test]
    fn static_cidr_baseline_excludes_geo_and_partial_prefixes() {
        let mut e = Engine::new(Policy::default()).unwrap();
        let make = |id: &str, n: &str, countries: Vec<String>| Rule {
            id: id.into(),
            priority: 0,
            network: Some(n.into()),
            countries,
            asns: vec![],
            action: RuleAction::Observe,
            score: 7,
            expires_at: None,
            description: String::new(),
        };
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![
                make("covers", "192.0.0.0/16", vec![]),
                make("partial", "192.0.2.42/32", vec![]),
                make("geo", "192.0.2.0/24", vec!["KR".into()]),
            ],
        })
        .unwrap();
        let n = e.inspect_network("192.0.2.0/24", 100).unwrap();
        assert_eq!(n.signal_score, 0);
        assert_eq!(n.static_rule_score, 7);
        assert_eq!(n.matched_rules, vec!["covers"]);
        assert_eq!(n.score, 7);
    }
}
#[cfg(test)]
mod catalog_rules_tests {
    use super::*;
    use crate::{AsnPrefix, Engine, Mode, Policy};
    #[test]
    fn offline_asn_fallback_geo_priority_catalog_reload_and_frozen_view() {
        let mut e = Engine::new(Policy {
            mode: Mode::Enforce,
            ..Policy::default()
        })
        .unwrap();
        let rule = Rule {
            id: "asn-country".into(),
            priority: 0,
            network: None,
            countries: vec!["KR".into()],
            asns: vec![64500],
            action: RuleAction::Deny,
            score: 11,
            expires_at: None,
            description: String::new(),
        };
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![rule],
        })
        .unwrap();
        let ip = "192.0.2.42".parse().unwrap();
        let geo = GeoContext {
            country: Some("KR"),
            asn: None,
        };
        let before = e.decision_view();
        let revision = e.revision();
        e.set_asn_catalog(vec![AsnPrefix {
            network: "192.0.2.0/24".into(),
            asn: 64500,
        }])
        .unwrap();
        assert!(e.revision() > revision);
        let view = e.decision_view();
        assert_eq!(view.query_ip_context(ip, 100, geo).action, "deny");
        assert_eq!(before.query_ip_context(ip, 100, geo).action, "allow");
        assert_eq!(
            view.query_ip_context(
                ip,
                100,
                GeoContext {
                    country: Some("KR"),
                    asn: Some(64501)
                }
            )
            .action,
            "allow"
        );
        assert_eq!(view.query_ip(ip, 100).action, "allow");
        let inspected = e.inspect_ip("192.0.2.42", 100, geo).unwrap();
        assert_eq!(inspected.asn, Some(64500));
        assert_eq!(inspected.static_rule_score, 11);
        assert_eq!(inspected.decision.action, "deny");
        let inspected = e
            .inspect_ip(
                "192.0.2.42",
                100,
                GeoContext {
                    country: Some("KR"),
                    asn: Some(64501),
                },
            )
            .unwrap();
        assert_eq!(inspected.asn, Some(64501));
        assert_eq!(inspected.static_rule_score, 0);
        let mut restored = Engine::restore(e.state()).unwrap();
        assert_eq!(
            restored
                .decision_context("192.0.2.42", 100, geo)
                .unwrap()
                .action,
            "allow"
        );
        restored
            .set_asn_catalog(vec![AsnPrefix {
                network: "192.0.2.0/24".into(),
                asn: 64500,
            }])
            .unwrap();
        assert_eq!(
            restored
                .decision_context("192.0.2.42", 100, geo)
                .unwrap()
                .action,
            "deny"
        );
    }
}
