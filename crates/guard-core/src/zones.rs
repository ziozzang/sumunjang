//! Named network zones (ADR 0021/0022 `NetworkZone`), owned by Sumunjang.
//!
//! A zone is a named set of IPv4/IPv6 prefixes. Zones do not change admission
//! decisions; they label addresses for decision evidence, explain and the zone
//! snapshot that Pumgye imports (Pumgye `docs/MODEL_V2.md`, "Sumunjang zone
//! contract"): `{"revision": N, "zones": {"<name>": {"prefixes": [CIDR, …]}}}`,
//! names `[A-Za-z0-9_.:-]{1,128}`, canonical prefixes, ≤ 64 zones and ≤ 65,536
//! prefixes. Membership compiles into one radix tree of 64-bit zone masks, so a
//! lookup visits at most one path and never allocates.
use crate::{FieldError, canonical_network, prefix::PrefixTrie};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

/// Contract bound shared with Pumgye (one 64-bit `ZoneMask`).
pub const MAX_ZONES: usize = 64;
/// Contract bound on prefixes over all zones.
pub const MAX_PREFIXES: usize = 65_536;

pub fn valid_zone_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn text(v: &Option<String>, max: usize) -> bool {
    v.as_ref()
        .is_none_or(|v| v.len() <= max && !v.chars().any(char::is_control))
}

/// One zone as stored and administered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Owning team or contact (free text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub prefixes: Vec<String>,
    /// Server-stamped provenance (ignored on input).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}
impl Zone {
    /// Every problem with its JSON Pointer (relative to the zone).
    pub fn diagnose(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if !valid_zone_name(&self.id) {
            e.push(FieldError::new(
                "/id",
                "zone id must match [A-Za-z0-9_.:-]{1,128}",
            ));
        }
        if !text(&self.display_name, 128) {
            e.push(FieldError::new(
                "/display_name",
                "at most 128 bytes without control characters",
            ));
        }
        if !text(&self.description, 512) {
            e.push(FieldError::new(
                "/description",
                "at most 512 bytes without control characters",
            ));
        }
        if !text(&self.owner, 128) {
            e.push(FieldError::new(
                "/owner",
                "at most 128 bytes without control characters",
            ));
        }
        if self.prefixes.is_empty() {
            e.push(FieldError::new("/prefixes", "zone needs prefixes"));
        }
        if self.prefixes.len() > MAX_PREFIXES {
            e.push(FieldError::new("/prefixes", "prefix capacity exceeded"));
        }
        let mut seen = BTreeSet::new();
        for (i, p) in self.prefixes.iter().enumerate().take(MAX_PREFIXES) {
            if e.len() >= crate::MAX_FIELD_ERRORS {
                break;
            }
            match canonical_network(p) {
                Ok(n) if !seen.insert(n) => e.push(FieldError::new(
                    format!("/prefixes/{i}"),
                    "duplicate network",
                )),
                Ok(_) => {}
                Err(err) => e.push(FieldError::new(format!("/prefixes/{i}"), err.to_string())),
            }
        }
        e.truncate(crate::MAX_FIELD_ERRORS);
        e
    }
    /// Validate and canonicalize prefixes (sorted, canonical CIDR strings).
    pub fn normalize(&mut self) -> Result<()> {
        if let Some(first) = self.diagnose().into_iter().next() {
            anyhow::bail!("{}: {}", first.path, first.message);
        }
        let mut set = BTreeSet::new();
        for p in &self.prefixes {
            set.insert(canonical_network(p)?);
        }
        self.prefixes = set.into_iter().map(|n| n.to_string()).collect();
        Ok(())
    }
}

/// The administered zone set (persisted in the checkpoint).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ZoneSet {
    /// Monotonic zone revision (contract `revision`), persisted.
    pub revision: u64,
    pub zones: BTreeMap<String, Zone>,
}
impl ZoneSet {
    pub fn validate(&mut self) -> Result<()> {
        ensure!(self.zones.len() <= MAX_ZONES, "zone capacity exceeded (64)");
        let mut total = 0usize;
        for (id, z) in &mut self.zones {
            ensure!(*id == z.id, "zone key must equal its id");
            z.normalize()?;
            total += z.prefixes.len();
        }
        ensure!(total <= MAX_PREFIXES, "prefix capacity exceeded (65536)");
        Ok(())
    }
    /// The Pumgye contract snapshot: exactly `{revision, zones: {name: {prefixes}}}`.
    pub fn snapshot(&self) -> serde_json::Value {
        let zones: serde_json::Map<String, serde_json::Value> = self
            .zones
            .iter()
            .map(|(k, z)| (k.clone(), serde_json::json!({"prefixes": z.prefixes})))
            .collect();
        serde_json::json!({"revision": self.revision, "zones": zones})
    }
}

/// Compiled zone membership: one radix tree of zone bitmasks.
#[derive(Clone, Default)]
pub struct CompiledZones {
    pub revision: u64,
    trie: PrefixTrie<u64>,
    names: Vec<String>,
}
impl CompiledZones {
    pub fn new(set: &ZoneSet) -> Result<Self> {
        ensure!(set.zones.len() <= MAX_ZONES, "zone capacity exceeded (64)");
        let mut trie = PrefixTrie::<u64>::default();
        let mut names = Vec::with_capacity(set.zones.len());
        for (i, (id, z)) in set.zones.iter().enumerate() {
            names.push(id.clone());
            for p in &z.prefixes {
                let n = canonical_network(p)?;
                let previous = trie.remove(n).unwrap_or(0);
                trie.insert(n, previous | (1u64 << i));
            }
        }
        Ok(Self {
            revision: set.revision,
            trie,
            names,
        })
    }
    /// Zones containing `ip` as a bitmask (bit i = i-th zone in id order).
    /// Visits one radix path; never allocates.
    #[inline]
    pub fn mask(&self, ip: IpAddr) -> u64 {
        let mut mask = 0u64;
        self.trie.visit_matches(ip, |m| mask |= *m);
        mask
    }
    /// Zone ids of a mask, in id order.
    pub fn names(&self, mask: u64) -> impl Iterator<Item = &str> {
        self.names
            .iter()
            .enumerate()
            .filter(move |(i, _)| mask & (1u64 << i) != 0)
            .map(|(_, n)| n.as_str())
    }
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn zone(id: &str, prefixes: &[&str]) -> Zone {
        Zone {
            id: id.into(),
            prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
            ..Zone::default()
        }
    }
    #[test]
    fn membership_masks_overlap_and_snapshot_matches_contract() {
        let mut set = ZoneSet {
            revision: 3,
            zones: [
                (
                    "corp".to_string(),
                    zone("corp", &["10.0.0.0/8", "2001:db8::/32"]),
                ),
                (
                    "office".to_string(),
                    zone("office", &["10.1.2.3/24", "::ffff:192.0.2.9/120"]),
                ),
            ]
            .into(),
        };
        set.validate().unwrap();
        assert_eq!(
            set.zones["office"].prefixes,
            ["10.1.2.0/24", "192.0.2.0/24"]
        );
        let c = CompiledZones::new(&set).unwrap();
        let names = |ip: &str| {
            c.names(c.mask(ip.parse().unwrap()))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(names("10.1.2.7"), ["corp", "office"]);
        assert_eq!(names("10.9.0.1"), ["corp"]);
        assert_eq!(names("::ffff:192.0.2.1"), ["office"]);
        assert_eq!(names("2001:db8::1"), ["corp"]);
        assert!(names("8.8.8.8").is_empty());
        assert_eq!(
            set.snapshot(),
            serde_json::json!({"revision":3,"zones":{"corp":{"prefixes":["10.0.0.0/8","2001:db8::/32"]},
                "office":{"prefixes":["10.1.2.0/24","192.0.2.0/24"]}}})
        );
    }
    #[test]
    fn validation_bounds_and_paths() {
        let bad = Zone {
            id: "bad name".into(),
            owner: Some("x\n".into()),
            prefixes: vec!["10.0.0.0/8".into(), "10.0.0.1/8".into(), "nope".into()],
            ..Zone::default()
        };
        let paths: Vec<_> = bad.diagnose().into_iter().map(|e| e.path).collect();
        assert_eq!(paths, ["/id", "/owner", "/prefixes/1", "/prefixes/2"]);
        assert_eq!(zone("e", &[]).diagnose()[0].path, "/prefixes");
        let mut many = ZoneSet::default();
        for i in 0..=MAX_ZONES {
            let id = format!("z{i}");
            many.zones.insert(id.clone(), zone(&id, &["10.0.0.0/8"]));
        }
        assert!(many.validate().is_err());
        assert!(valid_zone_name("legacy.svc:1-a_b") && !valid_zone_name(&"a".repeat(129)));
    }
}
