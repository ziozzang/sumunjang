//! Stable `sumunjang.*` reason codes and their en/ko message catalogs.
//!
//! Message keys are the reason codes themselves. Catalogs use `{name}`
//! placeholders. Adding a code requires an entry in both catalogs; the unit test
//! below and the server contract test enforce identical key sets.

/// English catalog (JSON object: code -> message).
pub const MESSAGES_EN: &str = include_str!("../messages/en.json");
/// Korean catalog (JSON object: code -> message).
pub const MESSAGES_KO: &str = include_str!("../messages/ko.json");

/// Decision reason codes that may appear in decision replies and explain output.
pub const DECISION_CODES: &[&str] = &[
    "sumunjang.observe.mode",
    "sumunjang.allow.allowlist",
    "sumunjang.allow.rule",
    "sumunjang.allow.default",
    "sumunjang.deny.rule",
    "sumunjang.deny.block_manual",
    "sumunjang.deny.block_approved",
    "sumunjang.deny.block_automatic",
    "sumunjang.deny.block_source",
    "sumunjang.unavailable.revision_floor",
    "sumunjang.unavailable.owner_replaced",
    "sumunjang.unavailable.source",
];

/// Explain stage codes.
pub const STAGE_CODES: &[&str] = &[
    "sumunjang.stage.mode.observe",
    "sumunjang.stage.mode.enforce",
    "sumunjang.stage.allowlist.match",
    "sumunjang.stage.allowlist.miss",
    "sumunjang.stage.geo.context",
    "sumunjang.stage.rules.none",
    "sumunjang.stage.rules.no_match",
    "sumunjang.stage.rules.winner",
    "sumunjang.stage.rules.observe_winner",
    "sumunjang.stage.rule.matched",
    "sumunjang.stage.rule.expired",
    "sumunjang.stage.block.match",
    "sumunjang.stage.block.miss",
    "sumunjang.stage.block.expired",
    "sumunjang.stage.score.normal",
    "sumunjang.stage.score.watch",
    "sumunjang.stage.score.suspicious",
    "sumunjang.stage.score.high",
    "sumunjang.stage.score.blocked",
    "sumunjang.stage.auto_block.would_trigger",
    "sumunjang.stage.auto_block.not_triggered",
];

/// Audit result labels.
pub const AUDIT_CODES: &[&str] = &[
    "sumunjang.audit.result.committed",
    "sumunjang.audit.result.refused",
    "sumunjang.audit.result.uncertain",
];

/// Every registered code.
pub fn all_codes() -> impl Iterator<Item = &'static str> {
    DECISION_CODES
        .iter()
        .chain(STAGE_CODES)
        .chain(AUDIT_CODES)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    #[test]
    fn catalogs_cover_every_code_with_identical_keys() {
        let en: BTreeMap<String, String> = serde_json::from_str(MESSAGES_EN).unwrap();
        let ko: BTreeMap<String, String> = serde_json::from_str(MESSAGES_KO).unwrap();
        assert_eq!(
            en.keys().collect::<BTreeSet<_>>(),
            ko.keys().collect::<BTreeSet<_>>()
        );
        let codes: BTreeSet<_> = all_codes().map(str::to_owned).collect();
        assert_eq!(codes.len(), all_codes().count(), "duplicate code");
        assert_eq!(codes, en.keys().cloned().collect::<BTreeSet<_>>());
        for (key, value) in en.iter().chain(ko.iter()) {
            assert!(key.starts_with("sumunjang.") && !value.trim().is_empty());
        }
        // Placeholders must agree between languages.
        let names = |s: &str| {
            s.split('{')
                .skip(1)
                .filter_map(|p| p.split_once('}').map(|(n, _)| n.to_owned()))
                .collect::<BTreeSet<_>>()
        };
        for (key, value) in &en {
            assert_eq!(names(value), names(&ko[key]), "{key}");
        }
    }
}
