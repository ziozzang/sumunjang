//! Evaluation trace sinks shared by live decisions, decision evidence and explain.
//!
//! The decision function is generic over a [`Tracer`]. Live HGD1/HTTP/gRPC
//! decisions instantiate it with [`NoTrace`], a zero-sized sink whose method is an
//! empty `#[inline(always)]` body: the production monomorphization contains no
//! trace code, no "tracing enabled" branch and no allocation
//! (`tests/no_alloc.rs`). Decision evidence uses [`Evidence`], a fixed-size
//! borrowed record that never allocates. Administrative explain uses the *same*
//! function with [`VecTrace`], a bounded event buffer. Tracers only receive facts;
//! the evaluator never reads anything back from them, so a tracer cannot change a
//! decision.
use crate::{Block, BlockSource, Mode, RuleAction, rules::Rule};

/// Receives facts in evaluation order.
pub trait Tracer<'a> {
    fn event(&mut self, event: TraceEvent<'a>);
}

/// Production sink: compiles away entirely.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTrace;
impl<'a> Tracer<'a> for NoTrace {
    #[inline(always)]
    fn event(&mut self, _event: TraceEvent<'a>) {}
}
const _: () = assert!(std::mem::size_of::<NoTrace>() == 0);

/// Which evaluation step produced the final action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecidingStage {
    /// Observe mode: every Guard decision allows; nothing else is consulted.
    Observe,
    /// The policy allowlist matched; it wins over rules and blocks.
    Allowlist,
    /// The highest-precedence matching JSON/Lua rule allowed or denied.
    Rule,
    /// An active manual, approved or automatic block denied.
    Block,
    /// Nothing matched in enforce mode.
    Default,
}

/// Where the ASN used by rule evaluation came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsnSource {
    None,
    Geoip,
    Catalog,
}

/// One evaluation fact. Events borrow only from the evaluated policy view.
#[derive(Clone, Copy, Debug)]
pub enum TraceEvent<'a> {
    /// Policy mode at evaluation.
    Mode { mode: Mode },
    /// Allowlist lookup; `prefix_len` is the matched allow prefix length.
    Allowlist { prefix_len: Option<u8> },
    /// Metadata used by rules (`country` is an uppercase ISO alpha-2 code).
    Geo {
        country: Option<[u8; 2]>,
        asn: Option<u32>,
        asn_source: AsnSource,
    },
    /// A rule whose conditions matched but whose `expires_at` has passed.
    RuleExpired { rule: &'a Rule },
    /// A matching active rule in precedence order; the first one is the winner.
    RuleMatched { rule: &'a Rule, winner: bool },
    /// A covering block that has expired and therefore does not enforce.
    BlockExpired { block: &'a Block },
    /// Block lookup result (most specific active block).
    Block { block: Option<&'a Block> },
    /// Final step.
    Outcome { stage: DecidingStage },
}

/// Maximum explain events. Bounded by 256 rules, 129 nested prefixes and a few
/// fixed events, so real evaluations never truncate; the bound is defensive.
pub const MAX_TRACE_EVENTS: usize = 512;

/// Bounded explain sink. It never grows past [`MAX_TRACE_EVENTS`] and marks
/// `truncated` instead.
#[derive(Debug, Default)]
pub struct VecTrace<'a> {
    events: Vec<TraceEvent<'a>>,
    truncated: bool,
}
impl<'a> VecTrace<'a> {
    pub fn events(&self) -> &[TraceEvent<'a>] {
        &self.events
    }
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}
impl<'a> Tracer<'a> for VecTrace<'a> {
    fn event(&mut self, event: TraceEvent<'a>) {
        if self.events.len() < MAX_TRACE_EVENTS {
            self.events.push(event);
        } else {
            self.truncated = true;
        }
    }
}

/// Maximum rule IDs carried by decision evidence (ADR 0019 stage list bound).
pub const MAX_EVIDENCE_RULES: usize = 8;

/// Fixed-size, allocation-free decision evidence used to enrich gRPC/HTTP
/// decision replies. Rule references are kept in precedence order (winner first).
#[derive(Clone, Copy, Debug)]
pub struct Evidence<'a> {
    pub stage: Option<DecidingStage>,
    pub allowlisted: bool,
    pub country: Option<[u8; 2]>,
    pub asn: Option<u32>,
    pub asn_source: AsnSource,
    pub winner: Option<&'a Rule>,
    rules: [Option<&'a Rule>; MAX_EVIDENCE_RULES],
    rule_count: usize,
    pub rules_truncated: bool,
    pub block: Option<&'a Block>,
}
impl Default for Evidence<'_> {
    fn default() -> Self {
        Self {
            stage: None,
            allowlisted: false,
            country: None,
            asn: None,
            asn_source: AsnSource::None,
            winner: None,
            rules: [None; MAX_EVIDENCE_RULES],
            rule_count: 0,
            rules_truncated: false,
            block: None,
        }
    }
}
impl<'a> Evidence<'a> {
    /// Matching active rules in precedence order, at most [`MAX_EVIDENCE_RULES`].
    pub fn rules(&self) -> impl Iterator<Item = &'a Rule> + '_ {
        self.rules[..self.rule_count].iter().flatten().copied()
    }
}
impl<'a> Tracer<'a> for Evidence<'a> {
    #[inline]
    fn event(&mut self, event: TraceEvent<'a>) {
        match event {
            TraceEvent::Allowlist { prefix_len } => self.allowlisted = prefix_len.is_some(),
            TraceEvent::Geo {
                country,
                asn,
                asn_source,
            } => {
                self.country = country;
                self.asn = asn;
                self.asn_source = asn_source;
            }
            TraceEvent::RuleMatched { rule, winner } => {
                if winner {
                    self.winner = Some(rule);
                }
                if self.rule_count < MAX_EVIDENCE_RULES {
                    self.rules[self.rule_count] = Some(rule);
                    self.rule_count += 1;
                } else {
                    self.rules_truncated = true;
                }
            }
            TraceEvent::Block { block } => self.block = block,
            TraceEvent::Outcome { stage } => self.stage = Some(stage),
            TraceEvent::Mode { .. }
            | TraceEvent::RuleExpired { .. }
            | TraceEvent::BlockExpired { .. } => {}
        }
    }
}

/// Well-known block reasons written by Sumunjang itself.
pub const AUTOMATIC_BLOCK_REASON: &str = "automatic threshold";
pub const APPROVED_BLOCK_REASON: &str = "manual candidate approval";

/// Decision reason codes as a compact enum (metrics index; `as_str` is the
/// stable `sumunjang.*` code).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ReasonCode {
    ObserveMode,
    AllowAllowlist,
    AllowRule,
    #[default]
    AllowDefault,
    DenyRule,
    DenyBlockManual,
    DenyBlockApproved,
    DenyBlockAutomatic,
    DenyBlockSource,
    DenyBlockAsn,
}
impl ReasonCode {
    pub const ALL: [ReasonCode; 10] = [
        Self::ObserveMode,
        Self::AllowAllowlist,
        Self::AllowRule,
        Self::AllowDefault,
        Self::DenyRule,
        Self::DenyBlockManual,
        Self::DenyBlockApproved,
        Self::DenyBlockAutomatic,
        Self::DenyBlockSource,
        Self::DenyBlockAsn,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveMode => "sumunjang.observe.mode",
            Self::AllowAllowlist => "sumunjang.allow.allowlist",
            Self::AllowRule => "sumunjang.allow.rule",
            Self::AllowDefault => "sumunjang.allow.default",
            Self::DenyRule => "sumunjang.deny.rule",
            Self::DenyBlockManual => "sumunjang.deny.block_manual",
            Self::DenyBlockApproved => "sumunjang.deny.block_approved",
            Self::DenyBlockAutomatic => "sumunjang.deny.block_automatic",
            Self::DenyBlockSource => "sumunjang.deny.block_source",
            Self::DenyBlockAsn => "sumunjang.deny.block_asn",
        }
    }
    pub fn classify(stage: DecidingStage, rule: Option<&Rule>, block: Option<&Block>) -> Self {
        match stage {
            DecidingStage::Observe => Self::ObserveMode,
            DecidingStage::Allowlist => Self::AllowAllowlist,
            DecidingStage::Default => Self::AllowDefault,
            DecidingStage::Rule => match rule.map(|r| r.action) {
                Some(RuleAction::Deny) => Self::DenyRule,
                _ => Self::AllowRule,
            },
            // Provenance decides; pre-provenance blocks fall back to Sumunjang's
            // own fixed reasons.
            DecidingStage::Block => match block.map(|b| (b.origin.source, b.reason.as_str())) {
                Some((BlockSource::Auto, _))
                | Some((BlockSource::Unknown, AUTOMATIC_BLOCK_REASON)) => Self::DenyBlockAutomatic,
                Some((BlockSource::Approved, _))
                | Some((BlockSource::Unknown, APPROVED_BLOCK_REASON)) => Self::DenyBlockApproved,
                Some((BlockSource::Kubernetes, _)) => Self::DenyBlockSource,
                Some((BlockSource::AsnProposal, _)) => Self::DenyBlockAsn,
                _ => Self::DenyBlockManual,
            },
        }
    }
}

/// Stable namespaced reason code for a decision (ADR 0019 `sumunjang.*`).
pub fn reason_code(
    stage: DecidingStage,
    rule: Option<&Rule>,
    block: Option<&Block>,
) -> &'static str {
    ReasonCode::classify(stage, rule, block).as_str()
}
