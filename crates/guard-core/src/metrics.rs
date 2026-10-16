//! Process-wide, allocation-free decision counters and latency histograms.
//!
//! Hot-path recording is a few relaxed atomic additions on fixed arrays indexed
//! by bounded enums (transport, mode, reason code); there are no maps, strings
//! or labels derived from addresses or subjects. Rendering (Prometheus text
//! exposition 0.0.4) happens only on scrape.
use crate::{Mode, trace::ReasonCode};
use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Transport {
    Http,
    Hgd1,
    Grpc,
}
impl Transport {
    pub const ALL: [Transport; 3] = [Self::Http, Self::Hgd1, Self::Grpc];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Hgd1 => "hgd1",
            Self::Grpc => "grpc",
        }
    }
}
/// Why a reply was unavailable (gRPC fences, native source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Unavailable {
    RevisionFloor,
    OwnerReplaced,
    Source,
}
impl Unavailable {
    pub const ALL: [Unavailable; 3] = [Self::RevisionFloor, Self::OwnerReplaced, Self::Source];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RevisionFloor => "sumunjang.unavailable.revision_floor",
            Self::OwnerReplaced => "sumunjang.unavailable.owner_replaced",
            Self::Source => "sumunjang.unavailable.source",
        }
    }
}

const CODES: usize = ReasonCode::ALL.len();
/// Histogram upper bounds in microseconds.
pub const LATENCY_BOUNDS_US: [u64; 12] = [
    5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 100_000,
];
const BUCKETS: usize = LATENCY_BOUNDS_US.len() + 1;

#[allow(clippy::declare_interior_mutable_const)]
const Z: AtomicU64 = AtomicU64::new(0);
pub struct Metrics {
    decisions: [[[AtomicU64; CODES]; 2]; 3],
    unavailable: [[AtomicU64; 3]; 3],
    latency: [[AtomicU64; BUCKETS]; 3],
    latency_sum_ns: [AtomicU64; 3],
    pub evidence_batches_rejected: AtomicU64,
    /// [lua, json]
    pub rules_compile_failures: [AtomicU64; 2],
    pub checkpoint_success: AtomicU64,
    pub checkpoint_failure: AtomicU64,
    pub checkpoint_last_success: AtomicU64,
    /// [committed, refused, uncertain]
    pub admin_changes: [AtomicU64; 3],
}
pub static METRICS: Metrics = Metrics {
    decisions: [const { [const { [Z; CODES] }; 2] }; 3],
    unavailable: [const { [Z; 3] }; 3],
    latency: [const { [Z; BUCKETS] }; 3],
    latency_sum_ns: [Z; 3],
    evidence_batches_rejected: Z,
    rules_compile_failures: [Z; 2],
    checkpoint_success: Z,
    checkpoint_failure: Z,
    checkpoint_last_success: Z,
    admin_changes: [Z; 3],
};

impl Metrics {
    /// Record one decision outcome. Allocation-free.
    #[inline]
    pub fn decision(&self, transport: Transport, mode: Mode, code: ReasonCode) {
        self.decisions[transport as usize][mode as usize][code as usize].fetch_add(1, Relaxed);
    }
    #[inline]
    pub fn unavailable(&self, transport: Transport, why: Unavailable) {
        self.unavailable[transport as usize][why as usize].fetch_add(1, Relaxed);
    }
    /// Record decision latency. Allocation-free.
    #[inline]
    pub fn latency(&self, transport: Transport, elapsed: std::time::Duration) {
        let us = elapsed.as_micros() as u64;
        let bucket = LATENCY_BOUNDS_US
            .iter()
            .position(|b| us <= *b)
            .unwrap_or(BUCKETS - 1);
        self.latency[transport as usize][bucket].fetch_add(1, Relaxed);
        self.latency_sum_ns[transport as usize].fetch_add(elapsed.as_nanos() as u64, Relaxed);
    }
    pub fn decisions_total(&self, transport: Transport, mode: Mode, code: ReasonCode) -> u64 {
        self.decisions[transport as usize][mode as usize][code as usize].load(Relaxed)
    }
    pub fn latency_count(&self, transport: Transport) -> u64 {
        self.latency[transport as usize]
            .iter()
            .map(|b| b.load(Relaxed))
            .sum()
    }
    /// Append counters and histograms in Prometheus text format.
    pub fn render(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# HELP sumunjang_decisions_total Network admission decisions by transport, mode, outcome and reason code."
        );
        let _ = writeln!(out, "# TYPE sumunjang_decisions_total counter");
        for t in Transport::ALL {
            for (m, mode) in [(Mode::Observe, "observe"), (Mode::Enforce, "enforce")] {
                for code in ReasonCode::ALL {
                    let outcome = if code.as_str().starts_with("sumunjang.deny.") {
                        "deny"
                    } else {
                        "allow"
                    };
                    let _ = writeln!(
                        out,
                        "sumunjang_decisions_total{{transport=\"{}\",mode=\"{mode}\",outcome=\"{outcome}\",reason=\"{}\"}} {}",
                        t.as_str(),
                        code.as_str(),
                        self.decisions_total(t, m, code)
                    );
                }
            }
        }
        let _ = writeln!(
            out,
            "# HELP sumunjang_decisions_unavailable_total Decision replies withheld as unavailable, by reason code."
        );
        let _ = writeln!(out, "# TYPE sumunjang_decisions_unavailable_total counter");
        for t in Transport::ALL {
            for why in Unavailable::ALL {
                let _ = writeln!(
                    out,
                    "sumunjang_decisions_unavailable_total{{transport=\"{}\",reason=\"{}\"}} {}",
                    t.as_str(),
                    why.as_str(),
                    self.unavailable[t as usize][why as usize].load(Relaxed)
                );
            }
        }
        let _ = writeln!(
            out,
            "# HELP sumunjang_decision_duration_seconds Decision handling latency per transport."
        );
        let _ = writeln!(out, "# TYPE sumunjang_decision_duration_seconds histogram");
        for t in Transport::ALL {
            let mut cumulative = 0u64;
            for (i, bound) in LATENCY_BOUNDS_US.iter().enumerate() {
                cumulative += self.latency[t as usize][i].load(Relaxed);
                let _ = writeln!(
                    out,
                    "sumunjang_decision_duration_seconds_bucket{{transport=\"{}\",le=\"{}\"}} {cumulative}",
                    t.as_str(),
                    *bound as f64 / 1e6
                );
            }
            cumulative += self.latency[t as usize][BUCKETS - 1].load(Relaxed);
            let _ = writeln!(
                out,
                "sumunjang_decision_duration_seconds_bucket{{transport=\"{}\",le=\"+Inf\"}} {cumulative}",
                t.as_str()
            );
            let _ = writeln!(
                out,
                "sumunjang_decision_duration_seconds_sum{{transport=\"{}\"}} {}",
                t.as_str(),
                self.latency_sum_ns[t as usize].load(Relaxed) as f64 / 1e9
            );
            let _ = writeln!(
                out,
                "sumunjang_decision_duration_seconds_count{{transport=\"{}\"}} {cumulative}",
                t.as_str()
            );
        }
        let counter = |out: &mut String, name: &str, help: &str, value: u64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        };
        counter(
            out,
            "sumunjang_evidence_batches_rejected_total",
            "Evidence batches refused before ingestion (size, source or timestamp).",
            self.evidence_batches_rejected.load(Relaxed),
        );
        let _ = writeln!(
            out,
            "# HELP sumunjang_rules_compile_failures_total Refused rule documents by kind.\n# TYPE sumunjang_rules_compile_failures_total counter"
        );
        for (i, kind) in ["lua", "json"].iter().enumerate() {
            let _ = writeln!(
                out,
                "sumunjang_rules_compile_failures_total{{kind=\"{kind}\"}} {}",
                self.rules_compile_failures[i].load(Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "# HELP sumunjang_checkpoints_total Durable checkpoint attempts by result.\n# TYPE sumunjang_checkpoints_total counter"
        );
        let _ = writeln!(
            out,
            "sumunjang_checkpoints_total{{result=\"success\"}} {}",
            self.checkpoint_success.load(Relaxed)
        );
        let _ = writeln!(
            out,
            "sumunjang_checkpoints_total{{result=\"failure\"}} {}",
            self.checkpoint_failure.load(Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP sumunjang_admin_changes_total Audited administrative changes by result.\n# TYPE sumunjang_admin_changes_total counter"
        );
        for (i, r) in ["committed", "refused", "uncertain"].iter().enumerate() {
            let _ = writeln!(
                out,
                "sumunjang_admin_changes_total{{result=\"{r}\"}} {}",
                self.admin_changes[i].load(Relaxed)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exposition_has_bounded_labels_and_cumulative_buckets() {
        let m = Metrics {
            decisions: [const { [const { [Z; CODES] }; 2] }; 3],
            unavailable: [const { [Z; 3] }; 3],
            latency: [const { [Z; BUCKETS] }; 3],
            latency_sum_ns: [Z; 3],
            evidence_batches_rejected: Z,
            rules_compile_failures: [Z; 2],
            checkpoint_success: Z,
            checkpoint_failure: Z,
            checkpoint_last_success: Z,
            admin_changes: [Z; 3],
        };
        m.decision(Transport::Grpc, Mode::Enforce, ReasonCode::DenyRule);
        m.latency(Transport::Grpc, std::time::Duration::from_micros(30));
        m.latency(Transport::Grpc, std::time::Duration::from_secs(1));
        m.unavailable(Transport::Grpc, Unavailable::RevisionFloor);
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains("sumunjang_decisions_total{transport=\"grpc\",mode=\"enforce\",outcome=\"deny\",reason=\"sumunjang.deny.rule\"} 1"));
        assert!(out.contains(
            "sumunjang_decision_duration_seconds_bucket{transport=\"grpc\",le=\"0.00005\"} 1"
        ));
        assert!(out.contains(
            "sumunjang_decision_duration_seconds_bucket{transport=\"grpc\",le=\"+Inf\"} 2"
        ));
        assert!(out.contains("sumunjang_decision_duration_seconds_count{transport=\"grpc\"} 2"));
        assert!(out.contains("sumunjang_decisions_unavailable_total{transport=\"grpc\",reason=\"sumunjang.unavailable.revision_floor\"} 1"));
        // Every series line is name{bounded labels} value; no free-form label values.
        for line in out.lines().filter(|l| !l.starts_with('#')) {
            assert!(!line.contains('/') || line.contains("le="), "{line}");
        }
    }
}
