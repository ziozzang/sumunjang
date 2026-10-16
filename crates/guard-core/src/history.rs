//! Bounded per-address signal history.
//!
//! Accepted evidence events are folded into per-minute buckets per address:
//! the weighted score added in that minute and per-signal counts. No request,
//! path or source data is retained. Buckets older than the retention window are
//! pruned; address and bucket counts are capped and overflow is counted, never
//! grown. History is in-memory observation (not policy): it is shared by engine
//! clones, survives policy changes and is lost on restart.
use crate::EventKind;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

pub const BUCKET_SECS: u64 = 60;
pub const DEFAULT_RETENTION_SECS: u64 = 6 * 3600;
pub const MAX_RETENTION_SECS: u64 = 48 * 3600;
/// Maximum distinct addresses with history.
pub const MAX_ADDRESSES: usize = 10_000;
/// Maximum buckets over all addresses (each ≈ 64 bytes including map overhead).
pub const MAX_BUCKETS: usize = 262_144;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SignalCounts {
    pub honeypot: u64,
    pub scanner: u64,
    pub auth_failure: u64,
    pub invalid_request: u64,
}
impl SignalCounts {
    pub fn add(&mut self, kind: EventKind, n: u64) {
        let slot = match kind {
            EventKind::Honeypot => &mut self.honeypot,
            EventKind::Scanner => &mut self.scanner,
            EventKind::AuthFailure => &mut self.auth_failure,
            EventKind::InvalidRequest => &mut self.invalid_request,
        };
        *slot = slot.saturating_add(n);
    }
    pub fn merge(&mut self, o: &SignalCounts) {
        self.honeypot = self.honeypot.saturating_add(o.honeypot);
        self.scanner = self.scanner.saturating_add(o.scanner);
        self.auth_failure = self.auth_failure.saturating_add(o.auth_failure);
        self.invalid_request = self.invalid_request.saturating_add(o.invalid_request);
    }
    pub fn total(&self) -> u64 {
        self.honeypot
            .saturating_add(self.scanner)
            .saturating_add(self.auth_failure)
            .saturating_add(self.invalid_request)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Bucket {
    /// Start of the minute, Unix seconds.
    pub start: u64,
    /// Weighted score added during this minute (weights at ingestion time).
    pub score: u64,
    pub signals: SignalCounts,
}

#[derive(Debug, Default)]
pub struct SignalHistory {
    retention: u64,
    addresses: HashMap<IpAddr, BTreeMap<u64, Bucket>>,
    buckets: usize,
    dropped: u64,
    last_pruned: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryStats {
    pub retention_secs: u64,
    pub bucket_secs: u64,
    pub addresses: usize,
    pub buckets: usize,
    pub max_addresses: usize,
    pub max_buckets: usize,
    pub dropped: u64,
}

impl SignalHistory {
    pub fn new(retention_secs: u64) -> Self {
        Self {
            retention: retention_secs.clamp(BUCKET_SECS, MAX_RETENTION_SECS),
            ..Self::default()
        }
    }
    pub fn retention_secs(&self) -> u64 {
        self.retention
    }
    fn prune(&mut self, now: u64) {
        if now.saturating_sub(self.last_pruned) < BUCKET_SECS && self.last_pruned != 0 {
            return;
        }
        self.last_pruned = now;
        let oldest = now.saturating_sub(self.retention);
        let mut removed = 0;
        self.addresses.retain(|_, b| {
            let before = b.len();
            b.retain(|start, _| *start + BUCKET_SECS > oldest);
            removed += before - b.len();
            !b.is_empty()
        });
        self.buckets -= removed;
    }
    /// Record one accepted event. Returns false when a capacity bound refused it.
    pub fn record(&mut self, ip: IpAddr, kind: EventKind, weight: u64, now: u64) -> bool {
        self.prune(now);
        let start = now - now % BUCKET_SECS;
        let known = self.addresses.contains_key(&ip);
        if !known && self.addresses.len() >= MAX_ADDRESSES {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let series = self.addresses.entry(ip).or_default();
        if !series.contains_key(&start) {
            if self.buckets >= MAX_BUCKETS {
                self.dropped = self.dropped.saturating_add(1);
                if series.is_empty() {
                    self.addresses.remove(&ip);
                }
                return false;
            }
            self.buckets += 1;
        }
        let bucket = series.entry(start).or_insert(Bucket {
            start,
            ..Bucket::default()
        });
        bucket.score = bucket.score.saturating_add(weight);
        bucket.signals.add(kind, 1);
        true
    }
    /// Buckets of one address within `[since, until)`, oldest first.
    pub fn series(&mut self, ip: IpAddr, since: u64, until: u64, now: u64) -> Vec<Bucket> {
        self.prune(now);
        self.addresses.get(&ip).map_or_else(Vec::new, |b| {
            b.range(since - since % BUCKET_SECS..until)
                .map(|(_, v)| *v)
                .collect()
        })
    }
    pub fn stats(&self) -> HistoryStats {
        HistoryStats {
            retention_secs: self.retention,
            bucket_secs: BUCKET_SECS,
            addresses: self.addresses.len(),
            buckets: self.buckets,
            max_addresses: MAX_ADDRESSES,
            max_buckets: MAX_BUCKETS,
            dropped: self.dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn buckets_are_per_minute_pruned_and_capped() {
        let mut h = SignalHistory::new(3600);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(h.record(ip, EventKind::Honeypot, 10, 120));
        assert!(h.record(ip, EventKind::Scanner, 5, 150));
        assert!(h.record(ip, EventKind::Scanner, 5, 200));
        let s = h.series(ip, 0, u64::MAX, 200);
        assert_eq!(s.len(), 2);
        assert_eq!(
            (
                s[0].start,
                s[0].score,
                s[0].signals.honeypot,
                s[0].signals.scanner
            ),
            (120, 15, 1, 1)
        );
        assert_eq!(s[1].start, 180);
        assert_eq!(h.series(ip, 180, 240, 200).len(), 1);
        // Retention removes old minutes.
        assert!(h.series(ip, 0, u64::MAX, 180 + 3600 + 61).is_empty());
        assert_eq!(h.stats().buckets, 0);
        // Address cap.
        let mut h = SignalHistory::new(3600);
        for i in 0..MAX_ADDRESSES as u32 {
            assert!(h.record(
                IpAddr::from(std::net::Ipv4Addr::from(i + 1)),
                EventKind::Scanner,
                1,
                60
            ));
        }
        assert!(!h.record(
            "255.255.255.255".parse().unwrap(),
            EventKind::Scanner,
            1,
            60
        ));
        assert_eq!(h.stats().dropped, 1);
        assert_eq!(h.stats().addresses, MAX_ADDRESSES);
    }
}
