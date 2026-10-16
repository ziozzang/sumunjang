//! Single-thread lookup microbenchmark, not HTTP throughput or a latency SLO.
//! cargo run --release -p guard-core --example prefix_bench
use guard_core::{Block, Engine, Mode, Policy, State, Stats, prefix::PrefixTrie};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
fn ip(seed: &mut u64, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(
            ((next(seed) as u128) << 64) | next(seed) as u128,
        ))
    } else {
        IpAddr::V4(Ipv4Addr::from(next(seed) as u32))
    }
}
fn main() {
    for count in [20_000, 100_000] {
        let mut seed = 0xabcdef123456789;
        let mut tree = PrefixTrie::default();
        let mut hash = HashMap::new();
        let mut hit = Vec::new();
        while hash.len() < count {
            let ip = ip(&mut seed, hash.len() % 2 == 0);
            let n = IpNet::new(ip, if ip.is_ipv4() { 24 } else { 48 })
                .unwrap()
                .trunc();
            if hash.insert(n, 200u64).is_none() {
                tree.insert(n, 200u64);
                hit.push(ip);
            }
        }
        let pool: Vec<_> = (0..100_000)
            .map(|i| {
                if i % 2 == 0 {
                    hit[i % hit.len()]
                } else {
                    ip(&mut seed, i % 4 == 1)
                }
            })
            .collect();
        let iterations = 1_000_000;
        let start = Instant::now();
        let mut matches = 0;
        for i in 0..iterations {
            matches += black_box(
                tree.longest_where(black_box(pool[i % pool.len()]), |expiry| *expiry > 100),
            )
            .is_some() as usize;
        }
        let trie_ns = start.elapsed().as_nanos() as f64 / iterations as f64;
        let start = Instant::now();
        let mut hash_matches = 0;
        for i in 0..iterations {
            let ip = black_box(pool[i % pool.len()]);
            let max = if ip.is_ipv4() { 32 } else { 128 };
            for prefix in (0..=max).rev() {
                let n = IpNet::new(ip, prefix).unwrap().trunc();
                if hash.get(&n).is_some_and(|v| *v > 100) {
                    hash_matches += 1;
                    break;
                }
            }
        }
        let hash_ns = start.elapsed().as_nanos() as f64 / iterations as f64;
        assert_eq!(matches, hash_matches);
        println!(
            "prefixes={count} pooled_ips={} iterations={iterations} hit_ratio={:.3} arena_bytes={} trie_ns_per_lookup={trie_ns:.1} hash_ns_per_lookup={hash_ns:.1} trie_lookup_per_sec={:.0}",
            pool.len(),
            matches as f64 / iterations as f64,
            tree.allocated_bytes(),
            1e9 / trie_ns
        );
        if count == 20_000 {
            let blocks = hash
                .keys()
                .map(|n| Block {
                    network: n.to_string(),
                    expires_at: 200,
                    reason: "benchmark".into(),
                    ..Default::default()
                })
                .collect();
            let engine = Engine::restore(State {
                block_origins: Default::default(),
                rules_script: None,
                rules_epoch: None,
                rules_sequence: None,
                policy_epoch: None,
                policy_sequence: None,
                zones: Default::default(),
                policy: Policy {
                    mode: Mode::Enforce,
                    ..Policy::default()
                },
                revision: 1,
                blocks,
                aggregates: vec![],
                stats: Stats::default(),
                rules: Default::default(),
            })
            .unwrap();
            let view = engine.decision_view();
            let start = Instant::now();
            for i in 0..iterations {
                black_box(view.query_ip(black_box(pool[i % pool.len()]), 100));
            }
            let ns = start.elapsed().as_nanos() as f64 / iterations as f64;
            println!(
                "decision_prefixes={count} arena_bytes={} decision_ns_per_lookup={ns:.1} decision_lookup_per_sec={:.0}",
                view.allocated_bytes(),
                1e9 / ns
            );
        }
    }
}
