//! The production decision instantiation (NoTrace) and the fixed-size decision
//! evidence sink must not allocate on any path; explain (VecTrace) must decide
//! exactly like the live path.
use guard_core::{
    AsnPrefix, Block, Engine, GeoContext, Mode, Policy, Rule, RuleAction, RuleSet,
    trace::{DecidingStage, Evidence, NoTrace, VecTrace},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    net::IpAddr,
};

struct Counting;
thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    f();
    ALLOCATIONS.with(Cell::get) - before
}

fn rule(id: &str, action: RuleAction, priority: i32) -> Rule {
    Rule {
        id: id.into(),
        priority,
        network: None,
        countries: vec![],
        asns: vec![],
        action,
        score: 3,
        expires_at: None,
        description: String::new(),
    }
}

fn engine(mode: Mode, with_rules: bool) -> Engine {
    let mut e = Engine::new(Policy {
        mode,
        allow: vec!["192.0.2.42/32".into(), "2001:db8:42::/48".into()],
        ..Policy::default()
    })
    .unwrap();
    e.set_asn_catalog(vec![AsnPrefix {
        network: "198.51.100.0/24".into(),
        asn: 64500,
    }])
    .unwrap();
    for (network, expires_at, reason) in [
        ("203.0.113.0/24", 1_000, "manual"),
        ("203.0.113.7/32", 150, "automatic threshold"),
        ("203.0.113.8/32", 1_000, "manual candidate approval"),
        ("2001:db8:66::/48", 1_000, "manual v6"),
    ] {
        e.add_block(
            Block {
                network: network.into(),
                expires_at,
                reason: reason.into(),
            },
            100,
        )
        .unwrap();
    }
    if with_rules {
        let mut deny = rule("net-deny", RuleAction::Deny, 30);
        deny.network = Some("192.0.2.0/25".into());
        let mut allow = rule("net-allow", RuleAction::Allow, 40);
        allow.network = Some("192.0.2.0/28".into());
        let mut observe = rule("net-observe", RuleAction::Observe, 50);
        observe.network = Some("203.0.113.0/24".into());
        let mut expired = rule("net-expired", RuleAction::Deny, 60);
        expired.network = Some("192.0.2.128/25".into());
        expired.expires_at = Some(120);
        let mut country = rule("country-deny", RuleAction::Deny, 20);
        country.countries = vec!["GB".into()];
        let mut asn = rule("asn-deny", RuleAction::Deny, 10);
        asn.asns = vec![64500];
        e.set_rules(RuleSet {
            version: 1,
            rules: vec![deny, allow, observe, expired, country, asn],
        })
        .unwrap();
    }
    e
}

fn addresses() -> Vec<IpAddr> {
    [
        "192.0.2.1",
        "192.0.2.42",
        "192.0.2.100",
        "192.0.2.200",
        "198.51.100.9",
        "203.0.113.1",
        "203.0.113.7",
        "203.0.113.8",
        "::ffff:203.0.113.9",
        "2001:db8:42::1",
        "2001:db8:66::1",
        "2001:db8:77::1",
        "8.8.8.8",
    ]
    .into_iter()
    .map(|ip| ip.parse().unwrap())
    .collect()
}

#[test]
fn production_and_evidence_paths_are_allocation_free_for_every_stage() {
    assert_eq!(std::mem::size_of::<NoTrace>(), 0);
    let views: Vec<_> = [
        (Mode::Observe, false),
        (Mode::Observe, true),
        (Mode::Enforce, false),
        (Mode::Enforce, true),
    ]
    .into_iter()
    .map(|(m, r)| engine(m, r).decision_view())
    .collect();
    let ips = addresses();
    let geos = [
        GeoContext::default(),
        GeoContext {
            country: Some("GB"),
            asn: None,
        },
        GeoContext {
            country: Some("kr"),
            asn: Some(64500),
        },
    ];
    let mut stages = [0usize; 5];
    let mut denies = 0usize;
    let count = allocations(|| {
        for view in &views {
            for ip in &ips {
                for geo in geos {
                    for now in [100, 130, 2_000] {
                        let d = view.query_ip_context(*ip, now, geo);
                        denies += usize::from(d.action == "deny");
                        std::hint::black_box(view.query_ip(*ip, now));
                        let mut evidence = Evidence::default();
                        let e = view.evaluate_as(Mode::Enforce, *ip, now, geo, &mut evidence);
                        std::hint::black_box(e);
                        std::hint::black_box(evidence.rules().count());
                        stages[evidence.stage.unwrap() as usize] += 1;
                    }
                }
            }
        }
    });
    assert_eq!(count, 0, "production decisions allocated {count} times");
    assert!(denies > 0);
    // Observe is only reached by the plain path; enforce evidence must reach the rest.
    assert!(
        stages[DecidingStage::Allowlist as usize] > 0
            && stages[DecidingStage::Rule as usize] > 0
            && stages[DecidingStage::Block as usize] > 0
            && stages[DecidingStage::Default as usize] > 0,
        "{stages:?}"
    );
}

#[test]
fn traced_evaluation_has_parity_with_live_decisions() {
    for (mode, rules) in [
        (Mode::Observe, true),
        (Mode::Enforce, false),
        (Mode::Enforce, true),
    ] {
        let view = engine(mode, rules).decision_view();
        for ip in addresses() {
            for now in [100, 130, 2_000] {
                let geo = GeoContext {
                    country: Some("GB"),
                    asn: None,
                };
                let live = view.query_ip_context(ip, now, geo);
                let mut trace = VecTrace::default();
                let traced = view.evaluate(ip, now, geo, &mut trace);
                assert_eq!(
                    (live.action, live.reason, live.ttl_ms, live.revision),
                    (traced.action, traced.reason, traced.ttl_ms, traced.revision),
                    "{ip} {now} {mode:?}"
                );
                assert!(!trace.truncated() && !trace.events().is_empty());
                let mut evidence = Evidence::default();
                let e = view.evaluate(ip, now, geo, &mut evidence);
                assert_eq!((e.action, e.reason), (live.action, live.reason));
                if mode == Mode::Observe {
                    assert_eq!(evidence.stage, Some(DecidingStage::Observe));
                    assert_eq!(live.action, "allow");
                }
            }
        }
    }
}
