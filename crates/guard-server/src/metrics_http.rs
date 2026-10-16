//! `GET /metrics`: Prometheus text exposition (version 0.0.4).
//!
//! Served on the main management listener (HTTPS with `--management-tls`),
//! authorized by the optional read-only `HANGANG_GUARD_METRICS_TOKEN` or the
//! admin credential. Labels are bounded enums only (transport, mode, outcome,
//! reason code, source kind, result); addresses, subjects, rule or zone names
//! never appear. Gauges are computed on scrape under the engine lock briefly.
use crate::App;
use axum::{
    extract::State as HttpState,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::fmt::Write;

fn gauge(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    );
}
fn counter(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
    );
}

pub fn render(app: &App) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let now = crate::now();
    let _ = writeln!(
        out,
        "# HELP sumunjang_build_info Build version.\n# TYPE sumunjang_build_info gauge\nsumunjang_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    guard_core::metrics::METRICS.render(&mut out);
    let m = &guard_core::metrics::METRICS;
    let last = m
        .checkpoint_last_success
        .load(std::sync::atomic::Ordering::Relaxed);
    gauge(
        &mut out,
        "sumunjang_checkpoint_last_success_timestamp_seconds",
        "Unix time of the last successful durable checkpoint (0 = none yet).",
        last,
    );
    gauge(
        &mut out,
        "sumunjang_checkpoint_age_seconds",
        "Seconds since the last successful checkpoint (-1 = none yet).",
        if last == 0 {
            -1
        } else {
            now.saturating_sub(last) as i64
        },
    );
    gauge(
        &mut out,
        "sumunjang_ready",
        "1 when /readyz reports ready.",
        u8::from(app.ready_reason().is_none()),
    );

    // Engine state (brief lock; counts only).
    if let Ok(inner) = app.inner.lock() {
        let e = &inner.engine;
        let (candidates, blocks) = e.capacity();
        gauge(
            &mut out,
            "sumunjang_candidates",
            "Tracked evidence aggregates (candidate addresses).",
            candidates,
        );
        let _ = writeln!(
            out,
            "# HELP sumunjang_blocks Active blocks by provenance.\n# TYPE sumunjang_blocks gauge"
        );
        let mut by_source = [0usize; 6];
        for b in e.blocks() {
            by_source[b.origin.source as usize] += 1;
        }
        for (i, source) in [
            "unknown",
            "manual",
            "approved",
            "auto",
            "kubernetes",
            "asn_proposal",
        ]
        .iter()
        .enumerate()
        {
            let _ = writeln!(
                out,
                "sumunjang_blocks{{source=\"{source}\"}} {}",
                by_source[i]
            );
        }
        let _ = blocks;
        let p = e.policy();
        let expired = p
            .allow_meta
            .values()
            .filter(|m| m.expires_at.is_some_and(|x| x <= now))
            .count();
        let _ = writeln!(
            out,
            "# HELP sumunjang_allowlist_entries Allowlist entries by state.\n# TYPE sumunjang_allowlist_entries gauge"
        );
        let _ = writeln!(
            out,
            "sumunjang_allowlist_entries{{state=\"active\"}} {}",
            p.allow.len() - expired
        );
        let _ = writeln!(
            out,
            "sumunjang_allowlist_entries{{state=\"expired\"}} {expired}"
        );
        gauge(
            &mut out,
            "sumunjang_policy_enforce",
            "1 in enforce mode, 0 in observe mode.",
            u8::from(p.mode == guard_core::Mode::Enforce),
        );
        gauge(
            &mut out,
            "sumunjang_rules",
            "Configured JSON/Lua rules.",
            e.rules().rules.len(),
        );
        gauge(
            &mut out,
            "sumunjang_rules_from_lua",
            "1 when active rules were applied from Lua.",
            u8::from(e.rules_script().is_some()),
        );
        let z = e.zones();
        gauge(&mut out, "sumunjang_zones", "Network zones.", z.zones.len());
        gauge(
            &mut out,
            "sumunjang_zone_prefixes",
            "Prefixes over all network zones.",
            z.zones.values().map(|z| z.prefixes.len()).sum::<usize>(),
        );
        gauge(
            &mut out,
            "sumunjang_zone_revision",
            "Network zone revision.",
            z.revision,
        );
        gauge(
            &mut out,
            "sumunjang_decision_revision",
            "Published decision revision.",
            e.revision(),
        );
        gauge(
            &mut out,
            "sumunjang_asn_catalog_prefixes",
            "Offline ASN catalog prefixes.",
            e.asn_catalog().len(),
        );
        let stats = e.stats();
        counter(
            &mut out,
            "sumunjang_evidence_accepted_total",
            "Evidence events accepted into aggregates.",
            stats.accepted,
        );
        counter(
            &mut out,
            "sumunjang_evidence_dropped_capacity_total",
            "Evidence events dropped at the candidate capacity bound.",
            stats.dropped_capacity,
        );
        counter(
            &mut out,
            "sumunjang_block_capacity_rejections_total",
            "Automatic blocks refused at the block capacity bound.",
            stats.block_capacity_rejections,
        );
        let history = e.history();
        drop(inner);
        if let Ok(h) = history.lock() {
            let s = h.stats();
            gauge(
                &mut out,
                "sumunjang_history_addresses",
                "Addresses with in-memory signal history.",
                s.addresses,
            );
            gauge(
                &mut out,
                "sumunjang_history_buckets",
                "In-memory signal history minute buckets.",
                s.buckets,
            );
            counter(
                &mut out,
                "sumunjang_history_dropped_total",
                "Signal history updates refused at capacity bounds.",
                s.dropped,
            );
        }
    }

    // TLS material.
    match &app.tls {
        Some(tls) => {
            let (reloads, failures, consecutive, not_after) = tls.counters();
            gauge(
                &mut out,
                "sumunjang_tls_enabled",
                "1 when mTLS material is configured.",
                1,
            );
            counter(
                &mut out,
                "sumunjang_tls_reloads_total",
                "Successful TLS material reloads.",
                reloads,
            );
            counter(
                &mut out,
                "sumunjang_tls_reload_failures_total",
                "Refused TLS material reloads (previous material kept).",
                failures,
            );
            gauge(
                &mut out,
                "sumunjang_tls_reload_consecutive_failures",
                "Consecutive refused reloads since the last success.",
                consecutive,
            );
            if let Some(not_after) = not_after {
                gauge(
                    &mut out,
                    "sumunjang_tls_leaf_expiry_seconds",
                    "Seconds until the served leaf certificate expires (negative when expired).",
                    not_after as i64 - now as i64,
                );
            }
        }
        None => gauge(
            &mut out,
            "sumunjang_tls_enabled",
            "1 when mTLS material is configured.",
            0,
        ),
    }

    // GeoIP.
    let geo = serde_json::to_value(app.geo.load().status()).unwrap_or_default();
    let _ = writeln!(
        out,
        "# HELP sumunjang_geoip_database_loaded GeoIP databases loaded by role.\n# TYPE sumunjang_geoip_database_loaded gauge"
    );
    for role in ["country", "asn"] {
        let _ = writeln!(
            out,
            "sumunjang_geoip_database_loaded{{role=\"{role}\"}} {}",
            u8::from(!geo[role].is_null())
        );
    }

    // Kubernetes sources.
    match &app.native_source {
        Some(owner) => {
            let report = owner.report(&app.view.load());
            gauge(
                &mut out,
                "sumunjang_kubernetes_authority_enabled",
                "1 when the native Kubernetes policy authority is configured.",
                1,
            );
            gauge(
                &mut out,
                "sumunjang_kubernetes_authority_available",
                "1 while the native source publication is fresh.",
                u8::from(report["available"] == true),
            );
            gauge(
                &mut out,
                "sumunjang_kubernetes_authority_remaining_seconds",
                "Remaining freshness of the native source publication.",
                report["remaining_ms"].as_u64().unwrap_or(0) as f64 / 1000.0,
            );
        }
        None => gauge(
            &mut out,
            "sumunjang_kubernetes_authority_enabled",
            "1 when the native Kubernetes policy authority is configured.",
            0,
        ),
    }
    let fresh = app
        .network_source
        .load_full()
        .is_some_and(|s| s.report()["fresh"] == true);
    gauge(
        &mut out,
        "sumunjang_kubernetes_diagnostic_source_fresh",
        "1 while the read-only Kubernetes policy diagnostic source is fresh.",
        u8::from(fresh),
    );
    out
}

pub async fn metrics(HttpState(app): HttpState<App>) -> Response {
    match tokio::task::spawn_blocking(move || render(&app)).await {
        Ok(body) => (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
