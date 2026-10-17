//! Router-level integration tests for the audit, explain and evidence APIs.
use crate::{App, actor, audit, tests::app};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;

const ADMIN: &str = "admin-test-token";
const COLLECTOR: &str = "collector-test-token";

struct Reply {
    status: StatusCode,
    body: Value,
    audit_id: Option<String>,
}
async fn call(app: &App, method: &str, path: &str, token: &str, body: Option<Value>) -> Reply {
    call_with(app, method, path, token, body, &[]).await
}
async fn call_with(
    app: &App,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> Reply {
    let mut builder = Request::builder()
        .uri(path)
        .method(method)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let response = crate::router(app.clone())
        .oneshot(builder.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let audit_id = response
        .headers()
        .get("x-sumunjang-audit-id")
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        audit_id,
    }
}
async fn entries(app: &App, query: &str) -> Vec<Value> {
    let r = call(app, "GET", &format!("/v1/audit{query}"), ADMIN, None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r.body["entries"].as_array().unwrap().clone()
}
async fn document(app: &App) -> Value {
    call(app, "GET", "/v1/policy/document", ADMIN, None)
        .await
        .body
}
async fn put_document(app: &App, policy: Value) -> Reply {
    let d = document(app).await;
    call(
        app,
        "PUT",
        "/v1/policy/document",
        ADMIN,
        Some(
            json!({"expected_revision": d["revision"], "policy": policy, "reason": "test change"}),
        ),
    )
    .await
}

#[tokio::test]
async fn every_admin_mutation_is_audited_with_actor_digests_and_summary() {
    let a = app();
    assert_eq!(
        call(&a, "GET", "/v1/audit", COLLECTOR, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&a, "POST", "/v1/audit/query", COLLECTOR, Some(json!({})))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let r = put_document(
        &a,
        json!({"mode":"enforce","threshold":10,"allow":["192.0.2.0/24"]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let first_id = r.audit_id.clone().unwrap();
    assert_eq!(
        call(
            &a,
            "PUT",
            "/v1/policy",
            ADMIN,
            Some(json!({"mode":"enforce","threshold":5}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let expires = crate::now() + 600;
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/blocks",
            ADMIN,
            Some(json!({"network":"203.0.113.0/24","expires_at":expires,"reason":"manual"}))
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &a,
            "DELETE",
            "/v1/blocks",
            ADMIN,
            Some(json!({"network":"203.0.113.0/24"}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let now = crate::now();
    assert_eq!(
        call(&a, "POST", "/v1/events", COLLECTOR, Some(json!({"source_id":"t","events":[{"ip":"198.51.100.7","kind":"honeypot","observed_at":now}]}))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/candidates/approve",
            ADMIN,
            Some(json!({"ip":"198.51.100.7"}))
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &a,
            "PUT",
            "/v1/rules",
            ADMIN,
            Some(
                json!({"version":1,"rules":[{"id":"r1","network":"198.18.0.0/15","action":"deny"}]})
            )
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        call(&a, "PUT", "/v1/rules/lua", ADMIN, Some(json!({"script":"return {version=1,rules={{id='lua1',network='198.18.0.0/16',action='observe'}}}"}))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &a,
            "PUT",
            "/v1/rules/lua",
            ADMIN,
            Some(json!({"script":"error('x')"}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&a, "POST", "/v1/geoip/reload", ADMIN, Some(json!({})))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        call(&a, "POST", "/v1/update/check", ADMIN, Some(json!({})))
            .await
            .status,
        StatusCode::CONFLICT
    );

    let all = entries(&a, "?limit=200").await;
    let actions: Vec<_> = all
        .iter()
        .rev()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        [
            "policy.document.replace",
            "policy.replace",
            "blocks.add",
            "blocks.remove",
            "candidates.approve",
            "rules.replace",
            "rules.lua.replace",
            "rules.lua.replace",
            "geoip.reload",
            "update.check"
        ]
    );
    let first = all.last().unwrap();
    assert_eq!(first["id"], first_id);
    assert_eq!(first["result"], "committed");
    assert_eq!(first["reason"], "test change");
    assert_eq!(first["actor"]["kind"], "credential");
    assert!(
        first["summary"]
            .as_str()
            .unwrap()
            .contains("mode observe -> enforce")
    );
    assert!(
        first["summary"]
            .as_str()
            .unwrap()
            .contains("allow +1: 192.0.2.0/24")
    );
    assert_ne!(first["before_digest"], first["after_digest"]);
    assert!(
        first["after_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(first["revision_after"].as_i64() > first["revision_before"].as_i64());
    assert_eq!(first["message_key"], "sumunjang.audit.result.committed");
    let block = all.iter().find(|e| e["action"] == "blocks.add").unwrap();
    assert_eq!(block["target"], "203.0.113.0/24");
    assert!(
        block["summary"]
            .as_str()
            .unwrap()
            .starts_with("block added 203.0.113.0/24")
    );
    let approve = all
        .iter()
        .find(|e| e["action"] == "candidates.approve")
        .unwrap();
    assert!(
        approve["summary"]
            .as_str()
            .unwrap()
            .contains("198.51.100.7/32")
    );
    let lua: Vec<_> = all
        .iter()
        .filter(|e| e["action"] == "rules.lua.replace")
        .collect();
    assert_eq!(lua[0]["result"], "refused");
    assert!(
        lua[0]["error"]
            .as_str()
            .unwrap()
            .contains("Lua compilation failed")
    );
    assert_eq!(lua[1]["result"], "committed");
    assert!(lua[1]["summary"].as_str().unwrap().contains("added lua1"));
    assert_eq!(all[0]["result"], "refused");

    // Filters, through the query string and through the broker-friendly POST.
    assert_eq!(entries(&a, "?action=rules.*").await.len(), 3);
    assert_eq!(entries(&a, "?result=refused").await.len(), 2);
    assert_eq!(
        entries(&a, "?actor=admin-credential&limit=200").await.len(),
        10
    );
    assert_eq!(entries(&a, "?actor=nobody").await.len(), 0);
    assert_eq!(
        entries(&a, &format!("?until={}", crate::now().saturating_sub(3600)))
            .await
            .len(),
        0
    );
    let r = call(
        &a,
        "POST",
        "/v1/audit/query",
        ADMIN,
        Some(json!({"action":"blocks.add"})),
    )
    .await;
    assert_eq!(r.body["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        call(&a, "GET", "/v1/audit?limit=0", ADMIN, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&a, "GET", "/v1/audit?result=maybe", ADMIN, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/audit/query",
            ADMIN,
            Some(json!({"bogus":1}))
        )
        .await
        .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Cursor pagination visits every row exactly once, newest first.
    let mut cursor: Option<String> = None;
    let mut ids = Vec::new();
    loop {
        let mut body = json!({"limit": 3});
        if let Some(c) = &cursor {
            body["cursor"] = json!(c);
        }
        let page = call(&a, "POST", "/v1/audit/query", ADMIN, Some(body))
            .await
            .body;
        ids.extend(
            page["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["id"].clone()),
        );
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(ids, all.iter().map(|e| e["id"].clone()).collect::<Vec<_>>());
}

#[tokio::test]
async fn refusals_are_recorded_and_reads_are_not() {
    let a = app();
    assert_eq!(
        put_document(&a, json!({"threshold":0})).await.status,
        StatusCode::BAD_REQUEST
    );
    let stale = call(
        &a,
        "PUT",
        "/v1/policy/document",
        ADMIN,
        Some(json!({"expected_revision":"stale","policy":{}})),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    for path in ["/v1/policy", "/v1/rules", "/v1/blocks", "/v1/status"] {
        call(&a, "GET", path, ADMIN, None).await;
    }
    let all = entries(&a, "").await;
    assert_eq!(all.len(), 2);
    assert!(
        all.iter()
            .all(|e| e["result"] == "refused" && e["before_digest"] == e["after_digest"])
    );
    assert!(
        all[0]["error"]
            .as_str()
            .unwrap()
            .starts_with("policy revision conflict")
    );
    assert_eq!(all[1]["error"], "invalid threshold");
}

#[tokio::test]
async fn audit_write_failure_fails_closed() {
    let a = app();
    let before = document(&a).await;
    a.db
        .lock()
        .unwrap()
        .execute_batch("CREATE TRIGGER audit_down BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")
        .unwrap();
    let r = put_document(&a, json!({"mode":"enforce"})).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(document(&a).await, before);
    assert_eq!(a.view.load().mode, guard_core::Mode::Observe);
    let checkpoint: Option<String> =
        a.db.lock()
            .unwrap()
            .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .ok();
    assert!(
        checkpoint.is_none(),
        "checkpoint committed without its audit row"
    );
    let expires = crate::now() + 600;
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/blocks",
            ADMIN,
            Some(json!({"network":"203.0.113.0/24","expires_at":expires,"reason":"x"}))
        )
        .await
        .status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        a.view
            .load()
            .query_ip("203.0.113.1".parse().unwrap(), crate::now())
            .reason,
        None
    );
    assert_eq!(
        call(&a, "POST", "/v1/geoip/reload", ADMIN, Some(json!({})))
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    a.db.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER audit_down")
        .unwrap();
    assert_eq!(
        put_document(&a, json!({"mode":"enforce"})).await.status,
        StatusCode::OK
    );
    assert_eq!(entries(&a, "").await.len(), 1);
}

#[tokio::test]
async fn row_retention_is_enforced_on_write() {
    let mut a = app();
    a.audit = audit::Retention {
        max_rows: 3,
        max_days: 1,
    };
    for threshold in 1..=6 {
        assert_eq!(
            put_document(&a, json!({"threshold": threshold}))
                .await
                .status,
            StatusCode::OK
        );
    }
    let r = call(&a, "GET", "/v1/audit", ADMIN, None).await.body;
    assert_eq!(r["entries"].as_array().unwrap().len(), 3);
    assert_eq!(r["retention"]["retained_rows"], 3);
    assert_eq!(r["retention"]["max_rows"], 3);
    assert!(
        r["entries"][0]["summary"]
            .as_str()
            .unwrap()
            .contains("threshold 5 -> 6")
    );
}

#[tokio::test]
async fn delegated_hangang_actor_is_verified_and_recorded() {
    let a = app();
    let body = json!({"version":1,"rules":[]});
    let bytes = body.to_string();
    let now = crate::now();
    let (assertion, mac) =
        actor::sign_for_test(ADMIN.as_bytes(), "PUT", "/v1/rules", bytes.as_bytes(), now);
    let headers = [
        ("x-hopae-delegation", assertion.clone()),
        ("x-hopae-delegation-mac", mac.clone()),
    ];
    let r = call_with(&a, "PUT", "/v1/rules", ADMIN, Some(body.clone()), &headers).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let e = &entries(&a, "").await[0];
    assert_eq!(e["actor"]["kind"], "delegated");
    assert_eq!(e["actor"]["name"], "operator");
    assert_eq!(e["actor"]["id"], 7);
    assert_eq!(e["actor"]["issuer"], "hangang");
    assert_eq!(e["actor"]["client_ip"], "192.0.2.10");
    assert_eq!(
        e["actor"]["request_sha256"],
        actor::sha256_hex(bytes.as_bytes())
    );
    assert_eq!(entries(&a, "?actor=operator").await.len(), 1);
    // Replay, body substitution, a lone header and a wrong key are refused.
    assert_eq!(
        call_with(&a, "PUT", "/v1/rules", ADMIN, Some(body.clone()), &headers)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let (assertion, mac) = actor::sign_for_test(
        ADMIN.as_bytes(),
        "PUT",
        "/v1/rules",
        bytes.as_bytes(),
        now + 1,
    );
    let other = json!({"version":1,"rules":[{"id":"x","network":"192.0.2.0/24","action":"deny"}]});
    assert_eq!(
        call_with(
            &a,
            "PUT",
            "/v1/rules",
            ADMIN,
            Some(other),
            &[
                ("x-hopae-delegation", assertion.clone()),
                ("x-hopae-delegation-mac", mac.clone())
            ]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call_with(
            &a,
            "PUT",
            "/v1/rules",
            ADMIN,
            Some(body.clone()),
            &[("x-hopae-delegation", assertion)]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    let (assertion, mac) = actor::sign_for_test(
        b"another-key-0123456789",
        "PUT",
        "/v1/rules",
        bytes.as_bytes(),
        now + 2,
    );
    assert_eq!(
        call_with(
            &a,
            "PUT",
            "/v1/rules",
            ADMIN,
            Some(body),
            &[
                ("x-hopae-delegation", assertion),
                ("x-hopae-delegation-mac", mac)
            ]
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert!(a.inner.lock().unwrap().engine.rules().rules.is_empty());
    assert_eq!(entries(&a, "").await.len(), 1);
    // Signed reads work too (the broker signs every dispatched call).
    let (assertion, mac) = actor::sign_for_test(ADMIN.as_bytes(), "GET", "/v1/audit", b"", now + 3);
    let r = call_with(
        &a,
        "GET",
        "/v1/audit",
        ADMIN,
        None,
        &[
            ("x-hopae-delegation", assertion),
            ("x-hopae-delegation-mac", mac),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

/// Published state with allowlist, rules (network, expired, observe, ASN via
/// catalog) and blocks (active, expired, automatic) for parity tests.
async fn rich_state(a: &App, mode: &str) {
    assert_eq!(
        put_document(
            a,
            json!({"mode": mode, "allow": ["192.0.2.64/26", "2001:db8:1::/48"]})
        )
        .await
        .status,
        StatusCode::OK
    );
    let now = crate::now();
    {
        let mut inner = a.inner.lock().unwrap();
        inner
            .engine
            .set_asn_catalog(vec![guard_core::AsnPrefix {
                network: "198.51.100.0/24".into(),
                asn: 64500,
            }])
            .unwrap();
        for (network, expires_at, reason) in [
            ("203.0.113.0/24", now + 600, "manual"),
            (
                "203.0.113.128/25",
                now + 600,
                guard_core::trace::AUTOMATIC_BLOCK_REASON,
            ),
            ("192.0.2.0/24", now + 900, "manual"),
            ("2001:db8::/32", now + 300, "v6"),
        ] {
            inner
                .engine
                .add_block(
                    guard_core::Block {
                        network: network.into(),
                        expires_at,
                        reason: reason.into(),
                        ..Default::default()
                    },
                    now,
                )
                .unwrap();
        }
        let view = inner.engine.decision_view();
        a.view.store(std::sync::Arc::new(view));
    }
    let rules = json!({"version":1,"rules":[
        {"id":"deny-net","priority":10,"network":"192.0.2.0/27","action":"deny","score":5},
        {"id":"allow-net","priority":20,"network":"192.0.2.0/29","action":"allow"},
        {"id":"observe-net","priority":30,"network":"203.0.113.0/26","action":"observe","score":2},
        {"id":"expired-deny","priority":40,"network":"192.0.2.32/27","action":"deny","expires_at":now - 10},
        {"id":"asn-deny","priority":5,"asns":[64500],"action":"deny"}]});
    assert_eq!(
        call(a, "PUT", "/v1/rules", ADMIN, Some(rules)).await.status,
        StatusCode::OK
    );
}
fn corpus() -> Vec<String> {
    let mut ips = Vec::new();
    for i in (0..=255).step_by(3) {
        ips.push(format!("192.0.2.{i}"));
        ips.push(format!("203.0.113.{i}"));
    }
    for i in 0..40 {
        ips.push(format!("198.51.100.{i}"));
        ips.push(format!("2001:db8:{i:x}::1"));
        ips.push(format!("::ffff:203.0.113.{}", i * 6));
    }
    ips.push("8.8.8.8".into());
    ips
}

#[tokio::test]
async fn explain_has_parity_with_live_decisions_for_many_addresses() {
    for mode in ["enforce", "observe"] {
        let a = app();
        rich_state(&a, mode).await;
        let ips = corpus();
        assert!(ips.len() > 200);
        let mut reasons = std::collections::BTreeSet::new();
        for ip in &ips {
            let live = call(
                &a,
                "POST",
                "/v1/decision",
                COLLECTOR,
                Some(json!({"source_id":"p","ip":ip})),
            )
            .await;
            assert_eq!(live.status, StatusCode::OK);
            let explained = call(&a, "POST", "/v1/explain", ADMIN, Some(json!({"ip": ip}))).await;
            assert_eq!(explained.status, StatusCode::OK, "{}", explained.body);
            let d = &explained.body["decision"];
            for field in ["action", "mode", "reason", "revision", "version"] {
                assert_eq!(d[field], live.body[field], "{mode} {ip} {field}");
            }
            assert!(
                d["ttl_ms"]
                    .as_u64()
                    .unwrap()
                    .abs_diff(live.body["ttl_ms"].as_u64().unwrap())
                    <= 1000
            );
            assert_eq!(explained.body["evaluated"]["source"], "published");
            reasons.insert(explained.body["reason_code"].as_str().unwrap().to_owned());
            let stages: Vec<_> = explained.body["stages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["stage"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(stages[0], "mode");
            assert!(
                stages.contains(&"outcome".to_owned())
                    && stages.ends_with(&["score".into(), "auto_block".into()])
            );
            if mode == "observe" {
                assert_eq!(explained.body["verdict"], "observe");
                let preview = &explained.body["enforce_preview"];
                assert_eq!(preview["decision"]["mode"], "enforce");
            }
        }
        if mode == "enforce" {
            for code in [
                "sumunjang.allow.allowlist",
                "sumunjang.allow.rule",
                "sumunjang.allow.default",
                "sumunjang.deny.rule",
                "sumunjang.deny.block_manual",
                "sumunjang.deny.block_automatic",
            ] {
                assert!(reasons.contains(code), "{code} missing from {reasons:?}");
            }
        } else {
            assert_eq!(
                reasons.into_iter().collect::<Vec<_>>(),
                ["sumunjang.observe.mode"]
            );
        }
    }
}

#[tokio::test]
async fn explain_trace_reports_stages_rules_and_blocks() {
    let a = app();
    rich_state(&a, "enforce").await;
    // Expired rule is matched but ignored; manual /24 block decides.
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"192.0.2.40"})),
    )
    .await
    .body;
    assert_eq!(r["schema"], "sumunjang.explain.v1");
    assert_eq!(r["reason_code"], "sumunjang.deny.block_manual");
    let stage = |name: &str| {
        r["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stage"] == name)
            .cloned()
            .unwrap()
    };
    assert_eq!(stage("allowlist")["matched"], false);
    assert_eq!(stage("rules")["expired"][0]["id"], "expired-deny");
    assert_eq!(stage("rules")["code"], "sumunjang.stage.rules.no_match");
    assert_eq!(stage("blocklist")["block"]["network"], "192.0.2.0/24");
    // Allowlist wins and reports the matched prefix.
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"192.0.2.70"})),
    )
    .await
    .body;
    assert_eq!(r["reason_code"], "sumunjang.allow.allowlist");
    assert_eq!(r["params"]["network"], "192.0.2.64/26");
    assert!(
        r["stages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["stage"] != "rules")
    );
    // Rule precedence: allow-net (20) beats deny-net (10); both listed.
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"192.0.2.3"})),
    )
    .await
    .body;
    assert_eq!(r["reason_code"], "sumunjang.allow.rule");
    assert_eq!(r["matched_rules"], json!(["allow-net", "deny-net"]));
    // ASN from the offline catalog matches the ASN rule.
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"198.51.100.4"})),
    )
    .await
    .body;
    assert_eq!(r["reason_code"], "sumunjang.deny.rule");
    let geo = r["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == "geo")
        .unwrap()
        .clone();
    assert_eq!(
        (geo["asn"].clone(), geo["asn_source"].clone()),
        (json!(64500), json!("catalog"))
    );
    // Observe rule winner continues to the automatic block.
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"203.0.113.130"})),
    )
    .await
    .body;
    assert_eq!(r["reason_code"], "sumunjang.deny.block_automatic");
    // Simulated geo, evidence and time are labelled; the future time expires blocks.
    let at = crate::now() + 3600;
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(
            json!({"ip":"203.0.113.200","at":at,"evidence":{"honeypot":2},"geo":{"country":"kr"}}),
        ),
    )
    .await
    .body;
    assert_eq!(
        r["simulated"],
        json!({"time":true,"geo":true,"evidence":true})
    );
    assert_eq!(r["decision"]["action"], "allow");
    let score = r["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == "score")
        .unwrap()
        .clone();
    assert_eq!(score["simulated_signal_score"], 20);
    assert_eq!(score["suspicion"], "suspicious");
}

#[tokio::test]
async fn candidate_what_if_is_validated_isolated_and_never_stored() {
    let a = app();
    rich_state(&a, "enforce").await;
    let before = document(&a).await;
    let audited = entries(&a, "").await.len();
    let candidate = json!({"policy": {"mode":"enforce","allow":["203.0.113.0/24"]}});
    let r = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"203.0.113.5","candidate":candidate})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["evaluated"]["source"], "candidate");
    assert_eq!(r.body["evaluated"]["stored"], false);
    assert!(
        r.body["evaluated"]["candidate_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(r.body["reason_code"], "sumunjang.allow.allowlist");
    let live = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"p","ip":"203.0.113.5"})),
    )
    .await;
    assert_eq!(live.body["action"], "deny");
    // Lua candidate rules use the same compiler as publication.
    let r = call(&a, "POST", "/v1/explain", ADMIN, Some(json!({"ip":"8.8.8.8","candidate":{"script":"return {version=1,rules={{id='g',network='8.8.8.0/24',action='deny'}}}"}}))).await;
    assert_eq!(r.body["reason_code"], "sumunjang.deny.rule");
    assert_eq!(r.body["evaluated"]["rules_source"], "lua");
    assert_eq!(document(&a).await, before);
    assert_eq!(entries(&a, "").await.len(), audited);
    // Validation errors carry JSON Pointers.
    for (body, path) in [
        (
            json!({"ip":"192.0.2.1","candidate":{"rules":{"version":1,"rules":[{"id":"a","network":"bad","action":"deny"}]}}}),
            "/candidate/rules/rules/0/network",
        ),
        (
            json!({"ip":"192.0.2.1","candidate":{"policy":{"bogus":1}}}),
            "/candidate/policy/bogus",
        ),
        (
            json!({"ip":"192.0.2.1","candidate":{"policy":{"threshold":"x"}}}),
            "/candidate/policy/threshold",
        ),
        (
            json!({"ip":"192.0.2.1","candidate":{"policy":{"window_secs":0}}}),
            "/candidate/policy/window_secs",
        ),
        (
            json!({"ip":"192.0.2.1","candidate":{"policy":{"allow":["x"]}}}),
            "/candidate/policy/allow/0",
        ),
        (
            json!({"ip":"192.0.2.1","candidate":{"script":"error('no')"}}),
            "/candidate/script",
        ),
        (json!({"ip":"192.0.2.1","candidate":{}}), "/candidate"),
        (json!({"ip":"not-an-ip"}), "/ip"),
        (
            json!({"ip":"192.0.2.1","evidence":{"honeypot":100000}}),
            "/evidence/honeypot",
        ),
        (json!({"ip":"192.0.2.1","at":1}), "/at"),
    ] {
        let r = call(&a, "POST", "/v1/explain", ADMIN, Some(body.clone())).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}");
        let paths: Vec<_> = r.body["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["path"].as_str().unwrap().to_owned())
            .collect();
        assert!(paths.iter().any(|p| p == path), "{body}: {paths:?}");
    }
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/explain",
            COLLECTOR,
            Some(json!({"ip":"192.0.2.1"}))
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn batch_impact_counts_changes_and_is_bounded() {
    let a = app();
    rich_state(&a, "enforce").await;
    let ips = [
        "203.0.113.5",
        "203.0.113.9",
        "8.8.8.8",
        "192.0.2.70",
        "198.51.100.1",
    ];
    let candidate = json!({"policy":{"mode":"enforce","allow":["203.0.113.0/28"]},
        "rules":{"version":1,"rules":[{"id":"g","network":"8.8.8.0/24","action":"deny"}]}});
    let r = call(
        &a,
        "POST",
        "/v1/explain/batch",
        ADMIN,
        Some(json!({"ips": ips, "candidate": candidate})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // 203.0.113.5/9 deny->allow; 8.8.8.8 allow->deny; 192.0.2.70 loses allowlist (deny by block);
    // 198.51.100.1 loses the ASN rule but stays allowed by default.
    assert_eq!(
        r.body["summary"],
        json!({"total":5,"changed":5,"allow_to_deny":2,"deny_to_allow":3,"reason_changed":0})
    );
    let unchanged = call(
        &a,
        "POST",
        "/v1/explain/batch",
        ADMIN,
        Some(json!({"ips": ["8.8.4.4"]})),
    )
    .await;
    assert!(unchanged.body["summary"].is_null());
    assert_eq!(
        unchanged.body["results"][0]["published"]["reason_code"],
        "sumunjang.allow.default"
    );
    let many: Vec<String> = (0..1025)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    let r = call(
        &a,
        "POST",
        "/v1/explain/batch",
        ADMIN,
        Some(json!({"ips": many})),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body["errors"][0]["path"], "/ips");
}

#[tokio::test]
async fn decision_evidence_is_additive_on_http() {
    let a = app();
    rich_state(&a, "enforce").await;
    let plain = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"p","ip":"192.0.2.3"})),
    )
    .await
    .body;
    assert!(plain.get("evidence").is_none());
    let r = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"p","ip":"192.0.2.3","evidence":true})),
    )
    .await
    .body;
    for field in ["action", "mode", "reason", "revision", "version"] {
        assert_eq!(r[field], plain[field]);
    }
    let e = &r["evidence"];
    assert_eq!(e["reason_code"], "sumunjang.allow.rule");
    assert_eq!(e["rules"], json!(["allow-net", "deny-net"]));
    assert_eq!(e["verdict"], "allow");
    assert_eq!(e["revision"], r["revision"]);
    let r = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"p","ip":"198.51.100.4","evidence":true})),
    )
    .await
    .body;
    assert_eq!(
        (
            r["evidence"]["asn"].clone(),
            r["evidence"]["reason_code"].clone()
        ),
        (json!(64500), json!("sumunjang.deny.rule"))
    );
    // Observe mode: verdict observe, with the enforce outcome alongside.
    let o = app();
    rich_state(&o, "observe").await;
    let r = call(
        &o,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"p","ip":"203.0.113.1","evidence":true})),
    )
    .await
    .body;
    assert_eq!(r["action"], "allow");
    assert_eq!(r["evidence"]["verdict"], "observe");
    assert_eq!(r["evidence"]["reason_code"], "sumunjang.observe.mode");
    assert_eq!(r["evidence"]["enforce"]["action"], "deny");
    assert_eq!(
        r["evidence"]["enforce"]["reason_code"],
        "sumunjang.deny.block_manual"
    );
    assert_eq!(r["evidence"]["block"], "203.0.113.0/24");
}

#[tokio::test]
async fn reason_catalog_is_served_with_identical_language_keys() {
    let a = app();
    let r = call(&a, "GET", "/v1/reasons", ADMIN, None).await.body;
    let en = r["messages"]["en"].as_object().unwrap();
    let ko = r["messages"]["ko"].as_object().unwrap();
    assert_eq!(en.keys().collect::<Vec<_>>(), ko.keys().collect::<Vec<_>>());
    for group in ["decision", "stage", "audit"] {
        for code in r["codes"][group].as_array().unwrap() {
            assert!(en.contains_key(code.as_str().unwrap()), "{code}");
        }
    }
}

// ----- console Network API gaps -----

async fn events(a: &App, ip: &str, kinds: &[&str]) {
    let now = crate::now();
    let events: Vec<Value> = kinds
        .iter()
        .map(|k| json!({"ip": ip, "kind": k, "observed_at": now}))
        .collect();
    let r = call(
        a,
        "POST",
        "/v1/events",
        COLLECTOR,
        Some(json!({"source_id":"t","events":events})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn signal_history_is_bounded_per_minute_and_queryable() {
    let a = app();
    events(
        &a,
        "198.51.100.7",
        &["honeypot", "scanner", "scanner", "auth_failure"],
    )
    .await;
    let r = call(
        &a,
        "POST",
        "/v1/history/query",
        ADMIN,
        Some(json!({"ip":"198.51.100.7"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let b = &r.body;
    assert_eq!(b["schema"], "sumunjang.history.v1");
    assert_eq!(b["bucket_secs"], 60);
    assert_eq!(b["retention_secs"], 6 * 3600);
    assert_eq!(b["buckets"].as_array().unwrap().len(), 1);
    assert_eq!(
        b["totals"]["signals"],
        json!({"honeypot":1,"scanner":2,"auth_failure":1,"invalid_request":0})
    );
    assert_eq!(b["totals"]["score"], 21);
    assert_eq!(b["window"]["signal_score"], 21);
    assert_eq!(b["stats"]["addresses"], 1);
    let g = call(&a, "GET", "/v1/history?ip=::ffff:198.51.100.7", ADMIN, None).await;
    assert_eq!(g.body["buckets"], b["buckets"]);
    let empty = call(&a, "GET", "/v1/history?ip=192.0.2.1", ADMIN, None).await;
    assert_eq!(empty.body["buckets"], json!([]));
    assert_eq!(
        call(&a, "GET", "/v1/history?ip=nope", ADMIN, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/history/query",
            ADMIN,
            Some(json!({"ip":"192.0.2.1","since":10,"until":5}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/history/query",
            COLLECTOR,
            Some(json!({"ip":"192.0.2.1"}))
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    // History survives a policy change that resets the evidence window.
    assert_eq!(
        put_document(&a, json!({"threshold": 50})).await.status,
        StatusCode::OK
    );
    let after = call(
        &a,
        "POST",
        "/v1/history/query",
        ADMIN,
        Some(json!({"ip":"198.51.100.7"})),
    )
    .await;
    assert_eq!(after.body["totals"]["score"], 21);
    assert_eq!(after.body["window"]["signal_score"], 0);
}

#[tokio::test]
async fn candidates_report_signal_counts_and_country() {
    let a = app();
    let paths = crate::geoip::GeoPaths {
        country: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/GeoIP2-Country-Test.mmdb"),
        ),
        asn: None,
    };
    a.geo.store(std::sync::Arc::new(
        crate::geoip::GeoCatalog::load(&paths).unwrap(),
    ));
    events(
        &a,
        "81.2.69.160",
        &["honeypot", "invalid_request", "invalid_request"],
    )
    .await;
    let c = call(&a, "GET", "/v1/candidates", ADMIN, None).await.body;
    assert_eq!(
        c[0]["signals"],
        json!({"honeypot":1,"scanner":0,"auth_failure":0,"invalid_request":2})
    );
    assert_eq!(c[0]["country"], "GB");
    assert_eq!(c[0]["events"], 3);
}

#[tokio::test]
async fn blocks_carry_provenance_and_change_reasons_are_audited() {
    let a = app();
    let expires = crate::now() + 600;
    let now = crate::now();
    let body = json!({"network":"203.0.113.0/24","expires_at":expires,"reason":"abuse report 42"});
    let bytes = body.to_string();
    let (assertion, mac) = actor::sign_for_test(
        ADMIN.as_bytes(),
        "POST",
        "/v1/blocks",
        bytes.as_bytes(),
        now,
    );
    let r = call_with(
        &a,
        "POST",
        "/v1/blocks",
        ADMIN,
        Some(body),
        &[
            ("x-hopae-delegation", assertion),
            ("x-hopae-delegation-mac", mac),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    // Provenance cannot be supplied by the client.
    assert_eq!(
        call(&a, "POST", "/v1/blocks", ADMIN, Some(json!({"network":"192.0.2.0/24","expires_at":expires,"reason":"x","origin":{"source":"auto"}}))).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    put_document(&a, json!({"mode":"enforce"})).await;
    events(&a, "198.51.100.9", &["honeypot"]).await;
    let r = call(
        &a,
        "POST",
        "/v1/candidates/approve",
        ADMIN,
        Some(json!({"ip":"198.51.100.9","reason":"reviewed honeypot hit"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["source"], "approved");
    let blocks = call(&a, "GET", "/v1/blocks", ADMIN, None).await.body;
    let find = |n: &str| {
        blocks
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["network"] == n)
            .unwrap()
            .clone()
    };
    let manual = find("203.0.113.0/24");
    assert_eq!(
        (manual["source"].clone(), manual["created_by"].clone()),
        (json!("manual"), json!("operator"))
    );
    assert!(manual["created_at"].as_u64().unwrap() >= now);
    assert_eq!(find("198.51.100.9/32")["source"], "approved");
    assert_eq!(find("198.51.100.9/32")["created_by"], "admin-credential");
    let r = call(
        &a,
        "DELETE",
        "/v1/blocks",
        ADMIN,
        Some(json!({"network":"203.0.113.0/24","reason":"false positive"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let all = entries(&a, "?limit=200").await;
    let reason =
        |action: &str| all.iter().find(|e| e["action"] == action).unwrap()["reason"].clone();
    assert_eq!(reason("blocks.add"), "abuse report 42");
    assert_eq!(reason("candidates.approve"), "reviewed honeypot hit");
    assert_eq!(reason("blocks.remove"), "false positive");
    // Provenance survives restart (checkpoint restore).
    let body: String =
        a.db.lock()
            .unwrap()
            .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .unwrap();
    let restored = guard_core::Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
    assert_eq!(
        restored.blocks().next().unwrap().origin.source,
        guard_core::BlockSource::Approved
    );
}

#[tokio::test]
async fn rules_compare_and_set_lua_source_and_legacy_writes() {
    let a = app();
    let d = call(&a, "GET", "/v1/rules/document", ADMIN, None)
        .await
        .body;
    assert_eq!(
        (d["source"].clone(), d["script"].clone()),
        (json!("json"), Value::Null)
    );
    let rules = json!({"version":1,"rules":[{"id":"a","network":"192.0.2.0/24","action":"deny"}]});
    let ok = call(
        &a,
        "PUT",
        "/v1/rules",
        ADMIN,
        Some(json!({"expected_revision":d["revision"],"rules":rules,"reason":"ticket 7"})),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    assert_ne!(ok.body["revision"], d["revision"]);
    let stale = call(
        &a,
        "PUT",
        "/v1/rules",
        ADMIN,
        Some(json!({"expected_revision":d["revision"],"rules":{"version":1,"rules":[]}})),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["current_revision"], ok.body["revision"]);
    assert_eq!(a.inner.lock().unwrap().engine.rules().rules.len(), 1);
    // Lua with CAS keeps the source for the editor.
    let script = "return {version=1,rules={{id='l',network='198.51.100.0/24',action='observe'}}}";
    let lua = call(
        &a,
        "PUT",
        "/v1/rules/lua",
        ADMIN,
        Some(json!({"script":script,"expected_revision":ok.body["revision"],"reason":"lua move"})),
    )
    .await;
    assert_eq!(lua.status, StatusCode::OK, "{}", lua.body);
    assert_eq!(
        (lua.body["source"].clone(), lua.body["script"].clone()),
        (json!("lua"), json!(script))
    );
    let stale = call(
        &a,
        "PUT",
        "/v1/rules/lua",
        ADMIN,
        Some(json!({"script":script,"expected_revision":ok.body["revision"]})),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["current_revision"], lua.body["revision"]);
    let body: String =
        a.db.lock()
            .unwrap()
            .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .unwrap();
    assert_eq!(
        guard_core::Engine::restore(serde_json::from_str(&body).unwrap())
            .unwrap()
            .rules_script(),
        Some(script)
    );
    // Legacy unconditional writes still work and return the bare RuleSet.
    let legacy = call(
        &a,
        "PUT",
        "/v1/rules",
        ADMIN,
        Some(json!({"version":1,"rules":[]})),
    )
    .await;
    assert_eq!(
        (legacy.status, legacy.body.clone()),
        (StatusCode::OK, json!({"version":1,"rules":[]}))
    );
    let legacy_lua = call(
        &a,
        "PUT",
        "/v1/rules/lua",
        ADMIN,
        Some(json!({"script":script})),
    )
    .await;
    assert_eq!(legacy_lua.body["rules"][0]["id"], "l");
    assert_eq!(
        call(&a, "GET", "/v1/rules/document", ADMIN, None)
            .await
            .body["script"],
        script
    );
    assert_eq!(
        call(
            &a,
            "PUT",
            "/v1/rules",
            ADMIN,
            Some(json!({"expected_revision":"x","rules":rules,"bogus":1}))
        )
        .await
        .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let all = entries(&a, "?action=rules.*&limit=200").await;
    assert!(
        all.iter()
            .any(|e| e["reason"] == "ticket 7" && e["result"] == "committed")
    );
    assert!(all.iter().any(|e| e["reason"] == "lua move"));
    assert_eq!(all.iter().filter(|e| e["result"] == "refused").count(), 2);
}

#[tokio::test]
async fn asn_catalog_lists_prefixes_per_asn_with_cursor() {
    let a = app();
    {
        let mut inner = a.inner.lock().unwrap();
        let mut prefixes = vec![];
        for i in 0..5u32 {
            prefixes.push(guard_core::AsnPrefix {
                network: format!("198.51.{i}.0/24"),
                asn: 64500,
            });
        }
        prefixes.push(guard_core::AsnPrefix {
            network: "2001:db8::/32".into(),
            asn: 64501,
        });
        prefixes.push(guard_core::AsnPrefix {
            network: "192.0.2.0/24".into(),
            asn: 13,
        });
        inner.engine.set_asn_catalog(prefixes).unwrap();
    }
    let r = call(
        &a,
        "POST",
        "/v1/asn/catalog/query",
        ADMIN,
        Some(json!({"limit":3})),
    )
    .await
    .body;
    assert_eq!(
        (r["total_prefixes"].clone(), r["total_asns"].clone()),
        (json!(7), json!(3))
    );
    assert_eq!(
        r["entries"],
        json!([{"asn":13,"prefixes":["192.0.2.0/24"]},{"asn":64500,"prefixes":["198.51.0.0/24","198.51.1.0/24"]}])
    );
    let mut cursor = r["next_cursor"].clone();
    let mut seen = 3;
    while let Some(c) = cursor.as_str() {
        let p = call(
            &a,
            "POST",
            "/v1/asn/catalog/query",
            ADMIN,
            Some(json!({"limit":3,"cursor":c})),
        )
        .await
        .body;
        seen += p["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["prefixes"].as_array().unwrap().len())
            .sum::<usize>();
        cursor = p["next_cursor"].clone();
    }
    assert_eq!(seen, 7);
    let one = call(&a, "GET", "/v1/asn/catalog?asn=64500&limit=10", ADMIN, None)
        .await
        .body;
    assert_eq!(one["entries"].as_array().unwrap().len(), 1);
    assert_eq!(one["entries"][0]["prefixes"].as_array().unwrap().len(), 5);
    assert!(one["next_cursor"].is_null());
    assert_eq!(
        call(&a, "GET", "/v1/asn/catalog?asn=1", ADMIN, None)
            .await
            .body["entries"],
        json!([])
    );
    assert_eq!(
        call(&a, "GET", "/v1/asn/catalog?limit=0", ADMIN, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&a, "GET", "/v1/asn/catalog?cursor=zz", ADMIN, None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn allowlist_entries_expire_and_use_compare_and_set() {
    let a = app();
    put_document(&a, json!({"mode":"enforce","allow":["192.0.2.0/24"]})).await;
    let expires = crate::now() + 300;
    {
        let now = crate::now();
        let mut inner = a.inner.lock().unwrap();
        inner
            .engine
            .add_block(
                guard_core::Block {
                    network: "198.51.100.0/24".into(),
                    expires_at: now + 600,
                    reason: "x".into(),
                    ..Default::default()
                },
                now,
            )
            .unwrap();
        let view = inner.engine.decision_view();
        a.view.store(std::sync::Arc::new(view));
    }
    let list = call(&a, "GET", "/v1/allowlist", ADMIN, None).await.body;
    assert_eq!(list["entries"][0]["network"], "192.0.2.0/24");
    let added = call(&a, "POST", "/v1/allowlist", ADMIN, Some(json!({"expected_revision":list["revision"],"network":"198.51.100.7/24","expires_at":expires,"reason":"partner test"}))).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.body);
    let entry = added.body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["network"] == "198.51.100.0/24")
        .unwrap()
        .clone();
    assert_eq!(
        (
            entry["expires_at"].clone(),
            entry["reason"].clone(),
            entry["expired"].clone()
        ),
        (json!(expires), json!("partner test"), json!(false))
    );
    let live = |ip: &str| {
        a.view
            .load()
            .query_ip(ip.parse().unwrap(), crate::now())
            .action
    };
    assert_eq!(live("198.51.100.1"), "allow");
    assert_eq!(
        a.view
            .load()
            .query_ip("198.51.100.1".parse().unwrap(), expires)
            .action,
        "deny"
    );
    // Stale revision is refused with the current one.
    let stale = call(
        &a,
        "POST",
        "/v1/allowlist",
        ADMIN,
        Some(json!({"expected_revision":list["revision"],"network":"10.0.0.0/8"})),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["current_revision"], added.body["revision"]);
    assert_eq!(call(&a, "POST", "/v1/allowlist", ADMIN, Some(json!({"expected_revision":added.body["revision"],"network":"10.0.0.0/8","expires_at":1}))).await.status, StatusCode::BAD_REQUEST);
    // The policy document exposes allow_meta; a legacy write without it keeps expiries.
    let d = document(&a).await;
    assert_eq!(
        d["policy"]["allow_meta"]["198.51.100.0/24"]["expires_at"],
        expires
    );
    let mut legacy = d["policy"].clone();
    legacy.as_object_mut().unwrap().remove("allow_meta");
    legacy["threshold"] = json!(30);
    assert_eq!(put_document(&a, legacy).await.status, StatusCode::OK);
    assert_eq!(
        document(&a).await["policy"]["allow_meta"]["198.51.100.0/24"]["reason"],
        "partner test"
    );
    let snapshot_allow = a.inner.lock().unwrap().engine.snapshot(expires).allow;
    assert_eq!(snapshot_allow, ["192.0.2.0/24"]);
    let rev = call(&a, "GET", "/v1/allowlist", ADMIN, None).await.body["revision"].clone();
    let removed = call(
        &a,
        "DELETE",
        "/v1/allowlist",
        ADMIN,
        Some(json!({"expected_revision":rev,"network":"198.51.100.0/24","reason":"partner done"})),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK);
    assert_eq!(live("198.51.100.1"), "deny");
    assert!(document(&a).await["policy"].get("allow_meta").is_none());
    let rev = removed.body["revision"].clone();
    assert_eq!(
        call(
            &a,
            "DELETE",
            "/v1/allowlist",
            ADMIN,
            Some(json!({"expected_revision":rev,"network":"198.51.100.0/24"}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    let all = entries(&a, "?action=allowlist.*").await;
    assert_eq!(all.iter().filter(|e| e["result"] == "committed").count(), 2);
    assert!(
        all.iter()
            .any(|e| e["reason"] == "partner done" && e["target"] == "198.51.100.0/24")
    );
    assert!(all.iter().any(|e| e["result"] == "refused"));
}

#[tokio::test]
async fn allowlist_writes_keep_evidence_and_expired_entries_are_pruned_with_audit() {
    let mut a = app();
    events(&a, "198.51.100.7", &["honeypot"]).await;
    let rev = call(&a, "GET", "/v1/allowlist", ADMIN, None).await.body["revision"].clone();
    let r = call(&a, "POST", "/v1/allowlist", ADMIN, Some(json!({"expected_revision":rev,"network":"203.0.113.0/24","expires_at":crate::now()+60,"reason":"incident"}))).await;
    assert_eq!(r.status, StatusCode::OK);
    let c = call(&a, "GET", "/v1/candidates", ADMIN, None).await.body;
    assert_eq!(
        c[0]["score"], 10,
        "allowlist write must keep the evidence window"
    );
    // A policy-document write whose only change is the allowlist also keeps it.
    let d = document(&a).await;
    let mut p = d["policy"].clone();
    p["allow"]
        .as_array_mut()
        .unwrap()
        .push(json!("192.0.2.0/24"));
    assert_eq!(put_document(&a, p).await.status, StatusCode::OK);
    assert_eq!(
        call(&a, "GET", "/v1/candidates", ADMIN, None).await.body[0]["score"],
        10
    );
    // Expired beyond retention: removed by the maintenance job, audited.
    {
        let mut inner = a.inner.lock().unwrap();
        let mut policy = inner.engine.policy().clone();
        policy
            .allow_meta
            .get_mut("203.0.113.0/24")
            .unwrap()
            .expires_at = Some(crate::now() - 100);
        inner.engine.set_policy(policy).unwrap();
    }
    a.allow_expired_keep = 1000;
    crate::console_api::prune_expired_allow(a.clone()).await;
    let list = call(&a, "GET", "/v1/allowlist", ADMIN, None).await.body;
    let expired = list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["network"] == "203.0.113.0/24")
        .unwrap()
        .clone();
    assert_eq!(expired["expired"], true, "kept visible within retention");
    a.allow_expired_keep = 50;
    crate::console_api::prune_expired_allow(a.clone()).await;
    let list = call(&a, "GET", "/v1/allowlist", ADMIN, None).await.body;
    assert_eq!(list["entries"].as_array().unwrap().len(), 1);
    let e = &entries(&a, "?action=allowlist.expire").await[0];
    assert_eq!(
        (
            e["actor"]["kind"].clone(),
            e["result"].clone(),
            e["target"].clone()
        ),
        (json!("system"), json!("committed"), json!("203.0.113.0/24"))
    );
    assert_eq!(
        call(&a, "GET", "/v1/candidates", ADMIN, None).await.body[0]["score"],
        10
    );
    let h = call(
        &a,
        "POST",
        "/v1/history/query",
        ADMIN,
        Some(json!({"ip":"198.51.100.7"})),
    )
    .await
    .body;
    assert_eq!(h["in_memory"], true);
    assert!(h["retained_since"].as_u64().unwrap() <= crate::now());
}

// ----- network zones -----

async fn zones(a: &App) -> Value {
    call(a, "GET", "/v1/zones", ADMIN, None).await.body
}
async fn upsert_zone(a: &App, zone: Value) -> Reply {
    let rev = zones(a).await["revision"].clone();
    call(
        a,
        "POST",
        "/v1/zones",
        ADMIN,
        Some(json!({"expected_revision": rev, "zone": zone, "reason": "zone change"})),
    )
    .await
}

#[tokio::test]
async fn zones_crud_uses_compare_and_set_reason_and_audit() {
    let a = app();
    assert_eq!(zones(&a).await["revision"], 0);
    assert_eq!(
        call(&a, "GET", "/v1/zones", COLLECTOR, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let r = upsert_zone(
        &a,
        json!({"id":"corp","display_name":"Corporate","owner":"netops","description":"HQ and VPN",
        "prefixes":["10.0.0.1/8","2001:db8::/32"]}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["revision"], 1);
    assert_eq!(
        r.body["zones"][0]["prefixes"],
        json!(["10.0.0.0/8", "2001:db8::/32"])
    );
    assert_eq!(r.body["zones"][0]["updated_by"], "admin-credential");
    // Server-stamped provenance in the body is ignored and overwritten.
    let r = upsert_zone(
        &a,
        json!({"id":"office","prefixes":["10.1.0.0/16"],"updated_by":"spoof"}),
    )
    .await;
    assert_eq!(r.body["zones"][1]["updated_by"], "admin-credential");
    // Stale revision → 409 with current revision, unchanged.
    let stale = call(
        &a,
        "POST",
        "/v1/zones",
        ADMIN,
        Some(json!({"expected_revision":1,"zone":{"id":"x","prefixes":["192.0.2.0/24"]}})),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["current_revision"], "2");
    // Validation paths.
    let bad = upsert_zone(
        &a,
        json!({"id":"bad id","prefixes":["10.0.0.0/8","10.0.0.1/8","nope"]}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let paths: Vec<_> = bad.body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(paths, ["/zone/id", "/zone/prefixes/1", "/zone/prefixes/2"]);
    assert_eq!(
        upsert_zone(&a, json!({"id":"empty","prefixes":[]}))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // Removal through POST {remove} (broker) and DELETE (direct API).
    let rev = zones(&a).await["revision"].clone();
    let r = call(
        &a,
        "POST",
        "/v1/zones",
        ADMIN,
        Some(json!({"expected_revision":rev,"remove":"office","reason":"merged"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let rev = r.body["revision"].clone();
    assert_eq!(
        call(
            &a,
            "DELETE",
            "/v1/zones",
            ADMIN,
            Some(json!({"expected_revision":rev,"id":"office"}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/zones",
            ADMIN,
            Some(json!({"expected_revision":rev}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    let all = entries(&a, "?action=zones.*&limit=200").await;
    let committed: Vec<_> = all.iter().filter(|e| e["result"] == "committed").collect();
    assert_eq!(committed.len(), 3);
    assert_eq!(committed[0]["action"], "zones.remove");
    assert_eq!(committed[0]["reason"], "merged");
    assert!(
        committed[2]["summary"]
            .as_str()
            .unwrap()
            .contains("added corp")
    );
    assert_eq!(committed[2]["reason"], "zone change");
    assert!(all.iter().any(|e| {
        e["result"] == "refused"
            && e["error"]
                .as_str()
                .unwrap()
                .starts_with("zone revision conflict")
    }));
    // Persisted with the checkpoint.
    let body: String =
        a.db.lock()
            .unwrap()
            .query_row("SELECT body FROM checkpoint WHERE id=1", [], |r| r.get(0))
            .unwrap();
    let restored = guard_core::Engine::restore(serde_json::from_str(&body).unwrap()).unwrap();
    assert_eq!(restored.zones().revision, 3);
    assert!(restored.zones().zones.contains_key("corp"));
}

#[tokio::test]
async fn zone_snapshot_matches_the_pumgye_contract_and_membership_is_reported() {
    let a = app();
    upsert_zone(
        &a,
        json!({"id":"corp","display_name":"Corporate","prefixes":["10.0.0.0/8"]}),
    )
    .await;
    upsert_zone(
        &a,
        json!({"id":"legacy.reports.0","prefixes":["10.1.2.0/24","::ffff:192.0.2.0/120"]}),
    )
    .await;
    let r = call(&a, "GET", "/v1/zones/snapshot", ADMIN, None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body,
        json!({"revision":2,"zones":{"corp":{"prefixes":["10.0.0.0/8"]},
        "legacy.reports.0":{"prefixes":["10.1.2.0/24","192.0.2.0/24"]}}})
    );
    let lookup = call(
        &a,
        "POST",
        "/v1/zones/lookup",
        ADMIN,
        Some(json!({"ip":"10.1.2.3"})),
    )
    .await
    .body;
    assert_eq!(lookup["zones"], json!(["corp", "legacy.reports.0"]));
    assert_eq!(lookup["revision"], 2);
    // Explain stage and HTTP evidence carry the same zones.
    let e = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"10.1.2.3"})),
    )
    .await
    .body;
    assert_eq!(e["stages"][1]["stage"], "zone");
    assert_eq!(e["stages"][1]["zones"], json!(["corp", "legacy.reports.0"]));
    assert_eq!(e["stages"][1]["code"], "sumunjang.stage.zone.match");
    let none = call(
        &a,
        "POST",
        "/v1/explain",
        ADMIN,
        Some(json!({"ip":"8.8.8.8"})),
    )
    .await
    .body;
    assert_eq!(none["stages"][1]["code"], "sumunjang.stage.zone.none");
    let d = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"t","ip":"192.0.2.9","evidence":true})),
    )
    .await
    .body;
    assert_eq!(d["evidence"]["zones"], json!(["legacy.reports.0"]));
    assert_eq!(d["evidence"]["zone_revision"], 2);
    let b = call(
        &a,
        "POST",
        "/v1/explain/batch",
        ADMIN,
        Some(json!({"ips":["10.9.9.9"]})),
    )
    .await
    .body;
    assert_eq!(b["results"][0]["published"]["zones"], json!(["corp"]));
    // Zones never change the decision.
    let plain = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"t","ip":"10.1.2.3"})),
    )
    .await
    .body;
    assert_eq!(plain["action"], "allow");
    assert!(plain.get("evidence").is_none());
}

#[tokio::test]
async fn readiness_reflects_checkpoint_health_and_status_reports_tls() {
    let a = app();
    let probe = |a: &App| {
        let a = a.clone();
        async move {
            crate::router(a)
                .oneshot(
                    Request::builder()
                        .uri("/readyz")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(probe(&a).await, StatusCode::OK);
    a.db.lock()
        .unwrap()
        .execute_batch("DROP TABLE checkpoint")
        .unwrap();
    assert!(crate::checkpoint(a.clone()).await.is_err());
    assert_eq!(probe(&a).await, StatusCode::SERVICE_UNAVAILABLE);
    let s = call(&a, "GET", "/v1/status", ADMIN, None).await.body;
    assert_eq!(
        (s["ready"].clone(), s["not_ready_reason"].clone()),
        (json!(false), json!("checkpoint failing"))
    );
    assert_eq!(s["tls"]["enabled"], false);
    a.db.lock()
        .unwrap()
        .execute_batch("CREATE TABLE checkpoint(id INTEGER PRIMARY KEY,body TEXT NOT NULL)")
        .unwrap();
    crate::checkpoint(a.clone()).await.unwrap();
    assert_eq!(probe(&a).await, StatusCode::OK);
}

#[tokio::test]
async fn metrics_endpoint_is_authorized_bounded_and_counts_decisions() {
    async fn scrape(a: &App, token: Option<&str>) -> (StatusCode, String, Option<String>) {
        let mut b = Request::builder().uri("/metrics");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let r = crate::router(a.clone())
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = r.status();
        let ct = r
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap(), ct)
    }
    let a = app();
    for token in [None, Some(COLLECTOR), Some("wrong-token-0123456789")] {
        assert_eq!(scrape(&a, token).await.0, StatusCode::UNAUTHORIZED);
    }
    let series = |text: &str, name: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    let key = "sumunjang_decisions_total{transport=\"http\",mode=\"enforce\",outcome=\"deny\",reason=\"sumunjang.deny.rule\"}";
    let before = series(&scrape(&a, Some("metrics-test-token")).await.1, key);
    put_document(&a, json!({"mode":"enforce"})).await;
    call(
        &a,
        "PUT",
        "/v1/rules",
        ADMIN,
        Some(json!({"version":1,"rules":[{"id":"r","network":"192.0.2.0/24","action":"deny"}]})),
    )
    .await;
    upsert_zone(&a, json!({"id":"corp","prefixes":["10.0.0.0/8"]})).await;
    for _ in 0..3 {
        call(
            &a,
            "POST",
            "/v1/decision",
            COLLECTOR,
            Some(json!({"source_id":"t","ip":"192.0.2.77"})),
        )
        .await;
    }
    let (status, text, ct) = scrape(&a, Some("metrics-test-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ct.as_deref(),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    assert!(series(&text, key) >= before + 3, "{text}");
    for needle in [
        "sumunjang_decision_duration_seconds_bucket{transport=\"http\",le=\"+Inf\"}",
        "sumunjang_rules 1",
        "sumunjang_zones 1",
        "sumunjang_policy_enforce 1",
        "sumunjang_tls_enabled 0",
        "sumunjang_kubernetes_authority_enabled 0",
        "sumunjang_allowlist_entries{state=\"active\"} 0",
        "sumunjang_history_buckets",
        "sumunjang_admin_changes_total{result=\"committed\"}",
        "sumunjang_checkpoints_total{result=\"failure\"}",
        "sumunjang_ready 1",
    ] {
        assert!(text.contains(needle), "missing {needle}");
    }
    // No addresses, rule ids or zone names as label values.
    for leak in ["192.0.2", "10.0.0.0", "corp", "\"r\""] {
        assert!(!text.contains(leak), "leaked {leak}");
    }
    assert_eq!(scrape(&a, Some(ADMIN)).await.0, StatusCode::OK);
}

// ----- ASN bundles and proposals -----

fn bundle_key() -> (ed25519_dalek::SigningKey, guard_update::update::TrustKey) {
    use base64::Engine as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let trust = guard_update::update::TrustKey::from_base64(
        &base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
    (key, trust)
}
fn bundle(key: &ed25519_dalek::SigningKey, version: u64, prefixes: &[(&str, u32)]) -> Vec<u8> {
    let payload = json!({"format":"sumunjang.asn-bundle.v1","version":version,"created_at":crate::now(),
        "source":"test-provider","provenance":{"dataset":"fixture"},
        "prefixes": prefixes.iter().map(|(n,a)| json!({"network":n,"asn":a})).collect::<Vec<_>>()});
    guard_update::signed_bundle::sign(
        crate::asn::BUNDLE_DOMAIN,
        payload.to_string().as_bytes(),
        key,
        1 << 24,
    )
    .unwrap()
}
async fn put_bundle(a: &App, body: Vec<u8>) -> Reply {
    let r = crate::router(a.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/asn/bundle")
                .method("PUT")
                .header("authorization", format!("Bearer {ADMIN}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap();
    Reply {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        audit_id: None,
    }
}
fn asn_app() -> (App, ed25519_dalek::SigningKey) {
    let (key, trust) = bundle_key();
    let mut a = app();
    a.asn = crate::asn::AsnState::new(Some(trust), None, None, 3600, 1);
    (a, key)
}

#[tokio::test]
async fn signed_asn_bundles_install_diff_refuse_downgrade_and_roll_back() {
    let (a, key) = asn_app();
    let v1 = bundle(
        &key,
        1,
        &[("198.51.100.0/24", 64500), ("203.0.113.0/24", 64500)],
    );
    let r = put_bundle(&a, v1.clone()).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        (r.body["changed"].clone(), r.body["diff"]["added"].clone()),
        (json!(true), json!(2))
    );
    assert_eq!(a.inner.lock().unwrap().engine.asn_catalog().len(), 2);
    assert_eq!(put_bundle(&a, v1).await.body["changed"], false);
    // Tampered, wrong key and downgrade are refused.
    let mut env: Value = serde_json::from_slice(&bundle(&key, 5, &[("192.0.2.0/24", 1)])).unwrap();
    env["signature"] = json!(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [0u8; 64]
    ));
    assert_eq!(
        put_bundle(&a, serde_json::to_vec(&env).unwrap())
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    assert_eq!(
        put_bundle(&a, bundle(&other, 6, &[("192.0.2.0/24", 1)]))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    let r = put_bundle(
        &a,
        bundle(
            &key,
            2,
            &[("198.51.100.0/24", 64501), ("2001:db8::/32", 64500)],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        (
            r.body["diff"]["added"].clone(),
            r.body["diff"]["removed"].clone(),
            r.body["diff"]["reassigned"].clone()
        ),
        (json!(1), json!(1), json!(1))
    );
    assert_eq!(
        put_bundle(&a, bundle(&key, 1, &[("192.0.2.0/24", 1)]))
            .await
            .status,
        StatusCode::CONFLICT
    );
    // Rollback to last-good v1 (CAS on the installed version).
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/asn/bundle/rollback",
            ADMIN,
            Some(json!({"expected_version":1,"reason":"bad data"}))
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let r = call(
        &a,
        "POST",
        "/v1/asn/bundle/rollback",
        ADMIN,
        Some(json!({"expected_version":2,"reason":"bad data"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["version"], 1);
    assert_eq!(
        a.inner
            .lock()
            .unwrap()
            .engine
            .asn_catalog()
            .iter()
            .filter(|p| p.asn == 64500)
            .count(),
        2
    );
    // The rolled-back version cannot come back; a newer one can.
    assert_eq!(
        put_bundle(&a, bundle(&key, 2, &[("192.0.2.0/24", 1)]))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put_bundle(&a, bundle(&key, 3, &[("192.0.2.0/24", 7)]))
            .await
            .status,
        StatusCode::OK
    );
    let g = call(&a, "GET", "/v1/asn/bundle", ADMIN, None).await.body;
    assert_eq!(g["current"]["version"], 3);
    assert_eq!(g["current"]["source"], "test-provider");
    let states: Vec<_> = g["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h["version"].as_u64().unwrap(),
                h["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        states,
        [(2, "rolled_back".to_owned()), (1, "previous".to_owned())]
    );
    let actions: Vec<_> = entries(&a, "?action=asn.*&limit=200")
        .await
        .iter()
        .filter(|e| e["result"] == "committed")
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        actions,
        [
            "asn.bundle.install",
            "asn.bundle.rollback",
            "asn.bundle.install",
            "asn.bundle.install"
        ]
    );
    // The installed bundle survives restart from the database.
    {
        let db = a.db.lock().unwrap();
        let mut fresh = guard_core::Engine::new(guard_core::Policy::default()).unwrap();
        assert_eq!(
            crate::asn::load_installed(&db, &mut fresh, None).unwrap(),
            Some(3)
        );
        assert_eq!(fresh.asn_catalog()[0].asn, 7);
    }
    // Refresh without a configured URL is refused.
    assert_eq!(
        call(&a, "POST", "/v1/asn/refresh", ADMIN, Some(json!({})))
            .await
            .status,
        StatusCode::CONFLICT
    );
    let (b, _) = (app(), ());
    assert_eq!(
        put_bundle(&b, bundle(&key, 1, &[("192.0.2.0/24", 1)]))
            .await
            .status,
        StatusCode::CONFLICT,
        "no key configured"
    );
}

async fn proposal_fixture() -> App {
    let (a, key) = asn_app();
    put_bundle(
        &a,
        bundle(
            &key,
            1,
            &[
                ("198.51.100.0/24", 64500),
                ("203.0.113.0/24", 64500),
                ("2001:db8::/32", 64501),
            ],
        ),
    )
    .await;
    put_document(&a, json!({"mode":"enforce","allow":["203.0.113.128/25"]})).await;
    upsert_zone(&a, json!({"id":"partner","prefixes":["198.51.100.0/25"]})).await;
    events(&a, "198.51.100.7", &["honeypot"]).await;
    events(&a, "203.0.113.9", &["scanner"]).await;
    a
}
async fn act(a: &App, id: &str, body: Value, headers: &[(&str, String)]) -> Reply {
    call_with(
        a,
        "POST",
        &format!("/v1/asn/proposals/{id}"),
        ADMIN,
        Some(body),
        headers,
    )
    .await
}
fn delegated(path: &str, body: &Value, ts_offset: u64) -> Vec<(&'static str, String)> {
    let (assertion, mac) = actor::sign_for_test(
        ADMIN.as_bytes(),
        "POST",
        path,
        body.to_string().as_bytes(),
        crate::now() + ts_offset,
    );
    vec![
        ("x-hopae-delegation", assertion),
        ("x-hopae-delegation-mac", mac),
    ]
}

#[tokio::test]
async fn asn_proposal_preview_and_scopes_report_impact_and_collisions() {
    let a = proposal_fixture().await;
    let r = call(
        &a,
        "POST",
        "/v1/asn/preview",
        ADMIN,
        Some(json!({"asn":64500,"scope":{"kind":"asn"}})),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let i = &r.body["impact"];
    assert_eq!(r.body["stored"], false);
    assert_eq!(i["networks"], 2);
    assert_eq!(i["estimated"]["ipv4_addresses"], 512);
    assert_eq!(i["tracked"]["addresses"], 2);
    assert_eq!(
        i["preview"]["enforce"]["allow_to_deny"], 2,
        "both tracked addresses would be denied in enforce"
    );
    assert_eq!(i["collisions"]["allowlist"][0]["allow"], "203.0.113.128/25");
    assert_eq!(i["collisions"]["zones"][0]["zone"], "partner");
    assert!(i["warnings"].as_array().unwrap().len() >= 2);
    let agg = call(
        &a,
        "POST",
        "/v1/asn/preview",
        ADMIN,
        Some(json!({"asn":64500,"scope":{"kind":"aggregates"}})),
    )
    .await
    .body;
    assert_eq!(
        agg["impact"]["network_list"],
        json!(["198.51.100.0/24", "203.0.113.0/24"])
    );
    let bad = call(&a, "POST", "/v1/asn/preview", ADMIN, Some(json!({"asn":64500,"scope":{"kind":"prefixes","prefixes":["192.0.2.0/24","203.0.113.0/26"]}}))).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.body["errors"][0]["path"], "/scope/prefixes/0");
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/asn/preview",
            ADMIN,
            Some(json!({"asn":1,"scope":{"kind":"asn"}}))
        )
        .await
        .body["errors"][0]["path"],
        "/asn"
    );
    let ok = call(
        &a,
        "POST",
        "/v1/asn/preview",
        ADMIN,
        Some(json!({"asn":64500,"scope":{"kind":"prefixes","prefixes":["203.0.113.0/26"]}})),
    )
    .await;
    assert_eq!(ok.body["impact"]["networks"], 1);
    // Preview stores nothing and changes no decision.
    assert_eq!(
        call(&a, "GET", "/v1/asn/proposals", ADMIN, None).await.body["proposals"],
        json!([])
    );
    assert_eq!(
        a.view
            .load()
            .query_ip("198.51.100.7".parse().unwrap(), crate::now())
            .action,
        "allow"
    );
}

#[tokio::test]
async fn asn_proposal_lifecycle_two_person_rule_activation_and_withdrawal() {
    let a = proposal_fixture().await;
    let create = json!({"asn":64500,"scope":{"kind":"asn"},"reason":"botnet C2 hosting","expires_at":crate::now()+3*86400});
    let headers = delegated("/v1/asn/proposals", &create, 0);
    let r = call_with(
        &a,
        "POST",
        "/v1/asn/proposals",
        ADMIN,
        Some(create),
        &headers,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let id = r.body["id"].as_str().unwrap().to_owned();
    assert!(
        id.starts_with("p-")
            && id.len() == 22
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    );
    assert_eq!(
        (
            r.body["state"].clone(),
            r.body["created_by"]["name"].clone()
        ),
        (json!("draft"), json!("operator"))
    );
    assert_eq!(
        call(
            &a,
            "POST",
            "/v1/asn/proposals",
            ADMIN,
            Some(json!({"asn":64500,"scope":{"kind":"asn"}}))
        )
        .await
        .body["errors"][0]["path"],
        "/reason"
    );
    // Approve before submit, stale revision, unknown action.
    assert_eq!(
        act(
            &a,
            &id,
            json!({"action":"approve","expected_revision":1}),
            &[]
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let stale = act(
        &a,
        &id,
        json!({"action":"submit","expected_revision":9}),
        &[],
    )
    .await;
    assert_eq!(
        (stale.status, stale.body["current_revision"].clone()),
        (StatusCode::CONFLICT, json!(1))
    );
    let r = act(
        &a,
        &id,
        json!({"action":"submit","expected_revision":1}),
        &[],
    )
    .await;
    assert_eq!(r.body["state"], "pending");
    // Two-person rule: the delegated proposer cannot approve.
    let body = json!({"action":"approve","expected_revision":2,"reason":"self"});
    let path = format!("/v1/asn/proposals/{id}");
    let own = act(&a, &id, body.clone(), &delegated(&path, &body, 1)).await;
    assert_eq!(own.status, StatusCode::CONFLICT);
    assert!(own.body["error"].as_str().unwrap().contains("two-person"));
    let r = act(&a, &id, json!({"action":"annotate","expected_revision":2,"decision_log":{"requests":1200,"denied":40,"distinct_ip_refs":17}}), &[]).await;
    assert_eq!(r.body["decision_log"]["counts"]["requests"], 1200);
    let r = act(
        &a,
        &id,
        json!({"action":"approve","expected_revision":3,"reason":"reviewed"}),
        &[],
    )
    .await;
    assert_eq!(r.body["state"], "approved");
    // Approval alone never blocks.
    assert_eq!(
        a.view
            .load()
            .query_ip("198.51.100.7".parse().unwrap(), crate::now())
            .action,
        "allow"
    );
    let r = act(
        &a,
        &id,
        json!({"action":"activate","expected_revision":4,"reason":"go"}),
        &[],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["state"], "active");
    assert_eq!(r.body["activation"]["blocked"].as_array().unwrap().len(), 2);
    let view = a.view.load_full();
    let d = view.query_ip("198.51.100.7".parse().unwrap(), crate::now());
    assert_eq!(
        (d.action, d.code.as_str()),
        ("deny", "sumunjang.deny.block_asn")
    );
    assert_eq!(
        a.view
            .load()
            .query_ip("203.0.113.200".parse().unwrap(), crate::now())
            .action,
        "allow",
        "allowlist wins"
    );
    let blocks = call(&a, "GET", "/v1/blocks", ADMIN, None).await.body;
    assert!(
        blocks
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b["source"] == "asn_proposal")
    );
    // Withdraw removes exactly this proposal's blocks.
    let r = act(
        &a,
        &id,
        json!({"action":"withdraw","expected_revision":5,"reason":"false positive"}),
        &[],
    )
    .await;
    assert_eq!(r.body["state"], "withdrawn");
    assert_eq!(
        a.view
            .load()
            .query_ip("198.51.100.7".parse().unwrap(), crate::now())
            .action,
        "allow"
    );
    assert_eq!(
        call(&a, "GET", "/v1/blocks", ADMIN, None).await.body,
        json!([])
    );
    assert_eq!(
        act(
            &a,
            &id,
            json!({"action":"activate","expected_revision":6}),
            &[]
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let detail = call(&a, "GET", &format!("/v1/asn/proposals/{id}"), ADMIN, None)
        .await
        .body;
    let steps: Vec<_> = detail["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["action"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        steps,
        [
            "create", "submit", "annotate", "approve", "activate", "withdraw"
        ]
    );
    let audited: Vec<_> = entries(&a, "?action=asn.proposal.*&limit=200")
        .await
        .iter()
        .filter(|e| e["result"] == "committed")
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        audited,
        [
            "asn.proposal.withdraw",
            "asn.proposal.activate",
            "asn.proposal.approve",
            "asn.proposal.annotate",
            "asn.proposal.submit",
            "asn.proposal.create"
        ]
    );
    assert_eq!(
        call(&a, "GET", "/v1/asn/proposals/p-unknown", ADMIN, None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn asn_proposals_reject_and_expire() {
    let a = proposal_fixture().await;
    let r = call(
        &a,
        "POST",
        "/v1/asn/proposals",
        ADMIN,
        Some(json!({"asn":64501,"scope":{"kind":"asn"},"reason":"test"})),
    )
    .await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    act(
        &a,
        &id,
        json!({"action":"submit","expected_revision":1}),
        &[],
    )
    .await;
    assert_eq!(
        act(
            &a,
            &id,
            json!({"action":"reject","expected_revision":2}),
            &[]
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        act(
            &a,
            &id,
            json!({"action":"reject","expected_revision":2,"reason":"too broad"}),
            &[]
        )
        .await
        .body["state"],
        "rejected"
    );
    let r = call(
        &a,
        "POST",
        "/v1/asn/proposals",
        ADMIN,
        Some(json!({"asn":64501,"scope":{"kind":"asn"},"reason":"expiring"})),
    )
    .await;
    let id2 = r.body["id"].as_str().unwrap().to_owned();
    {
        let db = a.db.lock().unwrap();
        let body: String = db
            .query_row("SELECT body FROM asn_proposals WHERE id=?1", [&id2], |r| {
                r.get(0)
            })
            .unwrap();
        let mut p: Value = serde_json::from_str(&body).unwrap();
        p["expires_at"] = json!(crate::now() - 1);
        db.execute(
            "UPDATE asn_proposals SET body=?2 WHERE id=?1",
            rusqlite::params![id2, p.to_string()],
        )
        .unwrap();
    }
    crate::asn::expire_due(&a);
    let list = call(&a, "GET", "/v1/asn/proposals", ADMIN, None).await.body;
    let states: Vec<_> = list["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["state"].as_str().unwrap().to_owned())
        .collect();
    let mut states = states;
    states.sort();
    assert_eq!(states, ["expired", "rejected"]);
    assert_eq!(
        entries(&a, "?action=asn.proposal.expire").await[0]["actor"]["kind"],
        "system"
    );
}

#[tokio::test]
async fn asn_bundle_fetch_over_https_and_offline_import() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (key, trust) = bundle_key();
    let pki = crate::tls_reload::tests::Pki::new();
    // Minimal HTTPS origin (server cert only) serving version 4 then version 4 again.
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut std::fs::read(pki.path("server.pem")).unwrap().as_slice())
            .collect::<Result<_, _>>()
            .unwrap();
    let key_der =
        rustls_pemfile::private_key(&mut std::fs::read(pki.path("server.key")).unwrap().as_slice())
            .unwrap()
            .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = bundle(&key, 4, &[("192.0.2.0/24", 64496)]);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = tls.read(&mut buf).await.unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(head.as_bytes()).await.unwrap();
            tls.write_all(&body).await.unwrap();
            tls.shutdown().await.unwrap();
        }
    });
    let mut a = app();
    a.asn = crate::asn::AsnState::new(
        Some(trust),
        Some(format!("https://localhost:{port}/asn.json")),
        Some(pki.path("ca.pem")),
        3600,
        1,
    );
    let r = call(&a, "POST", "/v1/asn/refresh", ADMIN, Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        (r.body["version"].clone(), r.body["diff"]["added"].clone()),
        (json!(4), json!(1))
    );
    let again = crate::asn::fetch_once(&a, crate::actor::Actor::system())
        .await
        .unwrap();
    assert_eq!(again["changed"], false);
    server.await.unwrap();
    let status = call(&a, "GET", "/v1/asn/bundle", ADMIN, None).await.body;
    assert_eq!(status["fetch"]["status"]["attempts"], 2);
    assert_eq!(status["fetch"]["status"]["last_version"], 4);
    // Unreachable origin: failure recorded, catalog unchanged.
    a.asn = crate::asn::AsnState::new(
        a.asn.key.clone(),
        Some("https://127.0.0.1:1/x".into()),
        None,
        3600,
        1,
    );
    assert!(
        crate::asn::fetch_once(&a, crate::actor::Actor::system())
            .await
            .is_err()
    );
    assert_eq!(a.inner.lock().unwrap().engine.asn_catalog().len(), 1);
    // Plain HTTP URLs are refused (https only).
    a.asn = crate::asn::AsnState::new(
        a.asn.key.clone(),
        Some("http://127.0.0.1:1/x".into()),
        None,
        3600,
        1,
    );
    assert!(
        crate::asn::fetch_once(&a, crate::actor::Actor::system())
            .await
            .is_err()
    );

    // Offline import into a database file.
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("guard.sqlite3");
    {
        let mut db = crate::open_database(&database).unwrap();
        crate::persist_state(
            &mut db,
            &guard_core::Engine::new(guard_core::Policy::default())
                .unwrap()
                .state(),
        )
        .unwrap();
    }
    let file = dir.path().join("bundle.json");
    std::fs::write(&file, bundle(&key, 9, &[("198.51.100.0/24", 64500)])).unwrap();
    use base64::Engine as _;
    // SAFETY: test-only environment variable read by import_offline.
    unsafe {
        std::env::set_var(
            "HANGANG_GUARD_ASN_BUNDLE_KEY",
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()),
        )
    };
    let report: Value = serde_json::from_str(
        &crate::asn::import_offline(&database, &file, audit::Retention::default()).unwrap(),
    )
    .unwrap();
    assert_eq!(report["version"], 9);
    let db = crate::open_database(&database).unwrap();
    let mut e = guard_core::Engine::new(guard_core::Policy::default()).unwrap();
    assert_eq!(
        crate::asn::load_installed(&db, &mut e, None).unwrap(),
        Some(9)
    );
    let audited: String = db
        .query_row(
            "SELECT action FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audited, "asn.bundle.install");
}

#[tokio::test]
async fn decision_evidence_carries_a_coarse_risk_bucket() {
    let a = app();
    events(&a, "198.51.100.7", &["honeypot", "scanner"]).await;
    let r = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"t","ip":"198.51.100.7","evidence":true})),
    )
    .await
    .body;
    // 15 of threshold 10 -> 15 / 30 = 50%, stage suspicious.
    assert_eq!(
        r["evidence"]["risk"],
        json!({"score": 50, "stage": "suspicious"})
    );
    let clean = call(
        &a,
        "POST",
        "/v1/decision",
        COLLECTOR,
        Some(json!({"source_id":"t","ip":"192.0.2.1","evidence":true})),
    )
    .await
    .body;
    assert_eq!(
        clean["evidence"]["risk"],
        json!({"score": 0, "stage": "normal"})
    );
    // A busy engine yields no bucket instead of waiting.
    let guard = a.inner.lock().unwrap();
    assert!(
        a.risk_inputs("198.51.100.7".parse().unwrap(), crate::now())
            .is_none()
    );
    drop(guard);
    // gRPC carries the same bucket (fields 13/14) within the encode bound.
    let reply = crate::grpc::fixture_evidence(a.clone(), vec![198, 51, 100, 7]).await;
    let e = reply.evidence.unwrap();
    assert_eq!((e.risk_score, e.risk_stage), (50, 3));
}
