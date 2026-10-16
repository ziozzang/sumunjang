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
