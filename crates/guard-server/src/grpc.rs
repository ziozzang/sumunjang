//! Additional decision transport over the existing network snapshot.
use crate::App;
use anyhow::Result;
use guard_grpc::v1::{
    NetworkEvidence, NetworkReply, NetworkRequest,
    network_server::{Network, NetworkServer},
};
pub use hangang_runtime::configuration;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tonic::{Request, Response, Status, transport::ServerTlsConfig};

struct Service {
    app: App,
    requests: Arc<Semaphore>,
}
fn caller(app: &App, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
    let mut values = metadata.get_all("authorization").iter();
    let supplied = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if values.next().is_some()
        || !supplied.is_some_and(|value| {
            crate::protocol::matches_token(value.as_bytes(), app.collector.as_bytes())
        })
    {
        return Err(Status::unauthenticated("collector credential required"));
    }
    if app.source_remaining(&app.view.load()).is_none() {
        return Err(Status::unavailable("native policy source unavailable"));
    }
    Ok(())
}
fn authenticate_transport<S>(
    service: S,
    app: App,
) -> tonic::service::interceptor::InterceptedService<S, impl tonic::service::Interceptor + Clone> {
    tonic::service::interceptor::InterceptedService::new(service, move |request: Request<()>| {
        caller(&app, request.metadata())?;
        Ok(request)
    })
}
#[tonic::async_trait]
impl Network for Service {
    async fn check(
        &self,
        request: Request<NetworkRequest>,
    ) -> Result<Response<NetworkReply>, Status> {
        caller(&self.app, request.metadata())?;
        let _permit = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision capacity"))?;
        let input = request.into_inner();
        let ip = match input.ip.as_slice() {
            bytes if bytes.len() == 4 => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()))
            }
            bytes if bytes.len() == 16 => {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            }
            _ => return Err(Status::invalid_argument("invalid address size")),
        };
        let view = self.app.view.load_full();
        if input.include_evidence {
            return Ok(Response::new(self.reply_with_evidence(
                input.request_id,
                input.minimum_revision,
                &view,
                ip,
            )));
        }
        let geo = view.requires_geo().then(|| self.app.geo.load_full());
        let decision = match &geo {
            Some(geo) => view.query_ip_context(ip, crate::now(), geo.context(ip)),
            None => view.query_ip(ip, crate::now()),
        };
        Ok(Response::new(self.reply(
            input.request_id,
            input.minimum_revision,
            &view,
            geo.as_ref(),
            decision,
        )))
    }
}
fn stage_number(stage: guard_core::trace::DecidingStage) -> i32 {
    use guard_core::trace::DecidingStage as S;
    match stage {
        S::Observe => 1,
        S::Allowlist => 2,
        S::Rule => 3,
        S::Block => 4,
        S::Default => 5,
    }
}
impl Service {
    /// Additive evidence reply. The verdict comes from the same evaluation and
    /// the same owner fence as [`Service::reply`]; evidence is withheld (only an
    /// unavailable reason code remains) whenever the reply is unavailable.
    fn reply_with_evidence(
        &self,
        request_id: u64,
        minimum_revision: u64,
        view: &Arc<guard_core::DecisionView>,
        ip: IpAddr,
    ) -> NetworkReply {
        let catalog = self.app.geo.load_full();
        let time = crate::now();
        let (evidence, _) = crate::explain::decision_evidence(view, &catalog, ip, time);
        // The verdict itself is the unmodified live decision.
        let decision = if view.requires_geo() {
            view.query_ip_context(ip, time, catalog.context(ip))
        } else {
            view.query_ip(ip, time)
        };
        let captured = view.requires_geo().then_some(&catalog);
        let mut reply = self.reply(request_id, minimum_revision, view, captured, decision);
        reply.evidence = Some(if reply.verdict == 3 {
            let source = self.app.source_remaining(view).is_none();
            NetworkEvidence {
                reason_code: if source {
                    "sumunjang.unavailable.source"
                } else if decision.revision < minimum_revision {
                    "sumunjang.unavailable.revision_floor"
                } else {
                    "sumunjang.unavailable.owner_replaced"
                }
                .into(),
                ..NetworkEvidence::default()
            }
        } else {
            NetworkEvidence {
                reason_code: evidence.reason_code.into(),
                deciding_stage: stage_number(evidence.stage),
                rule_ids: evidence.rules,
                rule_ids_truncated: evidence.rules_truncated,
                block_network: evidence.block_network.unwrap_or_default(),
                asn: evidence.asn.unwrap_or(0),
                country: evidence.country.unwrap_or_default(),
                enforce_verdict: if evidence.enforce_action == "deny" {
                    2
                } else {
                    1
                },
                enforce_reason_code: evidence.enforce_reason_code.into(),
                zone_ids: evidence.zones,
                zone_ids_truncated: evidence.zones_truncated,
                zone_revision: evidence.zone_revision,
            }
        });
        // Keep the reply within the 1 KiB encode bound: drop trailing zone ids.
        use prost::Message;
        while reply.encoded_len() > 1024 {
            match reply.evidence.as_mut() {
                Some(e) if !e.zone_ids.is_empty() => {
                    e.zone_ids.pop();
                    e.zone_ids_truncated = true;
                }
                _ => break,
            }
        }
        reply
    }
    fn reply(
        &self,
        request_id: u64,
        minimum_revision: u64,
        view: &Arc<guard_core::DecisionView>,
        geo: Option<&Arc<crate::geoip::GeoCatalog>>,
        decision: guard_core::DecisionRef<'_>,
    ) -> NetworkReply {
        let source_remaining = self.app.source_remaining(view);
        let available = source_remaining.is_some()
            && decision.revision >= minimum_revision
            && Arc::ptr_eq(view, &self.app.view.load_full())
            && geo.is_none_or(|captured| Arc::ptr_eq(captured, &self.app.geo.load_full()));
        NetworkReply {
            request_id,
            revision: decision.revision,
            verdict: if !available {
                3
            } else if decision.action == "deny" {
                2
            } else {
                1
            },
            mode: if !available {
                0
            } else if decision.mode == guard_core::Mode::Enforce {
                2
            } else {
                1
            },
            ttl_ms: if available {
                decision.ttl_ms.min(source_remaining.unwrap_or(0)).min(5000) as u32
            } else {
                0
            },
            evidence: None,
        }
    }
}
pub async fn serve(
    listener: TcpListener,
    tls: ServerTlsConfig,
    app: App,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let incoming = hangang_runtime::incoming(listener);
    // Separate predecode budget, shared by every connection to this listener.
    let ingress = Arc::new(Semaphore::new(app.max_http_requests.min(256)));
    hangang_runtime::server(tls)?
        .add_service(authenticate_transport(
            hangang_runtime::unary_ingress::UnaryIngress::new(
                NetworkServer::new(Service {
                    requests: Arc::new(Semaphore::new(app.max_http_requests)),
                    app: app.clone(),
                })
                .max_decoding_message_size(2048)
                .max_encoding_message_size(1024),
                ingress,
                2048,
            ),
            app,
        ))
        .serve_with_incoming_shutdown(incoming, async move {
            if !*stop.borrow() {
                let _ = stop.changed().await;
            }
        })
        .await?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) async fn fixture_check(app: App, ip: Vec<u8>) -> Result<NetworkReply, Status> {
    let service = Service {
        app,
        requests: Arc::new(Semaphore::new(1)),
    };
    let mut request = Request::new(NetworkRequest {
        request_id: 42,
        ip,
        minimum_revision: 0,
        include_evidence: false,
    });
    request.metadata_mut().insert(
        "authorization",
        "Bearer collector-test-token".parse().unwrap(),
    );
    service.check(request).await.map(Response::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(token: &str) -> Request<NetworkRequest> {
        let mut request = Request::new(NetworkRequest {
            request_id: 7,
            ip: vec![192, 0, 2, 1],
            minimum_revision: 0,
            include_evidence: false,
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }
    #[test]
    fn evidence_is_additive_and_withheld_when_unavailable() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        {
            let mut inner = service.app.inner.lock().unwrap();
            let mut policy = inner.engine.policy().clone();
            policy.mode = guard_core::Mode::Enforce;
            inner.engine.set_policy(policy).unwrap();
            inner
                .engine
                .set_rules(guard_core::RuleSet {
                    version: 1,
                    rules: vec![guard_core::Rule {
                        id: "net-deny".into(),
                        priority: 1,
                        network: Some("192.0.2.0/24".into()),
                        countries: vec![],
                        asns: vec![],
                        action: guard_core::RuleAction::Deny,
                        score: 0,
                        expires_at: None,
                        description: String::new(),
                    }],
                })
                .unwrap();
            service
                .app
                .view
                .store(Arc::new(inner.engine.decision_view()));
        }
        let view = service.app.view.load_full();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let plain = service.reply(7, 0, &view, None, view.query_ip(ip, crate::now()));
        assert!(plain.evidence.is_none());
        let rich = service.reply_with_evidence(7, 0, &view, ip);
        assert_eq!(
            (
                rich.request_id,
                rich.revision,
                rich.verdict,
                rich.mode,
                rich.ttl_ms
            ),
            (
                plain.request_id,
                plain.revision,
                plain.verdict,
                plain.mode,
                plain.ttl_ms
            )
        );
        use prost::Message;
        assert!(rich.encoded_len() <= 1024);
        let evidence = rich.evidence.unwrap();
        assert_eq!(evidence.reason_code, "sumunjang.deny.rule");
        assert_eq!(evidence.rule_ids, ["net-deny"]);
        assert_eq!((evidence.deciding_stage, evidence.enforce_verdict), (3, 2));
        let fenced = service.reply_with_evidence(7, u64::MAX, &view, ip);
        assert_eq!(fenced.verdict, 3);
        let evidence = fenced.evidence.unwrap();
        assert_eq!(evidence.reason_code, "sumunjang.unavailable.revision_floor");
        assert!(evidence.rule_ids.is_empty() && evidence.block_network.is_empty());
    }
    #[test]
    fn evidence_zone_ids_stay_within_the_encode_bound() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        {
            let mut inner = service.app.inner.lock().unwrap();
            for i in 0..20 {
                inner
                    .engine
                    .set_zone(
                        guard_core::zones::Zone {
                            id: format!("{:0>128}", i),
                            prefixes: vec!["192.0.2.0/24".into()],
                            ..Default::default()
                        },
                        1,
                        None,
                    )
                    .unwrap();
            }
            service
                .app
                .view
                .store(Arc::new(inner.engine.decision_view()));
        }
        let view = service.app.view.load_full();
        let reply = service.reply_with_evidence(7, 0, &view, "192.0.2.1".parse().unwrap());
        use prost::Message;
        assert!(reply.encoded_len() <= 1024);
        let evidence = reply.evidence.unwrap();
        assert!(evidence.zone_ids_truncated);
        assert!(!evidence.zone_ids.is_empty() && evidence.zone_ids.len() < 8);
        assert_eq!(evidence.zone_revision, 20);
    }
    #[test]
    fn changed_owner_with_same_revision_discards_captured_network_reply() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        let view = service.app.view.load_full();
        let decision = view.query_ip("192.0.2.1".parse().unwrap(), crate::now());
        assert_ne!(service.reply(7, 0, &view, None, decision).verdict, 3);
        service.app.view.store(Arc::new((*view).clone()));
        let decision = view.query_ip("192.0.2.1".parse().unwrap(), crate::now());
        let reply = service.reply(7, 0, &view, None, decision);
        assert_eq!((reply.request_id, reply.revision), (7, view.revision));
        assert_eq!((reply.verdict, reply.mode, reply.ttl_ms), (3, 0, 0));
    }
    #[test]
    fn changed_geo_owner_discards_reply_that_used_captured_geo() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        let view = service.app.view.load_full();
        let geo = service.app.geo.load_full();
        let decision = view.query_ip_context(
            "192.0.2.1".parse().unwrap(),
            crate::now(),
            geo.context("192.0.2.1".parse().unwrap()),
        );
        assert_ne!(service.reply(8, 0, &view, Some(&geo), decision).verdict, 3);
        service
            .app
            .geo
            .store(Arc::new(crate::geoip::GeoCatalog::default()));
        let decision = view.query_ip_context(
            "192.0.2.1".parse().unwrap(),
            crate::now(),
            geo.context("192.0.2.1".parse().unwrap()),
        );
        let reply = service.reply(8, 0, &view, Some(&geo), decision);
        assert_eq!((reply.verdict, reply.mode, reply.ttl_ms), (3, 0, 0));
    }
    #[tokio::test]
    async fn admission_is_bounded_and_revision_fence_is_unavailable() {
        let service = Service {
            app: crate::tests::app(),
            requests: Arc::new(Semaphore::new(1)),
        };
        let held = service.requests.clone().acquire_owned().await.unwrap();
        assert_eq!(
            service
                .check(request("collector-test-token"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        // Authentication still precedes capacity admission.
        assert_eq!(
            service
                .check(request("admin-test-token"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        drop(held);
        let mut input = request("collector-test-token");
        input.get_mut().minimum_revision = u64::MAX;
        let result = service.check(input).await.unwrap().into_inner();
        assert_eq!((result.verdict, result.mode, result.ttl_ms), (3, 0, 0));
    }

    use axum::{
        body::{Body, Bytes},
        http,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct PredecodeStream {
        polls: Arc<AtomicUsize>,
        forbid_poll: bool,
        chunks: std::collections::VecDeque<Bytes>,
    }
    impl tonic::codegen::tokio_stream::Stream for PredecodeStream {
        type Item = Result<Bytes, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.forbid_poll,
                "unauthenticated protobuf body was polled"
            );
            std::task::Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }
    fn predecode_body(chunks: Vec<Bytes>, forbid_poll: bool) -> (Body, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        (
            Body::from_stream(PredecodeStream {
                polls: polls.clone(),
                forbid_poll,
                chunks: chunks.into(),
            }),
            polls,
        )
    }
    fn predecode_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }
    fn predecode_request(path: &str, credentials: &[&str], body: Body) -> http::Request<Body> {
        let mut request = http::Request::builder()
            .method("POST")
            .version(http::Version::HTTP_2)
            .uri(path)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(body)
            .unwrap();
        for credential in credentials {
            request
                .headers_mut()
                .append("authorization", credential.parse().unwrap());
        }
        request
    }
    async fn predecode_response<B>(response: http::Response<B>) -> (u16, Vec<u8>)
    where
        B: tonic::codegen::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut status = response
            .headers()
            .get("grpc-status")
            .map(|v| v.to_str().unwrap().parse::<u16>().unwrap());
        let mut body = response.into_body();
        let mut data = Vec::new();
        while let Some(frame) =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
        {
            match frame.unwrap().into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers()
                        && let Some(value) = trailers.get("grpc-status")
                    {
                        status = Some(value.to_str().unwrap().parse::<u16>().unwrap());
                    }
                }
            }
        }
        (status.expect("gRPC status"), data)
    }

    const PREDECODE_PATH: &str = "/hangang.sumunjang.v1.Network/Check";
    fn predecode_service(
        app: App,
        requests: Arc<Semaphore>,
    ) -> tower::util::BoxCloneService<
        http::Request<Body>,
        http::Response<Body>,
        std::convert::Infallible,
    > {
        predecode_service_with_ingress(app, requests, Arc::new(Semaphore::new(1)))
    }
    fn predecode_service_with_ingress(
        app: App,
        requests: Arc<Semaphore>,
        ingress: Arc<Semaphore>,
    ) -> tower::util::BoxCloneService<
        http::Request<Body>,
        http::Response<Body>,
        std::convert::Infallible,
    > {
        let generated = NetworkServer::new(Service {
            app: app.clone(),
            requests,
        })
        .max_decoding_message_size(2048)
        .max_encoding_message_size(1024);
        tower::util::BoxCloneService::new(tower::ServiceExt::<http::Request<Body>>::map_response(
            authenticate_transport(
                hangang_runtime::unary_ingress::UnaryIngress::new(generated, ingress, 2048),
                app,
            ),
            |response| response.map(Body::new),
        ))
    }
    #[tokio::test]
    async fn predecode_auth_rejects_missing_wrong_role_and_duplicate_headers_before_body() {
        let app = crate::tests::app();
        let requests = Arc::new(Semaphore::new(1));
        for credentials in [
            vec![],
            vec!["Bearer incorrect"],
            vec!["Bearer admin-test-token"],
            vec!["Bearer collector-test-token", "Bearer incorrect"],
            vec!["Bearer incorrect", "Bearer collector-test-token"],
            vec!["Bearer collector-test-token", "Bearer collector-test-token"],
        ] {
            let (body, polls) = predecode_body(vec![Bytes::from_static(&[255; 5])], true);
            let response = predecode_service(app.clone(), requests.clone())
                .oneshot(predecode_request(PREDECODE_PATH, &credentials, body))
                .await
                .unwrap();
            let (status, data) = predecode_response(response).await;
            assert_eq!(status, tonic::Code::Unauthenticated as u16);
            assert!(data.is_empty());
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(requests.available_permits(), 1);
        }
    }
    fn predecode_scalar_payload(fields: &[(u8, u64)]) -> Vec<u8> {
        let mut output = Vec::new();
        for &(field, mut value) in fields {
            if value == 0 {
                continue;
            }
            output.push(field << 3);
            while value >= 128 {
                output.push((value as u8 & 0x7f) | 0x80);
                value >>= 7;
            }
            output.push(value as u8);
        }
        output
    }
    #[tokio::test]
    async fn predecode_auth_preserves_decoding_and_network_snapshot_execution() {
        let app = crate::tests::app();
        let requests = Arc::new(Semaphore::new(1));
        let expected = Service {
            app: app.clone(),
            requests: requests.clone(),
        }
        .check(request("collector-test-token"))
        .await
        .unwrap()
        .into_inner();
        assert_ne!(expected.verdict, 3);
        // Canonical NetworkRequest protobuf: request_id=7, ip=192.0.2.1,
        // omitted minimum_revision=0. Split its framing prefix across chunks.
        let frame = predecode_frame(b"\x08\x07\x12\x04\xc0\x00\x02\x01");
        let (body, polls) = predecode_body(
            vec![
                Bytes::copy_from_slice(&frame[..2]),
                Bytes::copy_from_slice(&frame[2..5]),
                Bytes::copy_from_slice(&frame[5..]),
            ],
            false,
        );
        let response = predecode_service(app, requests.clone())
            .oneshot(predecode_request(
                PREDECODE_PATH,
                &["Bearer collector-test-token"],
                body,
            ))
            .await
            .unwrap();
        let (status, data) = predecode_response(response).await;
        assert_eq!(status, tonic::Code::Ok as u16);
        let payload = predecode_scalar_payload(&[
            (1, expected.request_id),
            (2, expected.revision),
            (3, expected.verdict as u64),
            (4, expected.mode as u64),
            (5, u64::from(expected.ttl_ms)),
        ]);
        assert_eq!(data, predecode_frame(&payload));
        assert!(polls.load(Ordering::SeqCst) >= 3);
        assert_eq!(requests.available_permits(), 1);
    }
    #[tokio::test]
    async fn predecode_auth_preserves_generated_2048_byte_cap() {
        let app = crate::tests::app();
        let requests = Arc::new(Semaphore::new(1));
        let mut prefix = vec![0];
        prefix.extend_from_slice(&2049_u32.to_be_bytes());
        let (body, polls) = predecode_body(vec![Bytes::from(prefix)], false);
        let response = predecode_service(app, requests.clone())
            .oneshot(predecode_request(
                PREDECODE_PATH,
                &["Bearer collector-test-token"],
                body,
            ))
            .await
            .unwrap();
        let (status, data) = predecode_response(response).await;
        assert_eq!(status, tonic::Code::OutOfRange as u16);
        assert!(data.is_empty());
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert_eq!(requests.available_permits(), 1);
    }
    #[tokio::test]
    async fn predecode_auth_cannot_be_supplied_only_in_request_trailers() {
        use http_body_util::BodyExt;
        let app = crate::tests::app();
        let requests = Arc::new(Semaphore::new(1));
        let frame = predecode_frame(b"\x08\x07\x12\x04\xc0\x00\x02\x01");
        let (body, polls) = predecode_body(vec![Bytes::from(frame)], true);
        let trailers_polled = Arc::new(AtomicUsize::new(0));
        let observed = trailers_polled.clone();
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            "authorization",
            "Bearer collector-test-token".parse().unwrap(),
        );
        let body = Body::new(body.with_trailers(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Some(Ok::<_, axum::Error>(trailers))
        }));
        let response = predecode_service(app, requests.clone())
            .oneshot(predecode_request(PREDECODE_PATH, &[], body))
            .await
            .unwrap();
        let (status, data) = predecode_response(response).await;
        assert_eq!(status, tonic::Code::Unauthenticated as u16);
        assert!(data.is_empty());
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(trailers_polled.load(Ordering::SeqCst), 0);
        assert_eq!(requests.available_permits(), 1);
    }
    #[tokio::test]
    async fn unary_ingress_rejects_multiple_messages_and_recovers_capacity() {
        let app = crate::tests::app();
        let requests = Arc::new(Semaphore::new(1));
        let ingress = Arc::new(Semaphore::new(1));
        let first = predecode_frame(b"\x08\x07\x12\x04\xc0\x00\x02\x01");
        let second = predecode_frame(b"");
        // A dispatched handler would fail with ResourceExhausted, distinguishing
        // framing refusal from a domain-level decision/refusal.
        requests.close();
        let (body, _) = predecode_body(vec![Bytes::from(first), Bytes::from(second)], false);
        let response =
            predecode_service_with_ingress(app.clone(), requests.clone(), ingress.clone())
                .oneshot(predecode_request(
                    PREDECODE_PATH,
                    &["Bearer collector-test-token"],
                    body,
                ))
                .await
                .unwrap();
        let (status, data) = predecode_response(response).await;
        assert_eq!(status, tonic::Code::InvalidArgument as u16);
        assert!(data.is_empty());
        assert_eq!(ingress.available_permits(), 1);
        assert_eq!(requests.available_permits(), 1);
        let held = ingress.clone().try_acquire_owned().unwrap();
        let (body, polls) = predecode_body(vec![], true);
        let response = predecode_service_with_ingress(app, requests, ingress.clone())
            .oneshot(predecode_request(
                PREDECODE_PATH,
                &["Bearer collector-test-token"],
                body,
            ))
            .await
            .unwrap();
        assert_eq!(
            predecode_response(response).await.0,
            tonic::Code::ResourceExhausted as u16
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        drop(held);
        assert_eq!(ingress.available_permits(), 1);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn unavailable_native_source_refuses_before_protobuf_body_poll() {
        let mut app = crate::tests::app();
        app.native_source = Some(crate::kubernetes_authority::Owner::new().unwrap());
        let (body, polls) = predecode_body(vec![], true);
        let service = predecode_service(app, Arc::new(Semaphore::new(1)));
        let response = service
            .oneshot(predecode_request(
                PREDECODE_PATH,
                &["Bearer collector-test-token"],
                body,
            ))
            .await
            .unwrap();
        assert_eq!(predecode_response(response).await.0, 14);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
}
