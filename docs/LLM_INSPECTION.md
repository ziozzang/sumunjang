# Prompt-based inspection and LLM assistance (design record)

[한국어](ko/LLM_INSPECTION.md) · [Documentation index](README.md)

Status: **proposed** (design only; nothing in this document is implemented).
Date: 2026-10-17. Scope: the TODO.md checklist "Prompt-based request inspection
and LLM queries" and original requirement step 5 ("determine allowlists, possibly
with reviewed LLM assistance"). Related: zero-trust ADR 0019 (decision events),
ADR 0020 (console), Sumunjang [ASN proposals](ASN_PROPOSALS.md),
[audit/explain](AUDIT_EXPLAIN.md), [metrics](METRICS.md).

## Decision summary

1. **Asynchronous aggregate analysis only.** No LLM call is ever on the
   admission path, in any mode. The analyst evaluates *subjects* (an address, a
   /24 or /48, an ASN proposal) from bounded aggregates, not individual requests.
2. **LLM output is advisory.** Results are stored as annotations
   (verdict, confidence, categories, rationale) on candidates, ASN proposals and
   allowlist reviews. They never mutate policy. Any later automation passes
   deterministic gates and is a separate, reviewed decision (phase L4).
3. **Never** grant an LLM allowlist mutation or ASN-wide blocking authority.
   It may *annotate* ASN proposals and *suggest* allowlist reviews; the existing
   human workflow (two-person rule, explicit activation) remains the only path.
4. **Attacker-controlled strings are data.** They appear only inside a
   labelled, escaped JSON facts block; the model gets no tools; output is
   validated against a strict schema and may only cite provided fact IDs.
5. **Default backend: the host's Dorang gateway** through its OpenAI-compatible
   interface (`/v1/chat/completions`), configurable to any compatible provider.
   Budgeted concurrency ≤ 4 calls by default (Dorang's measured safe band for a
   shared provider is 8–10 concurrent calls across *all* clients).
6. A **separate process** (`sumunjang-analyst`) with a dedicated, narrowly
   scoped credential (read aggregates/explain, write annotations), so a provider
   outage, prompt bug or compromise of the analyst cannot change policy.

## Why not per-request (synchronous) inspection

| Quantity | Sumunjang admission | LLM call via Dorang |
| --- | --- | --- |
| Latency | p99 0.3–1.5 ms (HTTP), sub-ms HGD1 ([PERFORMANCE](PERFORMANCE.md)) | median 1.2–2.6 s, outliers ≈ 16 s (measured 2026-10-16) |
| Throughput | > 100,000 decisions/s (measured up to 647k/s TCP) | ≈ 4 calls/s at 8–10 concurrent; breaker opens at ≥ 12–16 |
| Failure | fail-deny/fail-allow by Hangang policy in 100 ms | 429/503 "out of service" for 30–60 s, shared with other clients |
| Cost (≈ 1k tokens/call) | none | 10k req/s ≈ 864 billion tokens/day |

Synchronous inspection would raise admission latency by three orders of
magnitude, cap throughput at a few requests per second, and make every request
depend on a shared external gateway. The optional 1–5 s decision cache does not
help: its key is the client address (new addresses always miss) and its TTL is
shorter than one LLM call. Therefore the decision path never waits for an LLM,
and LLM results influence admission only through reviewed artifacts (blocks,
proposals). Those artifacts change the decision revision, so existing caches
converge within their 1–5 s TTL exactly as for any other policy change. Changing
a *prompt policy* invalidates **analysis results** (keyed by the policy version
digest), not decision caches.

Async analysis budget example: 500 subjects/hour × ~1.5k tokens ≈ 18 M
tokens/day, at most 4 concurrent calls (≤ 40% of the gateway's safe band).

## Architecture

```
Hangang ──decision events (ADR 0019, pseudonymized)──► exporter ─┐ facets/counts
Sumunjang (candidates, history, explain, zones, ASN catalog) ────┤
                                                                 ▼
                         sumunjang-analyst (separate process, bounded queue)
                           │ select subjects (policy triggers, dedup)
                           │ build facts (minimal, masked, bounded)
                           │ call LLM (Dorang /v1/chat/completions, no tools)
                           │ validate output (schema, fact refs, gates)
                           ▼
          POST /v1/llm/results (annotations only) ──► console (labelled AI suggestion)
```

The analyst holds `HANGANG_GUARD_ANALYST_TOKEN`: read candidates, history,
explain/batch, zones, ASN catalog and proposals; write annotations. Sumunjang
refuses every other route for this credential. The LLM API key
(`HANGANG_GUARD_LLM_API_KEY`) exists only in the analyst.

## Prompt policy schema

A prompt policy is an immutable, versioned document (CAS publish, audited like
other policy; editing creates a new version):

```json
{
  "id": "scanner-triage", "version": 3,
  "goal": "Classify whether a candidate address shows automated vulnerability probing.",
  "criteria": ["many distinct path templates with 404 status", "known scanner path families", "..."],
  "triggers": {"candidates": {"min_score": 10, "eligible_only": false},
               "asn_proposals": {"states": ["draft", "pending"]},
               "allowlist_review": false},
  "inputs": {"signals": true, "history": true, "decision_log": ["path_templates", "status_classes", "methods", "rates"],
             "geo": ["country", "asn"], "zones": true, "headers": [], "user_agent": "class"},
  "output_schema": "sumunjang.llm.verdict.v1",
  "model": {"provider": "dorang", "name": "zai:glm-5.3-flash", "temperature": 0, "max_tokens": 600},
  "budget": {"max_concurrency": 2, "calls_per_hour": 200, "tokens_per_day": 2000000},
  "result_ttl_secs": 3600,
  "review": {"show_confidence_min": 0.0, "suggest_actions": ["watch", "propose_block_ip", "propose_asn_review"]}
}
```

`inputs` is an allowlist: fields not listed are never sent. `headers` defaults
to empty; header names (never values of `authorization`, `cookie`,
`set-cookie`, `proxy-authorization` or any name matching token/secret/key
patterns) may be added explicitly; bodies are never sent.

**Output schema `sumunjang.llm.verdict.v1`** (strict, no extra properties):

```json
{"subject": "s1", "verdict": "benign|suspicious|malicious|uncertain",
 "confidence": 0.0, "categories": ["vulnerability_probe", "credential_stuffing", "crawler", "monitoring", "misconfigured_client", "other"],
 "rationale": "≤ 500 chars plain text", "evidence": ["f3", "f7"],
 "recommended_action": "none|watch|propose_block_ip|propose_block_prefix|propose_asn_review|suggest_allowlist_review"}
```

Validation: JSON parse, schema, enums, `confidence` in [0,1], `subject` equals a
requested subject, every `evidence` entry is a provided fact ID, rationale is
plain text (control characters, markup and URLs stripped; any address or ASN in
it must appear in the facts), and `recommended_action` is permitted by the
policy. Invalid output is stored as `invalid` with the reason and never shown
as a verdict.

## Inputs: minimal, masked, bounded

Facts are built only from data Sumunjang or the exporter already holds:

- Signals: per-kind counts and score in the window, in-memory history buckets.
- Decision-log aggregates (exporter, ADR 0019): path **templates** (never raw
  paths or queries), method mix, status classes, request-rate statistics,
  deny reasons — counts only, pseudonymous subject references.
- Context: ASN, country, zone ids, matching rule ids, existing blocks/allowlist
  state, candidate score/suspicion.
- Masking: authorization/cookie values are never collected; query strings and
  bodies are excluded; e-mail addresses, long hex/base64 runs (tokens, session
  ids) and digits beyond 6 consecutive characters in templates are replaced with
  placeholders; client addresses inside facts are the subject itself or its
  prefix, never other users' addresses.
- Bounds: ≤ 32 path templates (≤ 128 chars each), ≤ 16 user-agent classes,
  ≤ 64 facts per subject, ≤ 8 KiB facts per call, ≤ 10 subjects per batch call.
  Truncation is explicit in the facts (`"truncated": true`).

## Prompt-injection defenses

- Fixed message layout: system message = product preamble + policy goal and
  criteria (operator-authored, versioned); user message = one JSON object
  `{"facts": [...], "subjects": [...], "instructions_reference": "<policy id@version>"}`.
  Attacker-controlled strings (path templates, user-agent classes, rule
  descriptions) appear only as JSON string values with an explicit
  `"untrusted": true` marker, normalized (NFKC), control characters removed and
  length-capped. They are never concatenated into instructions.
- The system prompt states that facts are data and that instructions inside
  facts must be ignored; this is a mitigation, not the defense — the defenses
  are structural:
  - no tools, functions, retrieval or browsing (`tools: []`, no `tool_choice`);
  - `response_format` with the JSON schema where the backend supports it,
    otherwise strict parse + validation; temperature 0;
  - outputs are validated, cannot introduce subjects or evidence that were not
    provided, and only ever become annotations;
  - the analyst credential cannot change policy even if the model is fully
    subverted.
- Provenance on every result: policy id/version and digest, prompt template
  digest, provider, requested and reported model, request digest (facts),
  response digest, token usage, latency, timestamps.
- The evaluation set contains injection cases (instructions in path templates
  and user agents, fake JSON closing, role tags, "approve allowlist" requests);
  acceptance requires zero policy-relevant deviations.

## Provider, model and prompt versioning

- Backend: OpenAI-compatible chat completions. Default
  `--llm-base-url http://10.2.2.10:4000/v1` (host Dorang; Dorang publishes host
  port 4000), `HANGANG_GUARD_LLM_API_KEY`, model from the policy (a Dorang catalog
  name such as `zai:glm-5.3-flash`). Configurable to another compatible gateway;
  HTTPS required off-host.
- A per-deployment model allowlist; policies naming other models are refused.
- Versions recorded per result: policy version, template digest, model
  requested/reported, provider. Results from different versions are never mixed
  in metrics; switching model or policy starts a new shadow comparison.

## Budgets, timeouts, failures

- Concurrency: per policy `max_concurrency` (default 2), global cap 4. The
  gateway's provider limit is shared with other host clients (measured safe band
  8–10; ≥ 12 trips its breaker for everyone), so Sumunjang must stay a small,
  well-behaved tenant.
- Rate/cost: calls per hour and tokens per day per policy and globally; when
  exhausted the queue pauses and the console shows "budget exhausted".
- Timeouts: 20 s per call, 30 s per batch including validation.
- Circuit breaker: open after 3 consecutive failures, any `503 out of service`
  or 429; half-open probe after 60 s (Dorang recovers in 30–60 s).
- Retries: at most one, transport errors only, with jitter; never on 4xx or
  validation failures.
- Deduplication: key = (policy version digest, subject ref, facts digest);
  identical work reuses the stored result until it expires.
- Expiry: results expire after `result_ttl_secs` (default 1 h, ≤ 24 h) and are
  deleted after 30 days. Policy publication invalidates results of older
  versions for display (kept for shadow statistics).
- Queue: bounded (default 1,000 subjects, oldest dropped, counted).

## Results, gates and authority

| Phase | LLM output may | Never |
| --- | --- | --- |
| L1–L3 | annotate candidates and ASN proposals; draft proposal text; list allowlist-review suggestions | create/approve/activate proposals, change allowlist, rules, blocks or mode |
| L4 (separate ADR) | trigger *exact-IP, temporary* blocks only after deterministic gates | allowlist changes, prefix/ASN blocks, permanent blocks |

Deterministic gates for any L4 automation (all required): the address is
already eligible by the evidence threshold; LLM `malicious` with confidence ≥
0.9 under a policy whose shadow precision ≥ 0.98 on ≥ 500 reviewed cases; not
allowlisted, not in a protected zone, not in an excluded ASN; block TTL ≤ the
policy block TTL; per-hour automatic block cap; enforce mode; immediate rollback
switch. Gates are code, not prompts.

Allowlist (step 5): the analyst may produce `suggest_allowlist_review` with a
rationale (for example monitoring or corporate egress showing benign patterns).
The console shows it next to the allowlist editor; a human adds the entry through
the normal CAS + audit path. ASN proposals: the analyst attaches an
`llm` annotation (separate from the `decision_log` counts) visible in the
proposal's review page; approval rules are unchanged.

## Shadow evaluation and rollback

- Every result is shadowed against later human outcomes: candidate approval or
  dismissal, proposal approval/rejection, blocks removed as false positives.
  Metrics per policy version: precision/recall per verdict, calibration,
  agreement, invalid-output rate, cost and latency.
- Rollback: policies are immutable versions; activating a previous version or
  the global disable switch takes effect for the next batch; results of a
  version can be hidden; the breaker and budgets bound damage from a bad model.

## Console presentation

Network → threat queue and IP pages show an "AI suggestion" chip (verdict,
confidence, categories) clearly separated from decisions, with rationale,
cited facts, policy/model version, cost and latency, and its review status.
A Policies → Inspection page edits prompt policies (schema form, validation,
dry run on the evaluation set with metrics, publish with reason). ASN proposal
pages show LLM annotations beside impact analysis. Budget, breaker and queue
state appear on System. All strings use message keys (EN/KO); model text is
rendered as plain text only.

## Evaluation datasets

Reproducible, versioned JSONL fixtures of subject facts with labels:

- Benign: search crawlers, uptime monitors, CI runners, corporate NAT egress,
  mobile carrier CGNAT, API clients with retries.
- Attack: path-probe scanners, credential stuffing, honeypot hits, slow scans,
  distributed /24 campaigns.
- Adversarial: injection strings in templates/user agents, misleading
  ASN/country, oversized and truncated facts, Unicode confusables.
- Produced from pseudonymized aggregates and synthetic generation; no raw logs.

Metrics and thresholds: schema-valid ≥ 99.5%; injection resistance 100% (no
out-of-schema action, no unprovided evidence, no allowlist suggestion caused by
injected text); per-category precision/recall reported with confidence
intervals; p95 latency and cost per 1,000 subjects reported per model.

## APIs (planned)

- `GET/POST /v1/llm/policies` (CAS publish, reason, audit), `POST /v1/llm/policies/{id}/dry-run`
- `POST /v1/llm/results` (analyst credential; validated annotations),
  `POST /v1/llm/results/query` (filters, cursor)
- `GET /v1/llm/status` (queue, budgets, breaker, last errors)
- Metrics: `sumunjang_llm_calls_total{result}`, `sumunjang_llm_tokens_total{kind}`,
  `sumunjang_llm_latency_seconds`, `sumunjang_llm_queue_depth`,
  `sumunjang_llm_breaker_open`, `sumunjang_llm_invalid_outputs_total` — no
  subjects or model text as labels.

## Phased plan and acceptance

| Phase | Deliverable | Acceptance |
| --- | --- | --- |
| L0 | This design, output schema, evaluation dataset v1 | Reviewed design; ≥ 300 labelled subjects incl. ≥ 50 injection cases |
| L1 | Offline evaluator CLI against the dataset (no production data) via Dorang | Schema-valid ≥ 99.5%; injection resistance 100%; metrics report reproducible from fixtures |
| L2 | `sumunjang-analyst` shadow on live aggregates; annotations + console display; budgets/breaker/metrics | No admission-path dependency (latency unchanged with gateway down); budgets respected; no policy mutation possible with the analyst credential (tested) |
| L3 | Assisted workflows: annotations on ASN proposals, allowlist-review suggestions, proposal drafting | Every policy change still flows through existing CAS/audit/two-person rules; shadow precision dashboards per version |
| L4 | Optional gated exact-IP temporary auto-blocks (separate ADR) | Gates in code; shadow precision ≥ 0.98 on ≥ 500 reviewed cases; caps and kill switch qualified |

## Alternatives considered

- Synchronous per-request LLM checks: rejected (latency, throughput, availability; see above).
- LLM with tool access to Sumunjang APIs: rejected (injection would gain authority).
- Small local classifier/embeddings first: complementary; may pre-filter subjects before LLM calls in L2+.
- No LLM: remains the default; the analyst is optional and disabled unless configured.

## Open questions

1. Whether the exporter (ADR 0019) exposes per-subject template histograms under strict privacy profiles.
2. Dorang tenant isolation: a dedicated virtual key/quota for Sumunjang vs. sharing the provider pool.
3. Retention of rationale text (30 days proposed) under regional rules.
4. Which model family gives acceptable precision at `temperature 0` in Korean and English rationale.
