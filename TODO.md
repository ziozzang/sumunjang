# TODO

[한국어](TODO.ko.md) · [Documentation](docs/README.md)

## Original requirements

Build a security service for Hangang (`~/hangang`) that analyzes request signals
and blocks IPs in real time according to policy. Hangang's native zero-trust
mechanism should support first-class integration.

Example workflow:

1. Record explicit honeypot evidence.
2. Resolve the source IP's ASN.
3. Add IPs exceeding the threshold to the block candidate list (BCL).
4. Retrieve the IP prefix pool associated with a proposed ASN block.
5. Determine allowlists, possibly with reviewed LLM assistance.
6. Decide the scope of IP ranges to block.

Requirements: per-request queries or an embedded policy mechanism, dashboard
management, dynamic policies, extremely fast block-pool lookup, and consideration
of GeoIP in guard. Design thoroughly before implementation; use sub-agents for
independent implementation units and consider cost. Existing running servers may
be used for testing when deployment conditions are established.

Research similar tools, attack-pattern collection and updateable pattern feeds.
Implement in Rust with low resource use. Databases are for persistence/checkpoints,
not every decision; do not retain all request logs. The original working name
`hangang-flogging` was considered before choosing `hangang-guard`.

## Accepted direction — 2026-10-12

- Project: `hangang-guard`; retain workspace directory `hangang-safe`.
- Rust service with native first-class Hangang support; modifying Hangang is authorized.
- Hangang queries guard on every request by default. Cache is optional and strictly limited to a 1–5 second TTL.
- Procedure: design/review → independent sub-agent implementation → real-process integration verification → commit/push. Protect existing Hangang edits with a separate worktree.
- Initial implementation: observe/enforce policies, BCL and reviewed approval, CIDR allow/block/expiration, dashboard, bounded aggregation, SQLite checkpoints, per-request decisions and optional short cache.
- Next phases: online ASN prefix refresh, ASN proposal impact analysis, authenticated attack-pattern updates with provenance/version/rollback, and GeoIP operational policy.
- Guard is the IP/network policy and risk component of the zero-trust backbone.
  Hopae manages users/principals. Guard must not duplicate accounts or sessions;
  future scope expansion should preserve that responsibility boundary.
- English is the primary documentation language; Korean translations accompany it.

## Prompt-based request inspection and LLM queries

User-requested investigation: inspect request patterns according to operator
prompts and use LLM queries for analysis. Decide implementation after design.

Design (proposed, 2026-10-17): [docs/LLM_INSPECTION.md](docs/LLM_INSPECTION.md)
covers every item below — asynchronous aggregate analysis only, advisory
annotations, Dorang OpenAI-compatible backend, phases L0–L4. Items stay open
until the corresponding phase is implemented and qualified.

- [ ] Design prompt policies defining inspection goals, criteria and output schemas.
- [ ] Compare synchronous per-request queries with asynchronous aggregate analysis:
      latency, cost, throughput, failure behavior, and interaction between optional
      1–5 second decision cache and policy changes.
- [ ] Select minimum inputs: method/path structure, status/frequency/time patterns,
      honeypot/scanner evidence. Decide header/body inclusion through explicit policy;
      remove or mask tokens, cookies and personal data. Bound input and aggregate sizes.
- [ ] Treat attacker-controlled request strings and prompt injection as untrusted
      data, separate from system prompts, operator policy and tool permissions.
      Validate structured output and retain decision provenance.
- [ ] Design provider/model/prompt versioning, cost budgets, timeouts, concurrency,
      circuit breakers, retries/deduplication and result expiration. Invalidate
      relevant cache entries when prompt policies change.
- [ ] First evaluate LLM results as candidates/explanations. Before automatic
      enforcement, design deterministic policy gates, false-positive validation,
      shadow evaluation and rollback. Do not grant allowlist mutation or ASN-wide
      blocking authority without separate review.
- [ ] Show prompt policies, results, rationale, cost, latency and approval status
      in the dashboard. Build reproducible benign/attack evaluation datasets and criteria.

## Performance, policy and management expansion — 2026-10-12

- [x] Compressed radix-tree IPv4/IPv6 pools and immutable lock-free decision views.
- [x] Qualify the 10,000–100,000 decisions/sec target with actual transport load tests.
- [x] Connection reuse, once-per-connection authentication, fixed 24-byte binary protocol and native integration.
- [x] Admin search/sort/pagination and structured policy/allowlist editing.
- [x] Offline GeoIP Country/City/ASN, admin lookup and last-good reload.
- [x] IP/CIDR scores, suspicion stages and matched rule explanations.
- [x] Similar-tool research, embedded Lua and JSON RuleSet validation/application.
- [ ] Sustained load, failures and distributed deployment qualification with full proxy/production traffic.
- [ ] Design prompt-based LLM inspection using the checklist above.
- [x] User confirmed that embedding means an embedded Lua runtime; implemented Lua 5.4.

## Native Hangang console
- [x] Trusted pinned Guard menu package, host authentication and native theme.
- [x] Reproducible generation and host credential/role/audit bounds.
- [ ] Coordinate verified package activation with runtime auto-updates; host pins remain explicit.

## Kubernetes ipBlock primitive

Implemented core-only `network_policy::IpBlock`: bounded exception input,
canonical IPv4/IPv6 and mapped addresses, strict subnet validation and per-peer
CIDR subtraction. Exceptions apply to their own peer, not a global deny list;
other peers/policies can still allow that address. This is not activated server
NetworkPolicy enforcement. Destination/port/direction and selector context, API
source ownership, snapshot freshness and CNI qualification remain required.

## Selected network direction core

`SelectedDirection` now evaluates a selector-resolved target/direction with TCP,
UDP or SCTP destination ports and ranges. It distinguishes no selected policy
from isolated default deny; matching rules are additive, with peer and port
conditions intersected within each rule. Empty peers/ports are unrestricted.
Zero destination port is refused for isolated targets. Capacity is bounded across
rules, peers and ports. The source adapter must resolve selectors and named ports,
and independently reconcile ingress/egress. Rule-level matching still scans
bounded candidates and needs a measured index before large-policy performance
claims. No server, native protocol or CNI activation is implied.

Semantics reference: [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## Label selector predicate core

Added bounded conjunctive `LabelSelector`/`Requirement` predicates: In, NotIn,
Exists and DoesNotExist. NotIn includes absent keys; present empty values remain
distinct from absence. Empty selectors match all objects. matchLabels can compile
into singleton In predicates. Constructors validate operator/value cardinality
and capacity; Kubernetes label syntax remains the API adapter's responsibility.
Apply only to authoritative labels, never request headers. Namespace scope,
combined namespace/Pod selector resolution, source snapshot consistency and server
integration remain open. Reference: [Kubernetes labels](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/).

## Namespace and Pod peer selector composition

`PodPeerSelector` composes namespaceSelector and podSelector with AND semantics.
Without namespaceSelector, podSelector stays in the policy namespace; an empty
namespaceSelector selects all namespaces, while an empty podSelector alone stays
local. Both selectors absent is rejected by this constructor: the adapter must
represent the all-peer case explicitly. Evaluate only authoritative live Pod and
Namespace facts, with source cluster/UID/freshness fencing still owned by the
adapter. API parsing, selector-to-address materialization and server enforcement
remain open. Core tests cover combined versus separate selectors and empty/absent
scope distinctions. Reference: [NetworkPolicy selectors](https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors).

## Server selector source adapter

The server now parses Kubernetes LabelSelector JSON with exact matchLabels and
matchExpressions fields and compiles it into the core. Unknown fields/operators,
null maps, invalid operator/value cardinality and oversized inputs are refused.
`sumunjang --check-kubernetes-selector FILE` runs offline without DB/listeners.
This validates shape and predicate bounds, not complete Kubernetes label syntax.
API collection, NetworkPolicy parsing, UID/freshness fencing and request-context
integration remain open; no production policy is activated by this command.

## Kubernetes selector label syntax

The server adapter now validates label names and values (ASCII alphanumeric
boundaries, internal dash/underscore/dot, 63-byte bounds, empty values allowed),
and optional lowercase DNS prefixes with total 253-byte bounds. It rejects invalid
syntax in both matchLabels and matchExpressions. The offline selector check now
includes syntax validation. Policy collection, address materialization and runtime
NetworkPolicy integration remain open. Earlier syntax-deferred notes describe
previous gates and are superseded by this adapter validation.

## Actual Kubernetes selector syntax compatibility

Owned Kubernetes v1.37 server dry-run exposed an overly strict DNS-component
length check in the adapter. Removed that check while retaining the API's total
253-byte prefix bound. The maintained `tools/kubernetes_selector_qualification.py`
compares 12 accepted/rejected syntax boundary cases against the actual API and the
real Sumunjang offline command; all agree. Kubernetes objects are dry-run only,
not persisted. Server selector tests and strict clippy pass. This qualification
covers selector syntax, not collection, reconciliation or NetworkPolicy execution.

## Offline NetworkPolicy evaluation adapter

The server now parses networking.k8s.io/v1 NetworkPolicy target selectors,
namespace scope, policyTypes defaults, ingress/egress rules, ipBlock exceptions,
numeric ports/ranges and TCP/UDP/SCTP into the core evaluator. An offline fixture
contains `policy`, `namespace`, `labels`, `direction`, `peer`, `protocol`, `port`;
`--evaluate-kubernetes-policy FILE` reports not_selected, not_isolated, allowed
or denied without DB/listeners. Inputs are bounded to 1 MiB. Unknown spec/rule
fields, selector peers, explicit empty peers, named ports and contradictory
rules/types are explicitly refused, not broadened. This is a supported subset,
not complete Kubernetes conformance or runtime enforcement. Actual API collection,
peer materialization, UID/source freshness and Hangang context remain open.

## Real API-defaulted NetworkPolicy adapter qualification

The maintained owned-cluster tool now passes actual server dry-run JSON responses
into the real Sumunjang offline policy evaluator. Eight evaluations cover ingress
and egress defaulting, explicit egress isolation, empty-rule allowance, default
TCP, protocol mismatch, CIDR exceptions and numeric endPort. All pass alongside
12 selector syntax acceptance comparisons. No objects are persisted and no CNI
packet enforcement is asserted. This bridges API-returned policy shape to the
implemented evaluator; collection/watch, source freshness and runtime integration
remain open. Run `python3 tools/kubernetes_selector_qualification.py --binary
/path/to/sumunjang` against an owned qualification container.

## Malformed peer API compatibility gate

Owned Kubernetes server dry-run rejects `from: [{}]` (a peer must be specified)
and a peer combining ipBlock with podSelector. The local evaluator's existing
rejections agree; the maintained tool now checks both alongside the 20 positive/
syntax cases. An empty ingress rule `{}` permits all peers, while an empty peer
object is invalid. No empty-peer wildcard support was committed or deployed.

## Compiled NetworkPolicy candidate separation

Server policy compilation now owns an immutable target selector and independently
compiled ingress/egress views. Typed decisions reuse that candidate without JSON
parsing, filesystem, database or API access. Offline evaluation compiles once then
calls the same decision method. Regression mutates the original source, compiles a
new deny candidate and proves repeated old/new decisions remain independent; an
invalid replacement cannot alter the old view. Six adapter tests, strict clippy
and the 22 actual owned-API qualification cases pass. No live publication/freshness
state machine is implemented yet; preserving an old candidate in this unit test is
not permission to serve stale authoritative policy. Production remains unchanged.

## Compiled NetworkPolicy sets

The offline adapter now accepts a bounded NetworkPolicyList and compiles every
item before returning a candidate. It rejects a nonempty list continuation token
and invalid members; an incomplete API page cannot silently become a policy set.
Decision evaluation combines selected policies additively: one applicable allow
wins, while unselected policies or policies isolating only the opposite direction
do not clear another policy's denial. Empty/unselected sets report not_selected;
callers must apply ordinary Kubernetes non-isolation semantics rather than treating
that as a zero-trust authorization grant. Seven adapter tests, strict clippy and
22 owned API regression cases pass. Lists currently scan bounded policy candidates;
large-policy indexing, actual pagination collection and runtime freshness remain
open. No production authority is activated.

## Authenticated Kubernetes source observer

`--observe-kubernetes-policy FILE` reads private source config fields api,
namespace, ca and token_env. It requires an HTTPS origin, pins the configured CA,
disables proxies/redirects and marks bearer headers sensitive. Namespaced list
collection is bounded to 32 pages, 4096 items, 1 MiB and one second across the full
collection/compilation. It validates opaque resourceVersion equality between pages,
namespace/UID facts and continuation cycles; fills only omitted item TypeMeta from
the validated collection. All policies must compile before a count/revision report.
It starts no listeners and changes no DB or policy authority.

`tools/kubernetes_source_smoke.py` qualifies the actual executable against an owned
Kubernetes API using a temporary namespace and list-only ServiceAccount. Successful
collection/compilation, invalid-token refusal and cross-namespace RBAC refusal pass;
cleanup deletes only its fixture namespace. Strict server clippy passes. Malicious
pagination/TLS/timeouts, source publication, watch recovery, rotation/pooling and
contextual enforcement remain open. This observer is not production activation.

## Owned TLS source adversarial qualification

`tools/kubernetes_source_adversarial.py` drives the actual observer executable
against an owned TLS server with a private synthetic bearer and generated CA.
Thirteen cases qualify valid empty collection and refusal of wrong collection
kind, missing/changing revision, continuation cycles, duplicate/missing UID,
wrong namespace, contradictory item kind, unresolved policy, slow response,
redirect and >1 MiB body. Deadline refusal is bounded; redirects are not followed;
credential values are absent from stdout/stderr. All pass. The initial fixture
omitted HTTP Content-Length and caused the valid body to be refused; framing was
corrected before qualification. Wrong-CA/rotation and live publication/recovery
remain separate gates. No production policy or binary changes.

## Complete source pagination qualification

The owned TLS source test now includes a successful two-page collection with
stable opaque resourceVersion, distinct UIDs and a continuation token containing
`+`, `/`, `%` and `=`. The peer checks decoded token equality; the real observer
reports exactly two compiled policies after exactly two requests. All 14 source
cases pass, including previously qualified uncertainty refusal. This verifies
complete page assembly and URL encoding, not source publication/watch continuity.

## Source CA boundary qualification

The maintained owned TLS fixture now generates an unrelated CA and confirms the
actual source observer rejects the server when configured with it. The TLS peer
receives zero HTTP requests, so its bearer does not cross an untrusted TLS channel.
Restoring the intended CA permits the subsequent valid pagination case. All 15
source cases pass. This checks fresh-process CA configuration; live key/CA rotation
and persistent transport pool replacement remain unqualified.

## Source object identity completeness

Namespaced source collection now requires bounded nonempty object name, UID and
individual resourceVersion. It rejects repeated names even when UIDs differ,
preventing same-name replacement facts from being combined in one candidate.
Individual object revisions need not equal the collection revision. The owned TLS
fixture covers missing names/revisions and duplicate names; all 18 cases pass.
Actual Kubernetes source/authentication/RBAC smoke and strict clippy also pass.
This does not establish cross-resource atomicity or persistent source ownership.

## Actual Kubernetes pagination and policy lifecycle

The maintained source smoke creates 129 owned policies and verifies the actual
API's first 128-item response carries a continuation token. The observer compiles
all 129. Deleting a policy produces 128 on the next independent collection;
same-name recreation has a different live UID and returns 129 with a changed
opaque collection revision. Invalid credential and namespace RBAC cases still
pass, and the owned namespace is deleted. This qualifies independent recollection,
not continuous watches, request-time withdrawal or 129-policy throughput.

## Continuous diagnostic source snapshots

`--kubernetes-policy-source FILE` now starts a cancellable read-only follower.
It withdraws the diagnostic snapshot before each complete recollection, atomically
publishes a validated candidate and sleeps 500 ms between cycles. Failures leave
no candidate. Snapshot expiry is anchored to collection start plus one second;
evaluation checks expiry before and after the in-memory decision, including when
an old Arc is retained. Stop withdraws the candidate. Admin-authenticated
`GET /v1/kubernetes/status` and `POST /v1/kubernetes/evaluate` expose status and
source-bound diagnostic decisions; caller-supplied labels are admin diagnostic
inputs, not authenticated workload evidence. Response activated remains false.
No native HGD1/Hangang enforcement or policy ownership is changed.

All 30 server tests and strict clippy pass; 18 owned TLS cases and actual
129-policy collection/deletion/recreation/RBAC smoke pass after rebuilding.
The continuous HTTP follower still needs live process/expiry/failure recovery
qualification and console integration. Conservative withdrawal creates temporary
unavailability during collection and is not watch continuity or high availability.

## Live source follower qualification

The maintained real-cluster source smoke now starts an owned Sumunjang server
with a private temporary SQLite DB and loopback management listener. Its
admin-authenticated diagnostic evaluation returns denied from 129 source policies.
An invalid admin credential returns 401. Atomic source-config replacement selects
an invalid token reference; after the previous one-second window, repeated queries
return 503 for the entire sampled failure interval. Restoring the valid reference
republishes a verified denied candidate. The server is terminated and its owned
namespace cleaned up. The same run preserves pagination/deletion/recreation/RBAC
gates. This verifies conservative follower withdrawal and recovery, not immediate
remote revocation, continuous watch availability, native request enforcement or
production deployment. Actual token/CA material rotation still needs qualification.

## Kubernetes source console diagnostics

Dashboard and generated Hangang console package now include a Kubernetes source
tab, source status and namespace/peer/direction/protocol/port/target-label diagnostic
query form. Manifest v0.1.2 permits only read-only status/evaluate routes; source
configuration and activation are not exposed. Failed reads replace old status or
results rather than leaving stale success visible. English/Korean labels follow
the host locale. Actual Chromium qualification covers mount, tab, status, denied
query, unavailable state, Korean switch and disposal using a mocked context API.
It also exposed self-translation MutationObserver loops; generation now skips
unchanged text/placeholder translations. Asset digests are regenerated.

`tools/kubernetes_plugin_browser.py --chromium /path/to/chromium` reproduces this
browser qualification. Actual Hangang proxy/runtime source integration and internal
package rollout remain open; production UI/backend are unchanged.

## Sumunjang console rollout attempt and rollback — 2026-10-14

The c9b4fb8 release binary passes all 18 owned TLS source boundary cases. Internal
backend/plugin replacement retained binary, stopped DB and registry backups, but
the existing whole-chain service probe failed. Both deployment attempts rolled
back to the previous backend and plugin v0.1.1. Console/backend services are active;
direct authenticated mTLS HGD1 and actual HTTPS console/SSO/logout isolation pass.
No Kubernetes production source was enabled.

The owned service-probe credential has expired. Limited six-hour rotations keeping
the same service identity/scope also failed verification and were rolled back;
runtime environment readback confirmed the candidate key was delivered, but direct
Hopae verification returned 401. The cause of rotation refusal remains unresolved.
The original expired credential/configuration are restored; no production user
credential was changed. Do not report plugin v0.1.2 as deployed or treat this as a
qualified new rollout. Next gate is authenticated native/HTTP probe diagnosis and
verified owned credential rotation before retrying the concrete retained package.

## Corrected credential rotation and completed internal console rollout

Rotation refusal was traced to intended durable authority: authentication profile
DB publication overrides bootstrap JSON after first activation. File-only expiry
edits therefore left the durable expired credential policy unchanged. Corrected
rotation updates the owned probe secret and publishes only its six-hour expiry
through the authenticated Hangang/Hopae profile editor with revision protection;
all other durable profile configuration, identity and permission scope are retained.
Readback matches, direct Hopae verification and gateway API checks pass; the retired
credential returns 401 while the current credential returns 200. Production user
credentials were not changed.

The c9b4fb8 Sumunjang backend and digest-pinned console plugin v0.1.2 are now
internally deployed with previous binary, stopped SQLite and registry backups.
Actual HTTPS Hangang browser qualification covers the Kubernetes tab, delegated
status/query proxy and unconfigured-source refusal, existing Pumgye/Hopae menus,
permission matrix, SSO and logout cleanup. Native mTLS HGD1 and API authentication/
authorization pass. An initial browser assertion used eval prohibited by existing
CSP; the verifier now supplies a function without weakening CSP. Production
Kubernetes source remains unconfigured, and diagnostic results are not enforcement.
Public release tags and GitHub Actions were not changed. These successful gates
supersede the earlier unresolved rollout status, not its factual failure record.

## Compilation freshness boundary

SourceSnapshot construction now refuses a candidate whose synchronous compilation
finishes at/after the one-second collection-start deadline. Tokio timeout alone
cannot interrupt synchronous compilation; follower publication already checked
expiry, but the one-shot observer could previously report a stale candidate as a
successful observation. Both paths now share the checked constructor. A late
completion regression and all ten Kubernetes adapter tests pass; strict clippy
passes. This prevents late authority creation rather than claiming preemptible
CPU work. Production diagnostic binary is unchanged pending rollout qualification.

## Diagnostic status freshness and credential boundary

The authenticated Kubernetes status endpoint now returns 503 for an expired
retained snapshot instead of a successful stale report. In-process source reports
still carry freshness for diagnostics. HTTP route regressions prove collector
credentials cannot inspect/evaluate Kubernetes policies (401), and authenticated
admins receive 503 without a candidate. All 32 server tests pass; strict clippy
passes. The deployed diagnostic binary is unchanged; this source correction and
compilation-deadline fix await rollout qualification together.

## Freshness fixes internally deployed — 2026-10-14

Sumunjang `df394d9` optimized release passes 18 owned TLS source boundary cases
and the actual Kubernetes 129-policy pagination/deletion/recreation, authenticated
follower withdrawal/recovery and admin-boundary smoke. Its backend is now deployed
internally with prior binary and stopped SQLite backup. Actual Hangang browser
Kubernetes diagnostics/unconfigured-source refusal, native service API permissions,
SSO/logout and mTLS HGD1 regressions pass. Console plugin v0.1.2 and registry bytes
are preserved. Production Kubernetes source remains unconfigured; no release tag
or GitHub Actions activation changed. This rollout includes compilation-deadline
refusal and expired diagnostic status refusal. Full network source enforcement,
selector peer resolution, watch continuity and distributed source ownership remain.

## Safe source diagnostic lifecycle states

Admin status errors now distinguish disabled, collecting, failed and stopped
source states with bounded static labels; they never expose source configuration,
raw upstream errors or credentials. Snapshot validity remains the authority gate,
independent of diagnostic phase metadata. The UI replaces old success and displays
the safe failure reason; generated plugin v0.1.3 has regenerated asset hashes.
All 32 server tests and strict clippy pass. Actual Kubernetes follower failure
sampling checks status/evaluation 503 with failed/collecting state and activated
false, plus recovery and all earlier source lifecycle gates. Chromium mock-context
qualification confirms reason display and locale/disposal. Production backend and
plugin remain at the previous qualified deployment pending rollout of this change.

## Persistent source transport pool

The follower now reuses a pinned reqwest client while actual CA bytes, sensitive
bearer header and API origin are unchanged. Changed material drops the old pool
before replacement; any failed/stale collection drops it too. Each cycle still
rereads bounded config/CA and credential references and fully recollects policy.
Idle transport is bounded to two connections/origin and ten seconds. This is
connection reuse, not permission caching or extended snapshot freshness.

All 32 server tests, strict clippy and actual 129-policy follower/RBAC lifecycle
smoke pass. The owned HTTP/1.1 TLS fixture proves at least three successful cycles
use exactly one connection; wrong-CA replacement refuses candidate use and trust
restoration succeeds on a new connection. All 18 boundary cases still pass.
Expected peer disconnect errors are suppressed in the fixture; unexpected errors
remain visible. Live bearer rotation and sustained collection throughput remain
separate qualifications. Production retains the prior qualified backend.

## Source bearer rotation and pool recovery qualification

The owned persistent TLS fixture now switches the source to a second declared
bearer reference while the peer retires the original credential. It records only
in-memory connection identities for assertions and proves the new credential is
authenticated on a new connection, not the prior pool. Selecting an invalid
reference withdraws the candidate; restoring the valid rotated reference recovers
on another newly authenticated connection. Follower stdout/stderr are checked for
original/rotated bearer and administrator secrets. These gates and all 18 earlier
TLS boundary cases pass. This is reference/material switching within one process,
not Kubernetes Secret watch delivery or mutation of process environment values.
Production deployment remains unchanged.

## Deletion-in-progress source fencing

Collection refuses a policy with non-null deletionTimestamp instead of compiling
it or silently omitting it from an authoritative set. This conservatively makes
the candidate unavailable until complete reconciliation; it is not a claim that
Kubernetes/CNI policy deletion is instantaneous. The owned real API fixture holds
one policy using its own finalizer, requests deletion, verifies deletionTimestamp
and proves the actual observer refuses collection. It removes the finalizer and
cleans its namespace. Nineteen TLS cases (including deleting policy), persistent
pool/credential recovery, actual pagination/lifecycle/follower smoke and strict
clippy pass. Production remains at its previously qualified deployment.

## Pooled source diagnostics internally deployed — 2026-10-14

Optimized Sumunjang `ae1cde6` and digest-pinned plugin v0.1.3 are now deployed
internally. Before rollout the release passes 19 owned TLS cases including pool
reuse, CA/material replacement and credential failure/recovery; actual Kubernetes
129-policy pagination/deletion/recreation/deletion-in-progress/follower/RBAC
qualification; and Chromium mock-context UI qualification. Previous binary,
stopped SQLite and registry backups are retained. Live API permissions, native
mTLS HGD1, Pumgye/Hopae menus, matrix, SSO/logout and actual Hangang Kubernetes
diagnostic proxy pass. The browser visibly shows disabled for unconfigured source,
rather than stale normal status. Production source remains unconfigured; diagnostics
are not gateway/CNI enforcement. Public release tags and Actions are unchanged.

## Namespace-indexed compiled policy candidates

CompiledPolicySet now owns policies grouped in a BTreeMap by namespace, with a
separate total policy count. Decisions perform an allocation-free borrowed namespace
lookup and evaluate only that namespace's candidates; unrelated namespace grants
cannot contribute. Compilation and indexing remain off the request path. A 64-
namespace fixture verifies alternating deny/port grants, opposite-direction
non-isolation, port boundaries and absent namespace handling. All 33 server tests,
strict clippy and actual 129-policy source/follower lifecycle qualification pass.
This is structural lookup optimization, not a new measured throughput claim.
Same-namespace selector/rule indexes and contextual enforcement remain open.
Production retains the previously qualified backend.

## Explicit peer wildcard versus empty resolved set

Core NetworkPeers now distinguishes All from Resolved(addresses). An empty resolved
set denies all peers; it cannot become a wildcard when a selector resolves to no
live Pods. NetworkRule::with_peers exposes this explicit form. The compatibility
constructor retains Kubernetes omitted/empty peer-array semantics for current IP
rules. IPv4, IPv6 and mapped-IP regressions prove the distinction. All 29 core
tests, 11 server adapter tests and strict clippy pass. Actual selector materialization
is still required; this typed foundation does not claim its implementation or
production enforcement. Production backend remains unchanged.

## User-designated remote k3s qualification and disk maintenance

Source smoke now supports an explicit kubectl wrapper and direct HTTPS API origin,
in addition to the owned local container default. It obtains the namespace CA
from kube-root-ca.crt and issues a namespace list-only ServiceAccount token; no
manager kubeconfig/token is emitted. The user-designated remote k3s v1.37.1+k3s1
passes 129-policy pagination, deletion/UID recreation/deletion-in-progress refusal,
invalid-token/RBAC boundaries and a local follower's failure/recovery/admin checks.
The temporary namespace is removed; node/DNS/existing HTTP and service health
checks pass. This tests remote source integration, not deploying all components
into Pods or packet/CNI enforcement. Remote operational records are kept with its
management workspace; public examples contain no actual host inventory.

`tools/clean_build_cache.py` defaults to inspection and requires --apply to remove
only explicit Cargo repositories' non-symlinked target/debug/incremental caches.
It refuses cleanup while cargo/rustc is active, retains release binaries and all
runtime/state/credential/rollback data, and reports free space. About 6 GiB of
reproducible Sumunjang/Pumgye incremental caches were removed. Check disk usage
before/after substantial builds periodically as requested; do not globally prune
Docker or operational volumes.

## Exact resolved-host peer index

Core NetworkPeers::hosts builds an exact /32 or /128 radix index from at most
4096 source addresses. Mapped IPv4 canonicalizes and duplicates coalesce; empty
input matches nobody. Unspecified, multicast and loopback inputs are refused.
Lookups allocate nothing and do not scan every host. This represents trusted
materialization output, not authentication by IP. Thirty core tests and strict
clippy pass. Pod/Namespace source parsing, UID/lifecycle reconciliation, named
ports and enforcement integration remain required. Incremental compilation was
disabled for these checks to avoid rebuilding the recently cleared disk cache.

## Pure Pod peer materialization

Core pod_peers::resolve now maps bounded complete Namespace/Pod facts through the
combined selector into exact host peers. It validates unique names/UIDs, namespace
UID associations and nonambiguous canonical live addresses. Deleting Pods contribute
no addresses; selected hostNetwork Pods refuse materialization because their network
semantics are not qualified. Empty results remain deny-only. Namespace UID is an
assembler association, not a Kubernetes Pod field; callers must establish cluster,
completeness, freshness and coherent lifecycle before supplying these facts. IP
membership is not authentication. All 32 core tests and strict clippy pass. Actual
API fact collection, cross-resource reconcile fences, named ports and enforcement
remain required. Production remains unchanged.

## Pod address reuse uncertainty and functional test priority

Deleting normal Pods contribute no peer grants but their reported addresses still
participate in ambiguity validation. A deleting Pod and a different live Pod with
the same canonical address refuse the candidate until coherent replacement facts
are supplied. All 33 core tests and strict clippy pass. Runtime API assembly and
actual enforcement remain open; production is unchanged.

The user clarified that the newly available remote Kubernetes environment is for
functional/integration qualification first. Prioritize actual resource ingestion,
identity/permission boundaries, withdrawal, lifecycle recovery and console flows.
Do not expand the current remote test work into load benchmarks or require extra
physical servers/load generators. Long-term throughput requirements remain separate.

## Namespace/Pod API fact parser

Server `--check-kubernetes-pod-facts FILE` parses bounded original v1 NamespaceList
and PodList responses, requiring complete lists and bounded name/UID/revision facts.
It validates labels, deletion state, hostNetwork type and primary/podIPs consistency.
Pod namespace UID is associated with the supplied Namespace collection, not read
from a nonexistent Pod field. Reports explicitly mark cross-resource coherence
unqualified and enforcement inactive. Twelve adapter tests and strict clippy pass.
Read-only qualification against the user-designated remote k3s passes using actual
API envelopes. kubectl's reconstructed generic List output was replaced with raw
API reads, not accepted as an authoritative collection. Coherent collection/barriers,
selector rule compilation and actual enforcement remain open.

The user requires all four components as one Hangang-integrated native Kubernetes
package, with Hangang World zero-trust authority as the original domain source.
Individual adapters are intermediate gates, not final success. Before subsequent
cluster-changing tests, create/verify node backups and record recovery paths;
prioritize functional tests in the supplied environment.

## Console plugin locale lifecycle internally deployed — 2026-10-15

Guard console plugin v0.1.4 (source `d314d87`, public release
`console-plugin-v0.1.4`) re-renders authority status, cards, refresh times and
dirty markers from cached state when the host locale changes. It uses the host
`onLocaleChange` notification (Hangang `13983ec`) and falls back to observing the
document `lang` attribute on older hosts; drafts are not refetched or replaced.
The public release round trip and package verification pass. Guard 0.1.4 and
Hopae 0.1.6 are installed internally with a backup; core binary, backend
bindings, runtime argv/environment and policy/profile documents are unchanged.
The first upgrade attempt rolled back safely on unstable systemd ExecStart
metadata comparison; the corrected stable comparison passed. Real HTTPS Chromium
qualification passes English/Korean switching without remount, back/forward,
390px layout without overflow, GET-only plugin requests, logout disposal and no
page errors. No policy mutation was exercised. This is a console package change
only; no server, cluster or enforcement change.

## Policy-change audit, explain/what-if and decision evidence — 2026-10-16

Owner APIs for zero-trust ADR 0019/0020 (branch `feat/audit-explain-api`, not
deployed). Every admin mutation (policy and policy document, blocks, candidate
approval, JSON/Lua rules, GeoIP reload, update check, Kubernetes authority
content changes, startup imports) writes an audit row with actor, action,
target, before/after digests, summary, result and revisions. Committed rows share
the checkpoint transaction, so an audit failure refuses the change; refusals are
recorded best-effort and update requests use a two-phase uncertain record.
Retention is bounded by rows and days. `GET /v1/audit` and `POST /v1/audit/query`
filter and paginate by cursor. A signed Hangang broker actor assertion is verified
(HMAC under the admin credential, method/path/body/freshness/nonce) and an invalid
one is refused. `POST /v1/explain` traces the published or a never-stored
candidate policy/rules/Lua through the same evaluation function as live decisions;
`POST /v1/explain/batch` reports impact for up to 1,024 addresses; `GET /v1/reasons`
serves `sumunjang.*` en/ko catalogs. gRPC `include_evidence` and HTTP
`"evidence": true` add rule IDs, ASN, country, reason code and the enforce outcome;
HGD1 is unchanged. Console package 0.1.5 declares the read-only routes. Core 38 +
no_alloc 2, server 72, update 16 tests and strict Clippy pass; a local real-process
HTTP smoke passed. Open: Python gRPC smoke with the new field, Hangang client
adoption of evidence and actor delegation for the Guard binding, console views,
`NetworkZone` ownership (ADR 0021/0022), explain rate limits per actor and audit
export/forwarding to the unified console store.

## Console Network API gaps — 2026-10-16

Branch `feat/console-api-gaps` (on `feat/audit-explain-api`; local, not pushed
or deployed) closes gaps found by the console Network rebuild, additively:
bounded per-minute per-address signal history (`/v1/history`, memory only,
`--history-hours`), per-signal counts and country on candidates, block
provenance (source/created_at/created_by) recorded outside the wire shape and
used for reason codes, rules compare-and-set (`/v1/rules/document`,
`expected_revision`, 409 with `current_revision`; unconditional writes
deprecated) with retained Lua source, offline ASN catalog listing
(`/v1/asn/catalog`), optional audited change reasons, and allowlist entries with
expiry/reason under compare-and-set (`/v1/allowlist`) while legacy policy writes
keep entry metadata. Console package 0.1.6 declares 31 routes. Core 42 +
no_alloc 2 and server 78 tests and strict Clippy pass. Open: console views,
history persistence across restarts (deliberately not done), allowlist expiry
cleanup job, ASN proposal workflow, removal of deprecated unconditional rules
writes after clients migrate.

Follow-up decisions applied on the same branch: allowlist-only changes keep the
evidence window; expired allow entries stay visible for 30 days
(`--allow-expired-retention-days`) and are then pruned as an audited
`allowlist.expire` change; history stays in memory and reports `in_memory` and
`retained_since`; the rules revision (lineage + sequence) is persisted so CAS
survives restarts. Core 43 + no_alloc 2 and server 79 tests and Clippy pass.

The policy document revision (lineage + sequence) is now persisted the same
way, so policy and allowlist compare-and-set also survive restarts.

## Network zones — 2026-10-17

Branch `feat/network-zones` (on `feat/console-api-gaps`; local, not pushed or
deployed) implements Sumunjang-owned `NetworkZone` (ADR 0021/0022): named
IPv4/IPv6 prefix sets with display name, description and owner, bounded to the
Pumgye contract (≤ 64 zones, ≤ 65,536 prefixes, `[A-Za-z0-9_.:-]{1,128}`), a
persisted monotonic zone revision, CAS + reason + audit admin API
(`/v1/zones`), the exact Pumgye snapshot (`/v1/zones/snapshot`, revision and
digest headers, unsigned until ADR 0021 P1), an allocation-free zone mask trie
(no_alloc extended), explain `zone` stage and HTTP/gRPC evidence zone ids.
Console package 0.1.7 uses all 32 broker routes. Core 46 + no_alloc 2 and
server 82 tests and Clippy pass. Open: ADR 0022 NetworkZone/NetworkControl CRD
source, signed snapshot fetch (PPG2/HGD), Pumgye import automation, broker
route limit (plugin contract v2).

## TLS hot reload and HTTP readiness — 2026-10-17

Remote k3s qualification showed renewed cert-manager certificates were served
only after restart. Branch `feat/tls-hot-reload` (on `feat/network-zones`;
local) polls the decision TLS cert/key/CA by content digest
(`--tls-reload-seconds`, default 10, no inotify), rebuilds the HGD1, gRPC and
management HTTPS rustls configurations from one consistent read and swaps them
atomically; existing connections keep their sessions. Invalid material is
refused, the old certificate keeps serving and `/v1/status` `tls` exposes
fingerprint and reload/failure counters. gRPC TLS now terminates in Sumunjang
before tonic. Outbound Kubernetes/update clients already re-read CA files.
`/readyz` also fails while the latest checkpoint failed; the deployment template
adds an HTTP liveness probe. Server 86 tests (real HGD1/gRPC/HTTPS reload
handshakes and a tonic mTLS call) and Clippy pass. Open: re-run the remote k3s
rotation qualification; Prometheus-style metrics endpoint.

## Prometheus metrics — 2026-10-17

Branch `feat/metrics` (on `feat/tls-hot-reload`; local) adds `GET /metrics`
(Prometheus text 0.0.4) on the management listener — HTTPS/mTLS with
`--management-tls`, authorized by an optional read-only
`HANGANG_GUARD_METRICS_TOKEN` or the admin credential. Bounded labels only:
decisions by transport/mode/outcome/reason code, unavailable fences,
per-transport latency histograms, evidence and capacity counters, candidates,
blocks by source, allowlist, zones, rules, history, checkpoints, admin change
results, TLS reload counters and leaf expiry, GeoIP and Kubernetes source
freshness. Hot-path recording is atomic and allocation-free (no_alloc covered);
DecisionRef now carries its reason code. Core 47 + no_alloc 2 and server 88
tests and Clippy pass. Open: chart ServiceMonitor/PrometheusRule in the world
package, OpenMetrics content negotiation.

## ASN prefix pools and reviewed ASN block proposals — 2026-10-17

Original requirements steps 4–6, branch `feat/asn-proposals` (on `feat/metrics`;
local). Signed `sumunjang.asn-bundle.v1` ASN prefix bundles (dedicated Ed25519
key, domain-separated envelope, offline signer and import CLI, upload API,
optional scheduled HTTPS fetch with no default URL, monotonic versions,
last-good rollback, diff report, audited install). ASN block proposals with
full-ASN / selected-prefix / /24-/48 aggregate scopes, impact analysis (address
estimates, tracked evidence and history, current and enforce decision preview,
allowlist/zone/block collisions, attachable decision-log counts), a configurable
two-person rule, audited draft→pending→approved/rejected→active→expired/withdrawn
lifecycle with CAS, and explicit activation into `asn_proposal` blocks only.
Console package 0.2.0 moves to broker contract v2. Core 47 + no_alloc 2, server
93 and update 17 tests and Clippy pass. Open: Hangang decision-log facets pulled
automatically (currently attached by the console), console views, bundle
publishing pipeline from a licensed provider, LLM-assisted allowlist review
(step 5 remains manual/reviewed).

Evidence risk bucket (branch `feat/evidence-score`, local): gRPC
`NetworkEvidence.risk_score` (13) / `risk_stage` (14) and HTTP evidence `risk`
add a coarse 0–100 score in tens and the suspicion stage, computed
allocation-free and without waiting on the engine lock.
