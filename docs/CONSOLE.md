# Hangang console integration

[한국어](ko/CONSOLE.md) · [Documentation](README.md)

Guard is a native Hangang sidebar entry through an operator-installed trusted
console package. Generate it with `python3 tools/build_console_plugin.py`.
The generated `plugins/guard` manifest pins its JavaScript, HTML and stylesheet;
configure the reviewed manifest SHA-256 in Hangang's `--admin-plugins` registry.
An optional native `hangang-console` adapter can reuse an already running native
Hangang admin authority. No Guard account/password database is introduced.

The package reuses Guard's management functions: candidates, block/allow pools,
policy editing, IP/CIDR scoring and GeoIP inspection, structured/Lua rules,
GeoIP database reload, metrics and signed-update status/check. Its own token form
is removed. Host authentication supplies each registered call; the Guard admin
credential exists only in the server-side broker environment. Collector credentials
and decision endpoints are excluded from this management allowlist.

The host admits only current enabled administrators, rechecks authority before
backend dispatch and response disclosure, bounds requests/responses and persists
mutation intent/outcomes with actor and body hash. Viewers are denied. The host
owns account/session revocation; Guard continues to own network policy and state.
Already accepted backend mutations are not globally atomically revoked.

Packages are trusted same-origin code and must be reviewed; imports are not a
sandbox. Startup verifies immutable pinned files and rejects tampering/unsafe
permissions. Restart with a new pin to activate an update. No credentials or
backend origin appear in browser discovery. Keep package/config/audit paths
protected, and place public plaintext console adapters behind TLS/access controls.

The UI follows native Hangang light/dark theme variables, locale selection and
navigation lifecycle. Hidden views stop periodic requests; logout disposes views
and rejects late operations. Policy drafts remain while navigating other views.
Backend failures are visible and do not trigger automatic mutation retries.

Qualification includes reproducible package generation, hash/allowlist/credential
checks in the host, actual browser navigation/lifecycle and real-process management
operations. Refer to Hangang's `docs/CONSOLE_PLUGINS.md` for registry configuration
and to the zero-trust design repository for ontology/automation plans. Console
integration does not itself implement pentest orchestration or ontology decisions.

Policy publication uses `GET /v1/policy/document` → `{revision, policy}` and
`PUT /v1/policy/document` with `{expected_revision, policy}`. The opaque revision
is carried in JSON so the Hangang broker need not forward conditional headers.
Comparison, validation, durable checkpoint and publication share the engine write
lock. A stale revision returns HTTP 409 without changing state; the UI retains
the draft and requires an explicit reload/reconciliation. Allowlist saves use the
loaded document revision too, without a fresh GET followed by an unguarded PUT.
Revisions change on every successful policy replacement, including native legacy
writes; unrelated observations do not change them. The revision
(`<lineage>:<sequence>`) is persisted in the checkpoint, so a restart keeps it
and console compare-and-set on policy and allowlist does not spuriously
conflict. The random lineage belongs to the database, so revisions from another
server or a fresh database never match. Restoring an older checkpoint rolls the
sequence back with its policy; reload after restores. Checkpoints written by
older versions start a new lineage once.

Legacy `GET/PUT /v1/policy` retain their original bare Policy wire format and
unconditional write semantics for native clients. Those clients remain exposed
to lost updates until migrated to the document endpoint. Deploy the backend
before the regenerated package; review and repin its manifest in the host. The
new UI fails closed against an older backend rather than falling back to legacy
writes. This does not change administrator admission or policy source ownership.

During policy/allowlist publication, draft inputs are disabled until the request
and refresh finish. A valid write acknowledgement updates the known revision
immediately; a later refresh failure says “Change accepted” and does not turn
the accepted write into a retryable failure. Network failures, ambiguous server
errors, and invalid acknowledgements retain drafts and disable both save actions.
Only an explicit successful fresh policy reload clears that uncertainty; reload
replaces the draft, so copy any local changes needed for reconciliation first.
A 409 retains the draft and is never retried automatically.

## Audit and explain routes (package 0.1.5)

Package 0.1.5 declares read-only broker routes `audit` (GET), `audit/query`,
`explain`, `explain/batch` (POST, `mutation: false`) and `reasons` (GET); assets
and UI are unchanged. Deploy the backend first, then review and repin the new
manifest. The broker forwards no query strings, so console audit filters and
cursors use `POST audit/query`. To record the console administrator instead of
the shared credential, set `"delegate_actor": true` and
`"delegation_authority": "hangang"` on the Guard binding with the Guard admin
credential (≥ 32 bytes) as `token_env`; Sumunjang verifies the signed actor
assertion and refuses invalid ones. See [audit and explain](AUDIT_EXPLAIN.md).

## Network API routes (package 0.1.6)

Package 0.1.6 adds `rules/document` (GET), `history/query` and
`asn/catalog/query` (POST, read-only) and `allowlist` (GET; POST and DELETE as
mutations). Prefer the compare-and-set rules and allowlist writes; see
[console Network APIs](CONSOLE_NETWORK_API.md).
