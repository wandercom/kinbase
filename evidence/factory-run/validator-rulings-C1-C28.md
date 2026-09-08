# Validator rulings on interface conflicts C1–C28

Principle applied, in order: (1) the ratified spec wins over the instrument; (2) where the
spec is silent on a shape, the instrument's shape becomes the contract for this
generation; (3) where the instrument demands something a blind Coder cannot know, the
instrument is defective and the Tester repairs it. Each ruling names who acts:
**PRODUCT** (Coder implements), **INSTRUMENT** (Tester repairs), or **BOTH**.

- **C1 — user config never written. INSTRUMENT + PRODUCT.** The instrument must write the
  launcher user config at `${XDG_CONFIG_HOME:-$HOME/.config}/guildhall/config.toml`
  (0600) with exactly the cli.md keys, using an isolated `HOME`/`XDG_CONFIG_HOME` per
  world, before any command that needs Company, cache, certificate, or Personal. The
  product resolves config only from that path (honouring both variables) and never from
  the worktree or the environment.
- **C2 — certificate inside worktree. INSTRUMENT + PRODUCT.** The steward certificate is
  installed with `repo init --repo PATH --certificate <file outside the worktree>`; the
  product copies it into the out-of-worktree Company cache root (0700) keyed by
  repository UUID and reads it only from there. A `.kin/certificate.json` inside the
  worktree is inert: counted as a foreign path, never trusted. "Uncertified" is
  constructed by withholding the cache/config, not by deleting a tracked file.
- **C3 — trusted results without anchors. INSTRUMENT.** V-5, V-7, NF determinism and
  diagnostics worlds must establish anchors (service, root key, certificate, registry,
  user config) exactly as the other gates do. The product's behaviour without anchors is
  the spec's: `UNVERIFIED`, empty trusted projection, typed status.
- **C4 — signing convention. BOTH.** One convention: the signed bytes are the JCS of the
  document with `signature` removed and `signer` (64-hex Ed25519 public key) present;
  `signature` is 128-hex over `signing_digest(message_type, jcs_bytes)`. The authority
  registry is one document `{"schema":"guildhall-authority-registry/1","authority_cursor",
  "entries":[...]}` signed by the steward root key as message type
  `authority-registry-entry`. The Tester converges all three conventions to this one.
- **C5 — request signature type and client key. PRODUCT (ruling R-4 stands).** Request
  signatures use message type `receipt` over `{"method","path","body_sha256","nonce",
  "expires_at"}`. Client keys bind on first successful use per token (R-4).
- **C6 — token authority for writes. PRODUCT.** Registry publication is authorised by the
  document's steward root-key signature; fact admission by the registered in-scope
  authority's signature; both require only a valid token plus a valid request signature.
  Service config accepts an optional `facts_token_scopes = [exact scope strings]`; when
  absent, the facts token may read exactly the scopes present in the admitted authority
  registry; any wildcard, prefix, glob, or empty-string entry is `CONFIG_INVARIANT` at
  startup. Facts token scopes: `facts:read`, `questions:write`. Directory token scopes:
  `directory:read`, `admin:issue`. Endpoints: `POST /v1/authority-registry`, `POST /facts`
  (aliases `/v1/facts`, `/v1/company/facts`), `GET|POST /questions`, `POST /answers`,
  `GET /status`, `GET /facts`.
- **C7 — Company/Personal events inside `.kin/`. INSTRUMENT + PRODUCT.** Company events are
  admitted through the service; Personal facts never enter `.kin/`. The instrument plants
  Company facts via `POST /facts` and Personal material via host transcripts only. A
  `.kin/events/` file whose `store_kind` is not `codebase` is a foreign event: counted,
  typed, never trusted.
- **C8 — session identity. INSTRUMENT.** `SESSION` is the id returned by `session start
  --json`; the instrument must use it.
- **C9 — `hooks install --approve`. BOTH.** No bypass flag exists; an unknown flag is a
  typed usage error (exit 2). `hooks install <host>` writes exactly the diff shown by
  `hooks plan` into the host's user-level config under `$HOME`, exits 0 with the plan
  digest, and never touches the host's project settings. The host presents its own
  approval at its next start; `doctor` reports `HOOK_APPROVAL_REQUIRED` while the host
  config lacks the planned entries. The instrument drops `--approve`.
- **C10 — `.kin/manifest`. INSTRUMENT.** The directory is `.kin/manifests/`.
- **C11 — unknown `.kin/config` key. INSTRUMENT.** Unknown keys fail closed (cli.md). A
  discovery-hint change is expressed through the Git remote URL, not `.kin/config`.
- **C12 — undeclared flags. PRODUCT (R-1 extended).** `--as-of`, `--reducer-version`, and
  `--authority-cursor` are optional on every reducer-invoking command; omitted values come
  from the recorded proof clock / current reducer / current cursor and are echoed in output.
- **C13 — event vocabulary. INSTRUMENT + PRODUCT.** `atom_kind` is exactly one of `claim`,
  `question`, `decision`, `constraint`, `rationale`, `observation`. Lifecycle actions the
  spec names but omits from the message-type enum (`misextraction`, `never_true`,
  `support_withdrawn`, `orphan_abandoned`, `manifest_observation_expired`, `relaxation`,
  `exception_request`, `unreachable_clone_residual`) are FactEvent messages signed as
  `fact-event` whose `disposition` is the action name and whose `parents`/`supersedes`
  name the affected events. `distortion` is exactly `{trigger, loss_if_absent, rationale}`.
  Dispositions: `draft`, `proposed`, `accepted`, `approved`, `merged`, `rejected`,
  `reverted`, `deployed`, `retracted`, `superseded`, plus the action names above.
- **C14 — non-unique `event_id`. INSTRUMENT + PRODUCT.** `event_id` is unique per event
  (the instrument derives it from the event's content digest). The product keys identity on
  the content-addressed digest and refuses a second event reusing an `event_id` with
  different bytes as `DIGEST_MISMATCH`.
- **C15 — instrument-private lifecycle taxonomy. INSTRUMENT.** `status --json` reports
  per-adapter receipt counts and per-observation `disposition`/`state`
  (`current|stale|retracted|foreign|quarantined`); the instrument derives its matrix from
  those observable fields and never asks the product to echo cell names or
  mutation outcomes.
- **C16 — host invocation witness. INSTRUMENT + PRODUCT.** The instrument places its host
  wrapper first on `PATH` of every product invocation. `hooks plan --json` emits
  `files[].path` relative to `$HOME`, plus `commands[]` and `permissions[]`.
- **C17 — Personal descriptor detection. PRODUCT.** With C1 the product knows the Personal
  root; shared processes refuse any inherited descriptor under it (device/inode) and any
  descriptor outside the frozen allowlist, both as startup failures.
- **C18 — malformed invocations. PRODUCT.** A usage error (unknown flag such as `--all`,
  `--accept-all`, `--yes-to-all`, `--approve`; missing positional; malformed value) emits
  the typed error object with `code: "CONFIG_INVARIANT"` and exit 4. A decision or show
  that names no candidate, or `--destination codebase:none`, emits `APPROVAL_EXPIRED`
  (exit 2). Exit 1 never occurs; the top-level boundary maps any uncaught failure to
  `RUN_INTEGRITY_FAILED` exit 70.
- **C19 — repeated decisions on one candidate. PRODUCT.** A decision on a consumed or
  expired candidate returns `APPROVAL_REPLAY` (exit 4) or `APPROVAL_EXPIRED` (exit 2);
  never exit 1.
- **C20 — atomisation exact-match. NOTE.** Measurement gap in the instrument; not gating.
- **C21 — broken kindex lifecycle fixture. INSTRUMENT.** Repair the column/key mismatch; the
  `kindex` adapter's native schema is Kindex 0.36.0's export (`nodes(id, node_type, title,
  content, payload, created_at)` plus `edges`).
- **C22 — Company fact admission body. INSTRUMENT.** `POST /facts` bodies are FactEvents
  (architecture §3 field set, `schema: "guildhall-event/1"`) signed as `fact-event`.
- **C23 — single-line `--json`. PRODUCT.** Every stdout line and every stderr line under
  `--json` is one complete JSON document.
- **C24 — foreign artefacts under `.kin/`. PRODUCT.** `fsck`/`ingest`/`status` count
  non-reserved paths as `foreign_paths` and continue; malformed files inside
  `.kin/events/` or `.kin/manifests/` are typed integrity failures (`DIGEST_MISMATCH`,
  `MANIFEST_INCOMPLETE`, `SIGNATURE_INVALID`) with counts, never crashes.
- **C25 — empty-stdin SessionStart. PRODUCT.** Empty stdin is a minimal native envelope
  with `cwd` = process cwd; the SessionStart payload is still produced.
- **C26 — `--key-file`. PRODUCT.** Informational; refusal of an impostor is by registry
  lookup (`AUTHORITY_WRONG_SCOPE`).
- **C27 — p95 includes process start. PRODUCT.** Accepted; the binary is native.
- **C28 — `GUILDHALL_COMPANY_URL`. INSTRUMENT + PRODUCT.** The product never reads a Company
  endpoint from the environment; an env-supplied endpoint yields `PROCESSOR_UNAUTHORIZED`
  with zero connections. The blackhole/timeout probe configures its endpoint through the
  user config.
