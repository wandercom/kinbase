# Validator rulings addendum 2 (2026-09-08)

- **R-7 (resolves C9 vs C18).** An unknown or forbidden flag (`--approve`, `--yes`,
  `--all`, `--accept-all`, `--yes-to-all`, any unlisted flag) is a typed usage error:
  `code: "CONFIG_INVARIANT"`, exit 4, no state change. C9's "exit 2" wording is
  withdrawn. The instrument may accept exit ∈ {2,4} for this probe; the product emits 4.
- **R-8 (Company criticality).** A Company fact's criticality is carried in
  `distortion.loss_if_absent` with exactly the vocabulary `safety_critical` | `advisory`;
  `CompanyReference.company_criticality` copies that value. Both lanes use this.
- **R-9 (local dependence class).** The maintainer's `local_dependence_class` is a
  Codebase `constraint` FactEvent at logical key `<reference logical key>/local_dependence_class`
  whose `statement` is exactly the class token (`safety_critical` | `advisory`). Projection
  applies the stricter of R-8 and R-9 and records which dominated.
- **R-10 (revocation).** A key or authority revocation is expressed by the steward
  republishing the authority registry at a strictly newer `authority_cursor` without the
  revoked entry (or with the rotated key); the cursor at which the entry vanished is the
  revocation cursor. The product treats registry republication as the revocation event and
  runs the architecture §3 cascade from it. A separate `POST /revocations` endpoint is not
  required this generation.
- **R-11 (classifier contract).** The product ships its classifier as
  `kinbase classifier --json` (same binary): stdin is one JSON object
  `{"observations":[Observation...]}`; stdout is one JSON object
  `{"atoms":[{"text","atom_kind","scope","confidence","proposed_destinations":[...],
  "taint":[...],"provenance":{...},"unresolved_uncertainty"}], "classifier_version","provider"}`.
  Provider is selected by the user config `[classifier]` table: absent `model` key selects
  the deterministic rule/replay provider; `model = "ollama:<name>"` selects a live Ollama
  call at `http://127.0.0.1:11434` with a structured-JSON response contract. The
  instrument writes `[classifier] executable = <path of the product binary>`,
  `executable_sha256 = <its SHA-256>`, `args = ["classifier","--json"]`, and
  `timeout_seconds`. `doctor --json` reports `classifier.provider`,
  `classifier.executable_sha256`, and `classifier_pinned: true|false` (true iff the pinned
  digest re-verified at last spawn). The P-2 live-model thresholds are measured with the
  Ollama provider; the deterministic provider satisfies structural gates only.
- **R-12 (`hooks dispatch --json` framing).** Under `--json`, `hooks dispatch` writes
  exactly one JSON document to stdout: the host response object, whose `envelope` field is
  the base64 of the length-prefixed canonical tool-result envelope. The raw length-prefixed
  stream is emitted only without `--json`.
- **R-13 (`metrics.macro_f1`).** The product never computes macro-F1; it emits per-atom
  predictions with ids. Scoring is the instrument's.
- **R-14 (clock skew scope).** The five-minute `CLOCK_SKEW` quarantine (architecture §6)
  applies to receipt-time claims: `observed_at` on observations, request `expires_at`,
  approval-token issue/expiry, and manifest `observed_at`. It does not apply to
  `asserted_at`, `effective_from`, `effective_until`, `issued_at`, or `answered_at`, which
  are historical validity claims and may be arbitrarily far in the past. Every command
  and the service compare against the proof clock (`KINBASE_PROOF_CLOCK_OFFSET_SECONDS`
  applies to it).
- **R-15 (`--json` error stream).** Under `--json`, every typed error object is written to
  stdout as one line (stderr may repeat it). Empty stdout under `--json` is a defect
  regardless of exit code.
- **R-16 (classifier directory chain).** The classifier executable's containing-directory
  chain check refuses directories writable by group or other; owner-writable directories
  are permitted; the sticky world-writable `/tmp` roots are refused. The Validator pins the
  judge's classifier under a home-rooted 0755 directory.
- **R-17 (replaces R-4).** A bearer token authenticates any request whose domain-separated
  signature verifies under the presented client public key. The service records each
  `(token, client_key)` pair on first successful use for audit and applies read-volume
  ceilings per pair; several client keys may use one token in this generation (the judge
  and the product share the facts token with distinct keys). Failed signatures still count
  toward the auth-failure throttle. Residual: binding a token to one key at issuance is
  post-proof packaging.
- **R-18 (post-freeze; suite reopened and fully re-judged).** The repository maintainer's
  signing key reaches the product through the user config `[identity] maintainer_key_file`
  (absolute path, mode 0600, 32-byte seed or 64-hex). `repo publish-manifest` signs with it;
  absence is a typed `AUTHORITY_SCOPE_DENIED` naming the config key.
- **R-19 (ceiling refusal is intake's, not diagnosis's).** At or beyond the 10,000-event /
  128-MiB ceiling, `ingest`/admission refuses with `LIMIT_EXCEEDED` and omitted counts,
  computed by an early-exit walk so refusal costs less than acceptance. `fsck`, `status`
  and `explain` stay exit 0 and bounded, reporting `events_checked`, `events_deferred`,
  `omitted_count`, `over_intake_ceiling` and `intake_state`. Verification V-4: "Intake
  refuses new writes while bounded incremental fsck/diagnosis remains available."
- **R-20 (cascade above the ceiling).** The revocation cascade is a real job keyed by the
  newly observed revocation cursor. It is `REVOCATION_CASCADE_INCOMPLETE` while any
  locally addressable fact or trace is unchecked; `unchecked_facts_withheld` means the
  admitted set is drawn only from events the pass re-evaluated, never from the clock. At
  the ratified 10,000-event ceiling it completes within 120 seconds; above it (the judge
  builds 65,536 dense events) it records the remaining count, holds fail-closed state and
  returns the typed limit failure, per architecture §3.
