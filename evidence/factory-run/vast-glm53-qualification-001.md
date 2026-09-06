# Vast GLM-5.3 pre-dispatch qualification receipt 001

Status: **infrastructure qualification only; not Product evidence and not Coder
admission**

Observed on 2026-09-05 CDT / 2026-09-06 UTC. The original manifest
`ac8a13d184397fef574e173b81466ff43e6b3f91f89804c7ee797cc404a622db`
remains the only ratified implementation authority. The Rust/Vast amendment bytes
qualified by this receipt have SHA-256
`9b2e1f85b0d84ae6c9ccc7aeb13f410654085a77aa748b975f72998391d71c49`
and remain an unratified candidate. No Coder dispatch occurred.

## Custody boundary exercised

Only generated synthetic prompt text and generic Codex harness metadata crossed
the SSH tunnel. No file content from the Guildhall repository or its specifications,
no Coder or Tester lane artifact, no Kindex graph, no credential, no Personal or
Company body, no customer data, and no test/oracle content was sent.

The Vast instance exposed only its mapped SSH port. The vLLM inference port remained
inside the container and was reached locally as `127.0.0.1:18000` through SSH. vLLM
ran with request logging and Uvicorn access logging disabled. At receipt time the
only non-model regular files below `/workspace` were the two vLLM process logs and
the current PID file; no prompt or response cache was present there.

## Instance and immutable inputs

- Vast account: `413964`
- instance: `50012413`
- machine / host: `54969` / `259870`
- host class: verified, static-IP, Italy
- accelerators: 8 x NVIDIA H200, 143,771 MiB reported per GPU
- driver / maximum supported CUDA: `590.48.01` / `13.1`
- container disk: 1,000 GB
- billed rate including storage: USD `34.00219298245615` per hour
- image tag: `vllm/vllm-openai:v0.28.0`
- image multi-architecture digest:
  `sha256:61fc8a896b0a4fbbbdc063bc4b0dbc25ce98e02b5050c24aeb7830ac02039b14`
- image amd64 digest:
  `sha256:2286e8533ca8b6bc777594bae30524f1426ba46ca21797524e06df6a94b06635`
- model: `zai-org/GLM-5.3`
- model Git revision: `aca966e4e02791568aa6a4ced368624b3d897f42`
- resolved model artifact manifest:
  `glm53-artifact-manifest-aca966e4.tsv`, 147 objects, 755,663,668,166 bytes,
  SHA-256 `4232b00338cfabddc71b593e319452ed56d4af3f5fe2441d023f2d305c1c5aab`

No instance API key or account credential is retained in this receipt.

## Qualified serving binding

The final server was launched as:

```text
vllm serve zai-org/GLM-5.3
  --revision aca966e4e02791568aa6a4ced368624b3d897f42
  --tokenizer-revision aca966e4e02791568aa6a4ced368624b3d897f42
  --download-dir /workspace/hf
  --kv-cache-dtype bfloat16
  --tensor-parallel-size 8
  --speculative-config.method mtp
  --speculative-config.num_speculative_tokens 5
  --tool-call-parser glm47
  --reasoning-parser glm45
  --enable-auto-tool-choice
  --served-model-name glm-5.3
  --max-model-len 262144
  --gpu-memory-utilization 0.90
  --max-num-seqs 4
  --enable-prefix-caching
  --prefix-caching-hash-algo sha256_cbor
  --no-enable-log-requests
  --disable-uvicorn-access-log
```

Observed vLLM facts:

- model load: 90.15 GiB per GPU;
- BF16 KV allocation: 30.74 GiB per GPU;
- cache capacity: 351,488 tokens;
- reported concurrency at a 262,144-token request: 1.34;
- `/health`: HTTP 200;
- `/v1/models`: `glm-5.3`, maximum model length 262,144.

An earlier synthetic-only FP8-KV preflight reported 504,384 cache tokens at 0.88
GPU utilization. It was terminated and is not the qualified Coder configuration.

## Synthetic probes

1. **Responses text.** A BF16 request with a sufficient output allowance completed
   and returned exactly `BF16_READY`.
2. **Tool selection.** A required function request emitted `multiply` with valid
   JSON arguments `{"a": 8, "b": 9}`.
3. **Stateless tool continuation.** vLLM does not retain a prior response by ID; a
   `previous_response_id` request returned 404. Full replay with a
   `function_call_output` completed correctly, and that is the protocol Codex used.
4. **Actual Codex harness.** Codex CLI 0.152.1 called the local shell tool in an
   empty temporary directory, consumed its output, and returned
   `SYNTHETIC_HARNESS_OK`. The turn used 8,491 input tokens, including 4,160 cached
   input tokens.
5. **Bound context.** A request containing 262,067 input tokens completed under
   BF16 KV. An exact repeat reported 261,952 cached input tokens and returned in
   four wall-clock seconds. This resolves capacity and long-prefix reuse for the
   selected 262K bound.
6. **Forced endpoint loss.** During Codex thread
   `01a07434-1c07-7d01-8662-6b7354ad8665`, the Validator removed the SSH tunnel
   while the model-directed local `uuidgen; sleep 30` tool was in flight. The tool
   completed locally; Codex recorded its exact function output in its native local
   session journal, waited for the endpoint, and completed the same thread and turn
   with UUID `346E3583-0907-468C-9E12-64B0F0111990` after reconnection.
7. **Explicit resume.** A separate `codex exec resume` of that same thread recovered
   the preceding UUID and returned exactly `346E3583`; the resumed turn reported
   10,176 cached input tokens.
8. **Durable local journal.** The local stream sink appends each operator-facing
   JSON event with mode 0600, calls `fsync`, then `fsync`s every JSONL file in the
   dedicated Codex session tree before forwarding the event. Its executable and
   shell launcher passed direct smoke, `bash -n`, and ShellCheck checks.

The 64-token text probe was once consumed entirely by model reasoning and correctly
returned `incomplete`; the same request completed with a 256-token allowance. The
actual Coder runner must not impose a tiny output cap. This is a harness bound, not
a model-correctness result.

The first recovery launcher attempt also correctly failed closed before inference:
`--ignore-user-config` discarded the custom provider profile and selected the
default OpenAI endpoint, which returned 401. It was stopped and replaced with a
dedicated run-only `CODEX_HOME` containing only the Vast provider binding. The
successful failure drill used that isolated home.

## Local recovery artifacts

- `durable-jsonl.py`:
  `fc92a544de93cf86999413423100fa2be5787f8f228f84d40bbe7af3ee371f3f`
- `launch-vast-recovery-probe.sh`:
  `212e3a56afd366ec23c07dc70ed04fe96b4f9b55476c062770ce8a2842a9fbb4`
- dedicated Codex `config.toml`:
  `675d0bddfa132f8fd0136b0597bd5a5a5c6fe17dc3f3064d5f95f5c0cc2a3b51`
- model catalog:
  `fd4f637bee656307b876493890bafa55c9684460fe8d5a757f8e1cc1a0922011`
- forced-loss operator journal:
  `edeb0da89dfafa8bd91024fe9bcea6e15971e422838ec09758bb1119921852e2`
- explicit-resume operator journal:
  `d76560eff2fafbe1f767c635a077d04e387bad1297a7f20cfeb9a6f60467df62`

These control files and Codex session data remain on the workstation, outside the
Coder repository and outside Vast.

## Budget observation

The account began this route with approximately USD 300.014 credit. At
approximately 2026-09-06 00:57 UTC it reported USD 263.841 remaining: about USD
36.173 consumed by image/model staging, transfer, runtime initialization, and all
synthetic probes. The USD 210-consumed warning and USD 285-consumed stop-new-turns
ceiling remain unchanged.

## What this proves and does not prove

This qualifies the pinned serving/harness configuration, BF16 capacity, long-prefix
reuse, local tool loop, and recovery from provider-path loss. It does **not** prove
the Guildhall Product, authorize repository transmission, admit a Coder artifact,
resolve the Tester rights grant, or satisfy any P-1 through P-10 or V-1 through V-10
Product gate.
