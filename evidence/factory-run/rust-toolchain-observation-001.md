# Rust 1.98.1 channel observation 001

Status: **external-artifact observation only; not a Product, build, or G-4 pass**

At `2026-09-06T02:33:05Z`, the Validator fetched
`https://static.rust-lang.org/dist/channel-rust-1.98.1.toml` over HTTPS. The response
was HTTP 200 and reported:

- manifest date: `2026-09-03`;
- response `Last-Modified`: `Thu, 03 Sep 2026 13:11:24 GMT`;
- S3 version ID: `uPft7joMwIOkubSn2SJLrPEX.4T7p04i`;
- ETag: `863170c89f1ffef819ed2ab00caa6078`;
- byte count: `898637`;
- locally computed SHA-256:
  `a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e`.

The manifest identifies Rust `1.98.1` component archives and their per-target hashes;
for example, the `aarch64-apple-darwin` Cargo XZ archive hash is
`de51d4fade4f31ad8ec405261cc96bedc000d905f98980027610d6e288dbe21b`
as recorded in the fetched manifest.

The local Homebrew toolchain is only `rustc 1.98.0
(88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)` on
`aarch64-apple-darwin`; this receipt does not claim 1.98.1 is installed. G-4 must
bootstrap the pinned 1.98.1 target components, verify their manifest hashes, record
`rustc -Vv`/Cargo/target receipts, and then prove subsequent builds run offline and
locked.

No downloaded executable was run while producing this observation.
