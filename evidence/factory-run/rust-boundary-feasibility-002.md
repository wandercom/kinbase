# Rust boundary feasibility observation 002

Status: **Validator feasibility observation; not dependency admission, code, or Product evidence**

Observed locally on `2026-09-05` after `source ~/.profile`. No Vast inference or
Guildhall Coder lane was used.

The strict first-party `#![forbid(unsafe_code)]` constraint is feasible in principle
on the Linux proof path through public safe wrapper APIs whose dependencies contain
the platform `unsafe` internally:

| Surface | Observed crate/API | Source evidence |
|---|---|---|
| descriptor-backed execution | `nix 0.31.2` safe public `fexecve` and Linux/Android `execveat` | `src/unistd.rs` lines 1195 and 1222; source SHA-256 `7aefd24323fb242086214340a8fc86e9bad80238b451c9f0a6fb0c6a78e57212` |
| descriptor-relative open | `rustix 1.1.4` safe public `openat` | `src/fs/at.rs` line 78; source SHA-256 `2758c9b1146d29da0fc94601b2b22776ec30bd00363aefd13a123ec513999f3c` |
| beneath/no-symlink resolution | `rustix 1.1.4` safe public `openat2` with `ResolveFlags` | `src/fs/openat2.rs` line 14; source SHA-256 `8e2b73aa55bb5a6fa5c74fd022133ec5577a1db2dc3ab0f2b022b44cd08cbf4e` |
| Landlock | `landlock 0.4.7` safe abstraction and `HardRequirement` compatibility mode | `src/lib.rs` SHA-256 `1110e2fe43ca28a71d744d12e39657e538e4a56fdfcdab0ef8478079c87ab22d` |
| macOS Factory Coder sandbox | `/usr/bin/sandbox-exec` present on Darwin 25.6.0 arm64 and invocable through safe `std::process::Command` | local executable/help observation |

Downloaded crate archives were:

- `nix-0.31.2.crate`: SHA-256
  `5d6d0705320c1e6ba1d912b5e37cf18071b6c2e9b7fa8215a1e8a7651966f5d3`;
- `rustix-1.1.4.crate`: SHA-256
  `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190`;
- `landlock-0.4.7.crate`: SHA-256
  `4cca98e95f35b29d469dade6724c6f96cec9236640f745a0e99b0334ec320ab1`.

This observation does not admit those versions or substitute for a `Cargo.lock`,
license review, dependency audit, denial probes, or fully enforced Landlock result.
It resolves only the categorical concern that first-party safe Rust necessarily
makes the Linux boundary impossible.

Important platform limit: `nix 0.31.2` does not expose `fexecve` on macOS, matching
the base Architecture rule that a platform without verified descriptor-backed
execution disables the external-classifier path. Therefore the live external-
classifier proof must execute on a Linux acceptance host with Landlock in hard-
requirement mode; the macOS workstation may host the isolated Coder but cannot be
used to claim that Product boundary. A different dependency/path requires a fresh
audit rather than extrapolation from this observation.
