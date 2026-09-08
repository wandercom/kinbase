//! Guildhall: the Company-memory member of the three-store Kindex system.
//!
//! Foundation rewrite (dispatch 009): the modules below implement the
//! ratified data model, canonicalization, signing, scanners, the private
//! store, the Codebase store, the reducer, the Company service/client/cache,
//! the launcher, and process containment. `repository.rs` (status/doctor/
//! fsck/repo commands) is present on disk but not yet compiled because it
//! depends on the not-yet-written `adapters` and `hooks` modules; the CLI
//! surface is not yet wired to this foundation (see the Coder report).
pub mod codebase;
pub mod company;
pub mod config;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod http;
pub mod json;
pub mod launcher;
pub mod model;
pub mod output;
pub mod paths;
pub mod private;
pub mod reducer;
pub mod sandbox;
pub mod scanner;
pub mod score;
pub mod time;
