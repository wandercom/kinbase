pub mod classify;
pub mod error;
pub mod hash;
pub mod json;
pub mod model;
pub mod projector;
pub mod reducer;
pub mod scanner;
pub mod store;
pub mod time;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
