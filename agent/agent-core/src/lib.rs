//! Shared core for pmacct-analyzer endpoint agents: the wire model, per-minute aggregation,
//! an on-disk spool for batches that could not be sent, the pinned-TLS HTTP client and the
//! configuration file. Platform shells (the desktop binary today, mobile apps later) only add
//! capture.
pub mod aggregator;
pub mod client;
pub mod config;
pub mod model;
pub mod pin;
pub mod spool;
pub mod version;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
