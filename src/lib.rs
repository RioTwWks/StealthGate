pub mod acceptor;
pub mod admin;
pub mod config;
pub mod detector;
pub mod error;
pub mod fallback;
pub mod fragmentation;
pub mod io_util;
pub mod proxy;
pub mod state;
pub mod tls;
pub mod tls_server;

pub use acceptor::run_acceptor;
pub use config::Config;
pub use detector::{DetectionResult, Detector, TrafficType};
pub use error::{Result, StealthGateError};
pub use state::{AppState, Stats, StatsSnapshot};
