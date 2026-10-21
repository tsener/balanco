//! Interfaces for trusted, statically linked workload-side HTTP plugins.
pub mod adapter;
pub mod http_plugin;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
