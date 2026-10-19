//! DumpAnalyzer: the Analyzer role for DumpLedger (docs/analyzer-design.md).
//!
//! Discovers dumps through the DumpLedger catalog, analyzes them with the
//! internal agent (CDB toolchain via the tool runner), and writes verdicts
//! back as analysis reports. A local dashboard separates catalog browsing
//! from the active work queue.
#![forbid(unsafe_code)]

pub mod agent;
pub mod analyzer;
pub mod assessment;
pub mod claude_runner;
pub mod client;
pub mod config;
pub mod explorer;
pub mod http;
pub mod report;
pub mod runner;
pub mod scheduler;
pub mod state;
pub mod symbols;
pub mod sync;
pub mod types;
pub mod verdict;
pub mod wire;
