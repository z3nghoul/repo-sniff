//! Scanning engine of repo-sniff.
//!
//! This crate knows nothing about how results are shown: it never prints
//! and has no terminal or UI dependencies. The CLI, the TUI and the GitHub
//! Action all build on top of it.
