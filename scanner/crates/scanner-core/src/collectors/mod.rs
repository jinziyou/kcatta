//! Asset collectors.
//!
//! Each submodule gathers one slice of host state and returns contract
//! types ready to be packed into an `AssetReport`. v0 ships mock data
//! for everything except the host descriptor; real collectors will
//! replace these progressively without touching their callers.

pub mod host;
pub mod packages;
pub mod ports;
