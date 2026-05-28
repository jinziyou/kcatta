//! scanner-ingest: push [`AssetReport`] JSON to form (`/ingest/asset-report`).
//!
//! v0 placeholder — wire `reqwest` here when the upload path is ready.

use scanner_contract::AssetReport;

/// Upload a report to form. Not implemented in v0.
pub fn upload_report(_report: &AssetReport, _form_base_url: &str) -> anyhow::Result<()> {
    anyhow::bail!("scanner-ingest: upload not implemented yet")
}
