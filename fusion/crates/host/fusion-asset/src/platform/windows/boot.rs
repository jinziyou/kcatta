//! Boot time estimation for live Windows scans.

use chrono::{DateTime, Utc};
use fusion_runtime::ScanContext;

/// Best-effort boot timestamp (live Windows host only).
pub fn boot_time(ctx: &ScanContext) -> Option<DateTime<Utc>> {
    #[cfg(windows)]
    {
        use crate::platform;
        if platform::use_live_registry(&ctx.scan_root) {
            return live_boot_time();
        }
    }
    let _ = ctx;
    None
}

#[cfg(windows)]
fn live_boot_time() -> Option<DateTime<Utc>> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;

    let uptime_ms = unsafe { GetTickCount64() };
    Utc::now().checked_sub_signed(chrono::Duration::milliseconds(uptime_ms as i64))
}
