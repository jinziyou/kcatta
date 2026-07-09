//! Boot time estimation for live Windows scans.

use crate::ScanContext;
use chrono::{DateTime, Utc};

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
// Unavoidable Win32 FFI (host already links windows-sys); scoped allow so the
// workspace `unsafe_code = "deny"` lint stays in force everywhere else.
#[allow(unsafe_code)]
fn live_boot_time() -> Option<DateTime<Utc>> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;

    // SAFETY: GetTickCount64 takes no arguments and returns the system uptime in
    // milliseconds; it is always safe to call.
    let uptime_ms = unsafe { GetTickCount64() };
    Utc::now().checked_sub_signed(chrono::Duration::milliseconds(uptime_ms as i64))
}
