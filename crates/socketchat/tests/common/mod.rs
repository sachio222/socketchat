//! What the tests that run the program share.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::process::Command;

/// The main-thread stack Windows gives a program, in KiB. macOS and Linux
/// give 8 MiB, so a command that needs more than this would pass there and
/// crash on Windows.
pub const WINDOWS_MAIN_STACK_KIB: u32 = 1024;

/// Runs `program` with the main-thread stack Windows gives it, on every
/// system. On Windows that is already the case.
pub fn windows_stack(program: impl AsRef<OsStr>) -> Command {
    #[cfg(unix)]
    {
        let mut c = Command::new("sh");
        c.arg("-c")
            .arg(format!(
                "ulimit -s {WINDOWS_MAIN_STACK_KIB} && exec \"$0\" \"$@\""
            ))
            .arg(program);
        c
    }
    #[cfg(not(unix))]
    Command::new(program)
}
