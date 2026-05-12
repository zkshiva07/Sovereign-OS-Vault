//! Process hardening — Rust side. The Zig vault-armor binary handles its own
//! address space; this module hardens the Rust TUI process and exposes a bridge
//! to query the Zig binary.
//!
//! Order of operations is non-negotiable:
//!   1. Refuse to run as root (UID 0 ignores PR_SET_DUMPABLE — GDB still attaches).
//!   2. PR_SET_DUMPABLE=0 — blocks /proc/[pid]/mem and ptrace from same-UID.
//!   3. PR_SET_PTRACER=0 — Yama LSM ptracer lock (best-effort).
//!   4. mlockall(MCL_CURRENT|MCL_FUTURE) — pages never swap to disk.
//!
//! All checks are re-read from the kernel on every refresh — tampering drops
//! the score live.

use std::path::PathBuf;
use std::process::Command;

// Yama LSM prctl option — 0x59616d61 spells "Yama".
const PR_SET_PTRACER: libc::c_int = 0x59616d61;

#[derive(Clone, Copy)]
pub struct StartupHardening {
    pub uid:         libc::uid_t,
    pub yama_active: bool,
}

/// MUST be the very first call in main() — before terminal init, before any
/// allocation that could touch sensitive data.
///
/// Panics with SECURITY_INIT_FAILURE if any check fails. The TUI must never
/// run unarmed: a half-hardened signer is worse than no signer (false sense
/// of security).
pub fn harden_process() -> StartupHardening {
    unsafe {
        // ── Check 0: refuse root ────────────────────────────────────────────
        let uid = libc::getuid();
        if uid == 0 {
            panic!(
                "SECURITY_INIT_FAILURE: launched as root (UID=0). \
                 Root bypasses PR_SET_DUMPABLE — GDB will attach freely. \
                 Re-launch as a normal user."
            );
        }

        // ── Check 1: block /proc/[pid]/mem and ptrace ───────────────────────
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            panic!("SECURITY_INIT_FAILURE: PR_SET_DUMPABLE syscall rejected by kernel");
        }
        let is_dumpable = libc::prctl(libc::PR_GET_DUMPABLE);
        if is_dumpable != 0 {
            panic!(
                "SECURITY_INIT_FAILURE: kernel refused to harden process — \
                 PR_GET_DUMPABLE returned {} (expected 0). \
                 Likely a container/seccomp policy is blocking prctl.",
                is_dumpable
            );
        }

        // ── Check 2: Yama LSM ptracer lock (best-effort) ────────────────────
        // Returns 0 if Yama loaded and accepted the call; -1 (EINVAL) if Yama
        // is not loaded — which is acceptable; PR_SET_DUMPABLE=0 already blocks
        // ptrace from non-root.
        let ptracer_rc  = libc::prctl(PR_SET_PTRACER, 0usize, 0usize, 0usize, 0usize);
        let yama_active = ptracer_rc == 0;

        // ── Check 3: lock all pages in RAM ──────────────────────────────────
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            panic!(
                "SECURITY_INIT_FAILURE: mlockall failed — \
                 increase RLIMIT_MEMLOCK or run with the CAP_IPC_LOCK capability. \
                 (Quick fix: `sudo setcap cap_ipc_lock=ep ./sovereign-vault`)"
            );
        }

        StartupHardening { uid, yama_active }
    }
}

/// True if a debugger has attached since startup. Polled every event-loop tick.
pub fn debugger_attached() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("TracerPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<i64>().ok())
        })
        .map(|pid| pid != 0)
        .unwrap_or(false)
}

/// Re-read live kernel state. Returns (dumpable_cleared, vmlck_kb).
pub fn read_kernel_state() -> (bool, u64) {
    let dumpable_ok = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
    let vmlck       = read_vmlck();
    (dumpable_ok, vmlck)
}

fn read_vmlck() -> u64 {
    let Ok(content) = std::fs::read_to_string("/proc/self/status") else { return 0 };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmLck:") {
            return rest.split_whitespace().next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

/// Mark a buffer so the kernel skips it in any core dump (defense in depth).
/// Buffer must be page-aligned (use a Vec from a fresh allocation).
pub fn madv_no_coredump(buf: &mut [u8]) {
    const MADV_DONTDUMP: libc::c_int = 16;
    unsafe {
        libc::madvise(buf.as_mut_ptr() as *mut _, buf.len(), MADV_DONTDUMP);
    }
}

// ── Zig vault-armor bridge ───────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct ZigArmorReport {
    pub connected:    bool,
    pub binary_path:  String,
    pub memory_guard: bool,
    pub swap_guard:   bool,
    pub madv_guard:   bool,
}

pub fn query_zig_armor() -> ZigArmorReport {
    let Some(path) = find_vault_armor() else {
        return ZigArmorReport {
            binary_path: "not found (set VAULT_ARMOR_PATH or place vault-armor next to TUI binary)".into(),
            ..Default::default()
        };
    };
    let display = path.display().to_string();
    match Command::new(&path).output() {
        Ok(out) if out.status.success() => {
            let json = String::from_utf8_lossy(&out.stdout);
            ZigArmorReport {
                connected:    true,
                binary_path:  display,
                memory_guard: json.contains("\"memory_guard\":true"),
                swap_guard:   json.contains("\"swap_guard\":true"),
                madv_guard:   json.contains("\"madv_guard\":true"),
            }
        }
        Ok(out) => ZigArmorReport {
            binary_path: format!("{display} (exit {:?})", out.status.code()),
            ..Default::default()
        },
        Err(e) => ZigArmorReport {
            binary_path: format!("{display} ({e})"),
            ..Default::default()
        },
    }
}

fn find_vault_armor() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VAULT_ARMOR_PATH") {
        let path = PathBuf::from(p);
        if path.exists() { return Some(path); }
    }
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("vault-armor");
        if sibling.exists() { return Some(sibling); }
        // Fallback: walk up to find zig-out/bin/vault-armor
        let mut p = exe.clone();
        while p.pop() {
            let candidate = p.join("zig-out/bin/vault-armor");
            if candidate.exists() { return Some(candidate); }
        }
    }
    None
}
