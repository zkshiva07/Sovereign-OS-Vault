const std = @import("std");
const linux = std.os.linux;

// 1. Block /proc/[pid]/mem and process_vm_readv() from same-UID processes.
//    Must be called BEFORE loading any key material.
pub fn disableCoreDumps() !void {
    // PR_SET_DUMPABLE = 4, value 0 = not dumpable
    const set_rc = linux.prctl(4, 0, 0, 0, 0);
    if (@as(isize, @bitCast(set_rc)) < 0) return error.PrctlFailed;

    // PR_GET_DUMPABLE = 3 — verify the kernel actually honored the call.
    // Do not proceed if the bit was not cleared: running with dumpable=1 means
    // any same-UID process can read our address space via /proc/[pid]/mem.
    const get_rc = linux.prctl(3, 0, 0, 0, 0);
    if (get_rc != 0) return error.DumpableNotCleared;
}

// 2. Lock all current and future memory pages in RAM — never swapped to disk.
//    MCL_CURRENT = 1: lock pages already mapped.
//    MCL_FUTURE  = 2: auto-lock every new mmap going forward (covers key allocs).
pub fn lockProcessMemory() !void {
    const rc = linux.syscall1(.mlockall, 1 | 2);
    const signed = @as(isize, @bitCast(rc));
    if (signed < 0) {
        const e: linux.E = @enumFromInt(-signed);
        if (e == .PERM) return error.InsufficientPrivileges;
        return error.MlockallFailed;
    }
}

// 3. Mark a specific memory region so the kernel skips it in any core dump.
//    Defense-in-depth: even if dumpability is somehow re-enabled, key pages
//    are individually excluded. Buf must be page-aligned (use page_allocator).
pub fn madviseNoCoredump(buf: []u8) !void {
    const MADV_DONTDUMP: usize = 16;
    const rc = linux.syscall3(.madvise, @intFromPtr(buf.ptr), buf.len, MADV_DONTDUMP);
    if (@as(isize, @bitCast(rc)) < 0) return error.MadviseFailed;
}

// 4. Zero a buffer using volatile writes so the compiler cannot optimize
//    away the wipe (a "dead store" the optimizer would normally delete).
//    Call this immediately after using key material — no GC delay.
pub fn secureWipe(buf: []u8) void {
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        const vp: *volatile u8 = @ptrCast(&buf[i]);
        vp.* = 0;
    }
}

// Convenience: apply both process-level hardening steps in the correct order.
pub fn hardenProcess() !void {
    try disableCoreDumps();
    try lockProcessMemory();
}
