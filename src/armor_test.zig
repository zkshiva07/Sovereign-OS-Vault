const std = @import("std");
const linux = std.os.linux;
const armor = @import("armor.zig");

// Read /proc/self/status via raw syscalls and parse the VmLck field (kB).
fn readVmLck() !u64 {
    const fd_raw = linux.syscall3(.open, @intFromPtr("/proc/self/status"), 0, 0);
    if (@as(isize, @bitCast(fd_raw)) < 0) return error.OpenFailed;
    defer _ = linux.syscall1(.close, fd_raw);

    var buf: [8192]u8 = undefined;
    const n_raw = linux.syscall3(.read, fd_raw, @intFromPtr(&buf), buf.len);
    const n_signed = @as(isize, @bitCast(n_raw));
    if (n_signed < 0) return error.ReadFailed;

    const content = buf[0..@as(usize, @intCast(n_signed))];
    const marker = "VmLck:";
    const pos = std.mem.indexOf(u8, content, marker) orelse return error.MarkerNotFound;
    var i = pos + marker.len;
    while (i < content.len and (content[i] == ' ' or content[i] == '\t')) i += 1;
    const start = i;
    while (i < content.len and content[i] >= '0' and content[i] <= '9') i += 1;
    if (start == i) return error.NoDigits;
    return std.fmt.parseInt(u64, content[start..i], 10);
}

// -- disableCoreDumps ---------------------------------------------------------

test "disableCoreDumps: syscall succeeds" {
    try armor.disableCoreDumps();
}

test "disableCoreDumps: PR_GET_DUMPABLE returns 0" {
    try armor.disableCoreDumps();
    // PR_GET_DUMPABLE = 3; the return value IS the dumpable state, not an errno.
    const rc = linux.prctl(3, 0, 0, 0, 0);
    try std.testing.expect(@as(isize, @bitCast(rc)) >= 0); // no syscall error
    try std.testing.expectEqual(@as(usize, 0), rc);        // 0 = not dumpable
}

test "disableCoreDumps: idempotent — calling twice leaves dumpable = 0" {
    try armor.disableCoreDumps();
    try armor.disableCoreDumps();
    const rc = linux.prctl(3, 0, 0, 0, 0);
    try std.testing.expectEqual(@as(usize, 0), rc);
}

// Forks a child (same UID). Child tries to open /proc/<parent>/mem.
// After PR_SET_DUMPABLE=0, the kernel re-owns that entry as root:root, so
// a non-root same-UID child receives EACCES or EPERM.
test "disableCoreDumps: /proc/[pid]/mem inaccessible to same-UID child" {
    try armor.disableCoreDumps();
    const parent_pid = linux.getpid();

    // Format path before fork — child must not allocate from the heap.
    var path_buf: [64:0]u8 = std.mem.zeroes([64:0]u8);
    _ = try std.fmt.bufPrintZ(&path_buf, "/proc/{d}/mem", .{parent_pid});

    // Pipe: child sends 1 byte result to parent.
    var pipe_fds: [2]i32 = undefined;
    const pipe_rc = linux.syscall2(.pipe2, @intFromPtr(&pipe_fds), 0);
    try std.testing.expect(@as(isize, @bitCast(pipe_rc)) >= 0);

    const child_rc = linux.fork();
    const child_signed = @as(isize, @bitCast(child_rc));

    if (child_signed == 0) {
        // -- CHILD: raw syscalls only --
        _ = linux.syscall1(.close, @as(usize, @bitCast(@as(isize, pipe_fds[0]))));

        // openat(AT_FDCWD=-100, path, O_RDONLY=0, mode=0)
        const at_fdcwd = @as(usize, @bitCast(@as(isize, -100)));
        const fd = linux.syscall4(.openat, at_fdcwd, @intFromPtr(&path_buf), 0, 0);
        // 0 = open denied (expected), 1 = open succeeded (security failure)
        var result: u8 = if (@as(isize, @bitCast(fd)) < 0) 0 else 1;
        if (@as(isize, @bitCast(fd)) >= 0) _ = linux.syscall1(.close, fd);

        _ = linux.syscall3(.write,
            @as(usize, @bitCast(@as(isize, pipe_fds[1]))),
            @intFromPtr(&result), 1);
        _ = linux.syscall1(.close, @as(usize, @bitCast(@as(isize, pipe_fds[1]))));

        // Raw exit_group — bypass all Zig cleanup in child.
        _ = linux.syscall1(.exit_group, 0);
        unreachable;
    }

    // -- PARENT --
    try std.testing.expect(child_signed > 0);
    _ = linux.syscall1(.close, @as(usize, @bitCast(@as(isize, pipe_fds[1]))));

    var result: u8 = 2; // sentinel: no byte received
    _ = linux.syscall3(.read,
        @as(usize, @bitCast(@as(isize, pipe_fds[0]))),
        @intFromPtr(&result), 1);
    _ = linux.syscall1(.close, @as(usize, @bitCast(@as(isize, pipe_fds[0]))));

    var wstatus: u32 = 0;
    _ = linux.waitpid(@intCast(child_signed), &wstatus, 0);

    // result = 0 means the child was correctly denied access.
    try std.testing.expectEqual(@as(u8, 0), result);
}

// -- lockProcessMemory --------------------------------------------------------

test "lockProcessMemory: syscall succeeds" {
    try armor.lockProcessMemory();
}

test "lockProcessMemory: idempotent — calling twice does not error" {
    try armor.lockProcessMemory();
    try armor.lockProcessMemory();
}

// After mlockall(MCL_CURRENT|MCL_FUTURE), the kernel locks all resident pages.
// VmLck in /proc/self/status must be > 0 for any non-trivial process.
test "lockProcessMemory: VmLck is nonzero in /proc/self/status" {
    try armor.lockProcessMemory();
    const vmlck = try readVmLck();
    try std.testing.expect(vmlck > 0);
}

// MCL_FUTURE causes new mmap mappings to be locked automatically.
// Allocate 1 MB via page_allocator (each call is a fresh mmap, not a pool),
// touch every page to force faults, then verify VmLck grew by >= 512 kB.
test "lockProcessMemory: MCL_FUTURE auto-locks new mmap allocations" {
    try armor.lockProcessMemory();
    const before = try readVmLck();

    // page_allocator calls mmap directly — triggers MCL_FUTURE locking.
    const buf = try std.heap.page_allocator.alloc(u8, 1024 * 1024);
    defer std.heap.page_allocator.free(buf);
    @memset(buf, 0xAA); // fault every page in

    const after = try readVmLck();
    // Generous lower bound: expect at least 512 kB growth from a 1 MB alloc.
    try std.testing.expect(after >= before + 512);
}

// -- madviseNoCoredump --------------------------------------------------------

// madvise requires a page-aligned address; page_allocator guarantees this.
test "madviseNoCoredump: succeeds on page-aligned key buffer" {
    const buf = try std.heap.page_allocator.alloc(u8, 4096);
    defer std.heap.page_allocator.free(buf);
    try armor.madviseNoCoredump(buf);
}

test "madviseNoCoredump: pages survive subsequent read/write" {
    const buf = try std.heap.page_allocator.alloc(u8, 4096);
    defer std.heap.page_allocator.free(buf);
    try armor.madviseNoCoredump(buf);
    // The madvise hint must not affect normal access to the pages.
    @memset(buf, 0xAB);
    for (buf) |byte| try std.testing.expectEqual(@as(u8, 0xAB), byte);
}

// -- secureWipe ---------------------------------------------------------------

test "secureWipe: zeros every byte of a known-dirty buffer" {
    var buf = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01, 0x23 };
    armor.secureWipe(&buf);
    for (buf) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "secureWipe: handles a single-byte slice" {
    var one: [1]u8 = .{0xFF};
    armor.secureWipe(&one);
    try std.testing.expectEqual(@as(u8, 0), one[0]);
}

test "secureWipe: handles a zero-length slice without panic" {
    var empty: [0]u8 = .{};
    armor.secureWipe(&empty);
}

// -- hardenProcess ------------------------------------------------------------

test "hardenProcess: disables core dumps and locks memory in one call" {
    try armor.hardenProcess();
    // Verify disableCoreDumps effect: PR_GET_DUMPABLE = 3 must return 0.
    const rc = linux.prctl(3, 0, 0, 0, 0);
    try std.testing.expectEqual(@as(usize, 0), rc);
    // Verify lockProcessMemory effect: VmLck must be nonzero.
    const vmlck = try readVmLck();
    try std.testing.expect(vmlck > 0);
}
