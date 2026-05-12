const std   = @import("std");
const linux = std.os.linux;
const armor = @import("armor.zig");

fn die(msg: []const u8) noreturn {
    _ = linux.syscall3(.write, 2, @intFromPtr(msg.ptr), msg.len);
    _ = linux.syscall1(.exit_group, 1);
    unreachable;
}

pub fn main() void {
    // Harden this process FIRST — before any key material is touched.
    // If hardening fails, abort immediately; do not run unarmed.
    armor.disableCoreDumps()    catch die("FATAL: disableCoreDumps failed — vault must not run unarmed\n");
    armor.lockProcessMemory()   catch die("FATAL: lockProcessMemory failed — vault must not run unarmed\n");

    // Allocate a 4 KiB page-aligned buffer and exercise MADV_DONTDUMP. This is
    // the same syscall the Rust side will use for key buffers — proving here
    // that the kernel accepts it gives the TUI confidence to enable madv_guard.
    const page = std.heap.page_allocator.alloc(u8, 4096) catch
        die("FATAL: page_allocator failed\n");
    defer std.heap.page_allocator.free(page);
    armor.madviseNoCoredump(page) catch die("FATAL: madviseNoCoredump failed — vault must not run unarmed\n");

    // All guards confirmed. Write one JSON line to stdout for the TUI to parse.
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "{{\"memory_guard\":true,\"swap_guard\":true,\"madv_guard\":true}}\n",
        .{},
    ) catch die("FATAL: bufPrint failed\n");
    _ = linux.syscall3(.write, 1, @intFromPtr(line.ptr), line.len);
}
