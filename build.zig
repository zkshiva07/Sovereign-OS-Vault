const std = @import("std");

pub fn build(b: *std.Build) void {
    const target   = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // vault-armor binary — the Zig hardening engine
    const exe = b.addExecutable(.{
        .name        = "vault-armor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target           = target,
            .optimize         = optimize,
        }),
    });
    b.installArtifact(exe);

    // zig build test — run armor unit tests
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/armor_test.zig"),
            .target           = target,
            .optimize         = optimize,
        }),
    });
    const test_step = b.step("test", "Run Armor unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
