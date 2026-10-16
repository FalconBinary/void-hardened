//! void-hardened: сборка инструментов на Zig (zig/README.md).
//!   zig build -Dtarget=x86_64-linux --prefix КАТАЛОГ   — все программы в КАТАЛОГ/bin
//!   zig build test                                     — юнит-тесты
//! Режим по умолчанию — ReleaseSafe: проверки границ, переполнений и null остаются в
//! программе. Программы без libc — статические PIE (им не нужна glibc системы).
const std = @import("std");

/// программы: имя → файл в tools/
const tools = [_][]const u8{};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = .x86_64, .os_tag = .linux } });
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const vh = b.createModule(.{ .root_source_file = b.path("lib/vh.zig"), .target = target, .optimize = optimize });
    const hash = b.createModule(.{ .root_source_file = b.path("lib/hash.zig"), .target = target, .optimize = optimize });
    hash.addImport("vh", vh);

    inline for (tools) |name| {
        const mod = b.createModule(.{
            .root_source_file = b.path("tools/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
            .pic = true,
            .omit_frame_pointer = false,
        });
        mod.addImport("vh", vh);
        mod.addImport("hash", hash);
        const exe = b.addExecutable(.{ .name = name, .root_module = mod });
        exe.pie = true;
        exe.link_z_relro = true; // полный RELRO: relro + now
        exe.link_z_lazy = false;
        b.installArtifact(exe);
    }

    // test — собрать и запустить (на Linux); tests — только собрать в ПРЕФИКС/test
    // (tests/zig/run.sh запускает их в контейнере Void)
    const test_step = b.step("test", "юнит-тесты: собрать и запустить");
    const tests_step = b.step("tests", "юнит-тесты: только собрать");
    const roots = [_][]const u8{ "lib/vh.zig", "lib/hash.zig" } ++ tool_paths;
    inline for (roots) |src| {
        const mod = b.createModule(.{ .root_source_file = b.path(src), .target = target, .optimize = optimize });
        mod.addImport("vh", vh);
        mod.addImport("hash", hash);
        const t = b.addTest(.{ .name = std.fs.path.stem(src), .root_module = mod });
        test_step.dependOn(&b.addRunArtifact(t).step);
        tests_step.dependOn(&b.addInstallArtifact(t, .{ .dest_dir = .{ .override = .{ .custom = "test" } } }).step);
    }
}

const tool_paths = blk: {
    var p: [tools.len][]const u8 = undefined;
    for (tools, 0..) |t, i| p[i] = "tools/" ++ t ++ ".zig";
    break :blk p;
};
