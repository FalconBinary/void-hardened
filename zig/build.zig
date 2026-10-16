//! void-hardened: сборка инструментов на Zig (zig/README.md).
//!   zig build -Dtarget=x86_64-linux --prefix КАТАЛОГ   — все программы в КАТАЛОГ/bin
//!   zig build tests -Dtarget=… --prefix КАТАЛОГ         — юнит-тесты в КАТАЛОГ/test (без запуска)
//! Режим по умолчанию — ReleaseSafe: проверки границ, переполнений и null остаются в
//! программе. Программы без libc — статические PIE (им не нужна glibc системы).
const std = @import("std");

/// общие модули: имя → lib/ИМЯ.zig
const libs = [_][]const u8{ "vh", "hash", "seccomp" };

/// программы: tools/ИМЯ.zig; libc — нужна библиотека системы (OpenSSL, libxcrypt)
const Tool = struct { name: []const u8, libc: []const []const u8 = &.{} };
const tools = [_]Tool{
    .{ .name = "vh-seccomp" },
    .{ .name = "vh-pkg" },
    .{ .name = "vh-deep-clean" },
    .{ .name = "vh-usb-udev" },
    .{ .name = "vh-open" },
    .{ .name = "vh-limine-update" },
    .{ .name = "vh-uki-verify" },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = .x86_64, .os_tag = .linux } });
    // по умолчанию ReleaseSafe (а не Debug): проверки границ и переполнений, оптимизация
    const optimize = b.option(std.builtin.Optimize, "optimize", "режим сборки (safe = ReleaseSafe)") orelse .safe;

    var mods: [libs.len]*std.Build.Module = undefined;
    for (libs, 0..) |name, i|
        mods[i] = b.createModule(.{ .root_source_file = b.path(b.fmt("lib/{s}.zig", .{name})), .target = target, .optimize = optimize });
    for (mods, 0..) |m, j| for (libs, 0..) |name, i| if (i != j) m.addImport(name, mods[i]);

    const test_step = b.step("test", "юнит-тесты: собрать и запустить");
    const tests_step = b.step("tests", "юнит-тесты: только собрать (tests/zig/run.sh запускает их в контейнере)");

    for (tools) |t| {
        const mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("tools/{s}.zig", .{t.name})),
            .target = target,
            .optimize = optimize,
            .pic = true,
            .omit_frame_pointer = false,
            .strip = true,
            .link_libc = t.libc.len > 0,
        });
        for (libs, 0..) |name, i| mod.addImport(name, mods[i]);
        for (t.libc) |l| mod.linkSystemLibrary(l, .{ .use_pkg_config = .no });
        const exe = b.addExecutable(.{ .name = t.name, .root_module = mod });
        exe.pie = true;
        exe.link_z_relro = true; // полный RELRO: relro + now
        exe.link_z_lazy = false;
        b.installArtifact(exe);
        addTest(b, mod, t.name, test_step, tests_step);
    }
    for (libs, 0..) |name, i| addTest(b, mods[i], name, test_step, tests_step);
}

fn addTest(b: *std.Build, mod: *std.Build.Module, name: []const u8, run: *std.Build.Step, only: *std.Build.Step) void {
    const t = b.addTest(.{ .name = name, .root_module = mod });
    run.dependOn(&b.addRunArtifact(t).step);
    only.dependOn(&b.addInstallArtifact(t, .{ .dest_dir = .{ .override = .{ .custom = "test" } } }).step);
}
