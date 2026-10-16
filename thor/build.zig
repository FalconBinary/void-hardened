//! thor: команда thor на Zig (docs/18). Собирается из thor/build.sh после xbps:
//!   zig build -Dxbps-src=КАТАЛОГ_ИСХОДНИКОВ_XBPS --prefix DESTDIR/usr
//! Линкуется с libxbps из того же дерева (с политикой thor внутри).
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // по умолчанию ReleaseSafe (а не Debug): проверки границ и переполнений, оптимизация
    const optimize = b.option(std.builtin.Optimize, "optimize", "режим сборки (safe = ReleaseSafe)") orelse .safe;
    const xbps_src = b.option([]const u8, "xbps-src", "исходники xbps после configure и make") orelse
        @panic("нужен -Dxbps-src=КАТАЛОГ");

    const vh = b.createModule(.{ .root_source_file = b.path("../zig/lib/vh.zig"), .target = target, .optimize = optimize });
    const rules = b.createModule(.{ .root_source_file = b.path("policy/rules.zig"), .target = target, .optimize = optimize });

    const mod = b.createModule(.{
        .root_source_file = b.path("src/thor.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = true,
        .omit_frame_pointer = false,
        .strip = true, // без отладочной информации: 4 МБ → ~1 МБ; проверки ReleaseSafe остаются
    });
    // API libxbps: заголовок переводится в модуль Zig (в 0.17 вместо @cImport)
    const tc = b.addTranslateC(.{ .root_source_file = b.path("src/xbps_c.h"), .target = target, .optimize = optimize });
    tc.addIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{xbps_src}) });
    mod.addImport("c", tc.createModule());
    mod.addImport("vh", vh);
    mod.addImport("rules", rules);
    mod.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{xbps_src}) });
    mod.linkSystemLibrary("xbps", .{ .use_pkg_config = .no });
    // libxbps с политикой — из своего дерева (live-среда: DESTDIR/usr/lib; система: /usr/lib)
    mod.addRPath(.{ .cwd_relative = "$ORIGIN/../lib" });

    const exe = b.addExecutable(.{ .name = "thor", .root_module = mod });
    exe.pie = true;
    exe.link_z_relro = true;
    exe.link_z_lazy = false;
    b.installArtifact(exe);

    const t = b.addTest(.{ .root_module = mod });
    b.step("test", "юнит-тесты").dependOn(&b.addRunArtifact(t).step);
}
