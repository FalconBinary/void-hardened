//! thor: правила политики — чёрный список пакетов и категории путей (docs/18).
//! Общие для политики в libxbps (policy.zig) и команды thor; без экспортируемых
//! символов, поэтому thor не перекрывает ими функции libxbps.
const std = @import("std");
const mem = std.mem;

// ---------------------------------------------------------------- чёрный список

pub const Deny = struct { name: [:0]const u8, why: [:0]const u8 };

/// перенесён из vh-pkg (src/vh-pkg.c); причины — те же
pub const deny = [_]Deny{
    // компиляторы: вредонос собрал бы инструмент на месте
    .{ .name = "gcc", .why = "компилятор C (часто тянет libgccjit — например, emacs-pgtk/gtk3)" },
    .{ .name = "clang", .why = "компилятор C" },
    .{ .name = "tcc", .why = "компилятор C" },
    .{ .name = "make", .why = "система сборки" },
    .{ .name = "rust", .why = "компилятор" },
    .{ .name = "go", .why = "компилятор" },
    .{ .name = "zig", .why = "компилятор (Zig для сборки живёт только в RAM live-среды)" },
    // интерпретаторы: обходят noexec (ctypes, FFI) — в системе их нет намеренно
    .{ .name = "python3", .why = "интерпретатор: исполняет код из файлов на noexec (docs/05)" },
    .{ .name = "perl", .why = "интерпретатор: исполняет код из файлов на noexec (docs/05)" },
    .{ .name = "ruby", .why = "интерпретатор" },
    .{ .name = "nodejs", .why = "интерпретатор" },
    // привилегированные демоны и помощники
    .{ .name = "polkit", .why = "SUID pkexec и демон прав — здесь его работу делает doas" },
    .{ .name = "elogind", .why = "менеджер сеансов — здесь seatd" },
    .{ .name = "udisks2", .why = "монтирование дисков без пароля через D-Bus" },
    .{ .name = "gvfs", .why = "демоны виртуальных ФС" },
    .{ .name = "avahi", .why = "mDNS: рассылает имя в сеть, слушает порт" },
    .{ .name = "cups", .why = "сервер печати, слушает порт" },
    .{ .name = "NetworkManager", .why = "второй менеджер сети рядом с iwd" },
    .{ .name = "ModemManager", .why = "демон модемов" },
    .{ .name = "connman", .why = "второй менеджер сети" },
    .{ .name = "wpa_supplicant", .why = "второй Wi-Fi-демон рядом с iwd" },
    .{ .name = "openssh", .why = "содержит сервер sshd (сервис не включайте)" },
    .{ .name = "sudo", .why = "второй SUID-инструмент повышения прав" },
    .{ .name = "usbguard", .why = "тянет polkit" },
    .{ .name = "cronie", .why = "планировщик — точка закрепления" },
    .{ .name = "dcron", .why = "планировщик" },
    .{ .name = "fcron", .why = "планировщик" },
    .{ .name = "snooze", .why = "планировщик" },
    .{ .name = "at", .why = "планировщик" },
    .{ .name = "xorg-server", .why = "X11: нет изоляции окон" },
    .{ .name = "xorg-server-xwayland", .why = "Xwayland: нет изоляции окон" },
    .{ .name = "xdg-desktop-portal", .why = "D-Bus-порталы" },
    .{ .name = "gnome-keyring", .why = "демон ключей с D-Bus" },
    .{ .name = "pulseaudio", .why = "конфликтует с PipeWire" },
    .{ .name = "fuse", .why = "SUID fusermount; модуль fuse запрещён" },
    .{ .name = "fuse3", .why = "SUID fusermount3; модуль fuse запрещён" },
    .{ .name = "flatpak", .why = "нужны userns и fuse" },
    .{ .name = "podman", .why = "нужны userns и overlay" },
    .{ .name = "docker", .why = "root-демон, нужны overlay и iptables" },
    .{ .name = "tlp", .why = "демон питания — работу делает vh-power" },
    .{ .name = "thermald", .why = "демон питания" },
    .{ .name = "power-profiles-daemon", .why = "демон питания" },
    .{ .name = "auto-cpufreq", .why = "демон питания" },
    .{ .name = "acpid", .why = "усыпляет по крышке — здесь vh-acpid" },
    // сам xbps: его заменяет thor, обычный пакет откатил бы политику
    .{ .name = "xbps", .why = "заменён пакетом thor (обновление thor — install/build-thor.sh, docs/18)" },
};

const deny_prefix = [_]Deny{
    .{ .name = "xdg-desktop-portal-", .why = "D-Bus-порталы" },
    .{ .name = "llvm", .why = "компилятор (LLVM)" },
};

pub fn denyReason(name: []const u8) ?[:0]const u8 {
    for (deny) |d| if (mem.eql(u8, name, d.name)) return d.why;
    for (deny_prefix) |d| if (mem.startsWith(u8, name, d.name)) return d.why;
    return null;
}

/// SUID/SGID, без которых система не работает (их же ждёт vh-audit)
pub const suid_allowed = [_][]const u8{ "/usr/bin/doas", "/usr/bin/unix_chkpwd" };

// ---------------------------------------------------------------- категории путей

pub fn base(p: []const u8) []const u8 {
    return std.fs.path.basename(p);
}

pub fn isKernelHook(p: []const u8) bool {
    return mem.startsWith(u8, p, "/etc/kernel.d/");
}

/// каталог модуля dracut: /usr/lib/dracut/modules.d/90foo/
pub fn dracutModule(p: []const u8) ?[]const u8 {
    const pre = "/usr/lib/dracut/modules.d/";
    if (!mem.startsWith(u8, p, pre)) return null;
    const slash = mem.indexOfScalarPos(u8, p, pre.len, '/') orelse return null;
    return p[0 .. slash + 1];
}

pub fn isLoginScript(p: []const u8) bool {
    return (mem.startsWith(u8, p, "/etc/profile.d/") and mem.endsWith(u8, p, ".sh") and p.len > 18) or
        (mem.startsWith(u8, p, "/etc/bash/bashrc.d/") and p.len > 19);
}

pub fn isSysctl(p: []const u8) bool {
    return (mem.startsWith(u8, p, "/usr/lib/sysctl.d/") or mem.startsWith(u8, p, "/run/sysctl.d/")) and
        mem.endsWith(u8, p, ".conf") and base(p).len > 5;
}

pub fn isUdevRule(p: []const u8) bool {
    return (mem.startsWith(u8, p, "/usr/lib/udev/rules.d/") or mem.startsWith(u8, p, "/etc/udev/rules.d/")) and
        mem.endsWith(u8, p, ".rules") and base(p).len > 6;
}

/// MODE="0666" и подобное: устройство для всех (как udev_world_mode в vh-pkg)
pub fn udevWorldMode(t: []const u8) bool {
    const modes = [_][]const u8{ "666", "777", "766", "776", "677" };
    var from: usize = 0;
    while (mem.indexOfPos(u8, t, from, "MODE")) |p| {
        from = p + 4;
        var q = p + 4;
        while (q < t.len and isSpace(t[q])) q += 1;
        if (q < t.len and t[q] == ':') q += 1;
        if (q >= t.len or t[q] != '=') continue;
        q += 1;
        while (q < t.len and isSpace(t[q])) q += 1;
        if (q >= t.len or t[q] != '"') continue;
        q += 1;
        if (q < t.len and t[q] == '0') q += 1;
        for (modes) |m| if (t.len - q >= 4 and mem.eql(u8, t[q .. q + 3], m) and t[q + 3] == '"') return true;
    }
    return false;
}

pub fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or ch == 0x0b or ch == 0x0c;
}

test "чёрный список" {
    try std.testing.expect(denyReason("polkit") != null);
    try std.testing.expect(denyReason("xdg-desktop-portal-wlr") != null);
    try std.testing.expect(denyReason("llvm19") != null);
    try std.testing.expect(denyReason("firefox") == null);
    try std.testing.expect(denyReason("thor") == null);
}

test "категории путей" {
    try std.testing.expect(isKernelHook("/etc/kernel.d/post-install/20-dracut"));
    try std.testing.expectEqualStrings("/usr/lib/dracut/modules.d/90crypt/", dracutModule("/usr/lib/dracut/modules.d/90crypt/module-setup.sh").?);
    try std.testing.expect(dracutModule("/usr/lib/dracut/modules.d/README") == null);
    try std.testing.expect(isLoginScript("/etc/profile.d/x.sh"));
    try std.testing.expect(!isLoginScript("/etc/profile.d/.sh"));
    try std.testing.expect(isSysctl("/usr/lib/sysctl.d/99-x.conf"));
    try std.testing.expect(!isSysctl("/usr/lib/sysctl.d/.conf"));
    try std.testing.expect(isUdevRule("/usr/lib/udev/rules.d/60-x.rules"));
}

test "udev MODE 0666" {
    try std.testing.expect(udevWorldMode("KERNEL==\"fuse\", MODE=\"0666\""));
    try std.testing.expect(udevWorldMode("MODE:=\"666\""));
    try std.testing.expect(udevWorldMode("MODE = \"0777\""));
    try std.testing.expect(!udevWorldMode("MODE=\"0660\""));
    try std.testing.expect(!udevWorldMode("MODE=\"0666"));
    try std.testing.expect(!udevWorldMode("MODE"));
}
