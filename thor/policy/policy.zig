//! thor: политика безопасности void-hardened внутри libxbps (docs/18).
//!
//! Собирается в объектный файл thor_policy.o и вшивается в libxbps (патч
//! patches/0001-thor-policy-hooks.patch), поэтому действует во всех программах xbps-*:
//! xbps-install, xbps-remove, xbps-reconfigure и в самом thor — обойти её прямым
//! вызовом xbps-install нельзя.
//!
//! Что делает:
//!  * SUID/SGID: снимается ещё до записи файла на диск. Разрешены только doas и
//!    unix_chkpwd (без него swaylock не проверит пароль) и пути из /etc/thor/keep.conf.
//!    То, что поставили скрипты INSTALL (chmod u+s, setcap), снимается после настройки.
//!  * хуки /etc/kernel.d (исполняются от root при каждой сборке UKI), модули dracut
//!    (попали бы в initramfs), скрипты /etc/profile.d и bashrc.d (в каждом шелле) —
//!    не распаковываются, если их нет в базовом списке /etc/thor/baseline;
//!  * sysctl.d пакетов — маскируются одноимённым файлом в /etc/sysctl.d (файл пакета
//!    99-* перекрыл бы 30-vh-hardening);
//!  * правила udev с MODE 0666/0777 (устройство для всех) — маскируются;
//!  * пакеты из чёрного списка (компиляторы, polkit, cups…) — транзакция отменяется,
//!    в том числе при обновлении; разрешение — /etc/thor/allow.conf (thor allow ИМЯ).
//!
//! Базовый список: при установке системы политика работает в режиме learn
//! (/etc/thor/policy.conf: mode=learn) — хуки, модули и правила пакетов базовой
//! системы не обезвреживаются, а записываются в baseline. Затем установщик ставит
//! mode=enforce. SUID/SGID, capabilities и чёрный список действуют в обоих режимах.
//!
//! Без libc: только системные вызовы Linux. Ошибки политики не роняют транзакцию —
//! о них пишется в stderr, а файл обезвреживается (отказ в сторону безопасности).
const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;

const THOR_EXTRACT: c_int = 0;
const THOR_SKIP: c_int = 1;

// ---------------------------------------------------------------- чёрный список

const Deny = struct { name: [:0]const u8, why: [:0]const u8 };

/// перенесён из vh-pkg (src/vh-pkg.c); причины — те же
const deny = [_]Deny{
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
const suid_allowed = [_][]const u8{ "/usr/bin/doas", "/usr/bin/unix_chkpwd" };

// ---------------------------------------------------------------- состояние

var cfg_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
var tmp_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);

const Config = struct {
    root: []const u8 = "",
    learn: bool = false,
    baseline: std.StringHashMapUnmanaged(void) = .empty,
    keep: std.StringHashMapUnmanaged(void) = .empty,
    allow: std.StringHashMapUnmanaged(void) = .empty,
};
var cfg: ?Config = null;

/// Конфиг политики для корня установки (загружается один раз на процесс).
fn config(rootdir: []const u8) *Config {
    if (cfg) |*c| if (mem.eql(u8, c.root, rootdir)) return c;
    _ = cfg_arena.reset(.free_all);
    const a = cfg_arena.allocator();
    var c: Config = .{ .root = a.dupe(u8, rootdir) catch oom() };
    if (readFile(a, join(a, rootdir, "/etc/thor/policy.conf"))) |text| {
        var it = mem.tokenizeScalar(u8, text, '\n');
        while (it.next()) |raw| {
            const line = mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const eq = mem.indexOfScalar(u8, line, '=') orelse continue;
            const k = mem.trim(u8, line[0..eq], " \t");
            const v = mem.trim(u8, line[eq + 1 ..], " \t\"");
            if (mem.eql(u8, k, "mode")) c.learn = mem.eql(u8, v, "learn");
        }
    }
    loadList(a, &c.baseline, join(a, rootdir, "/etc/thor/baseline"));
    loadList(a, &c.keep, join(a, rootdir, "/etc/thor/keep.conf"));
    loadList(a, &c.allow, join(a, rootdir, "/etc/thor/allow.conf"));
    cfg = c;
    return &cfg.?;
}

/// одна запись на строку; «#» — комментарий
fn loadList(a: mem.Allocator, set: *std.StringHashMapUnmanaged(void), path: [:0]const u8) void {
    const text = readFile(a, path) orelse return;
    var it = mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        set.put(a, line, {}) catch oom();
    }
}

fn oom() noreturn {
    @panic("thor policy: нет памяти");
}

// ---------------------------------------------------------------- системные вызовы

fn join(a: mem.Allocator, root: []const u8, path: []const u8) [:0]const u8 {
    const r = mem.trimEnd(u8, root, "/");
    return std.fmt.allocPrintSentinel(a, "{s}{s}", .{ r, path }, 0) catch oom();
}

fn ok(rc: usize) bool {
    return linux.errno(rc) == .SUCCESS;
}

fn openRetry(path: [:0]const u8, flags: linux.O, mode: linux.mode_t) ?linux.fd_t {
    var f = flags;
    f.CLOEXEC = true;
    while (true) {
        const rc = linux.open(path.ptr, f, mode);
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return null,
        }
    }
}

fn readFile(a: mem.Allocator, path: [:0]const u8) ?[]u8 {
    const fd = openRetry(path, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true }, 0) orelse return null;
    defer _ = linux.close(fd);
    var b: std.ArrayList(u8) = .empty;
    while (true) {
        b.ensureUnusedCapacity(a, 65536) catch oom();
        const rc = linux.read(fd, b.unusedCapacitySlice().ptr, 65536);
        switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) break else {
                b.items.len += rc;
            },
            .INTR => continue,
            else => return null,
        }
        if (b.items.len > 16 << 20) return null; // конфиг или правило udev больше 16 МБ — не наш случай
    }
    return b.items;
}

fn writeAll(fd: linux.fd_t, data: []const u8) bool {
    var p = data;
    while (p.len > 0) {
        const rc = linux.write(fd, p.ptr, p.len);
        switch (linux.errno(rc)) {
            .SUCCESS => p = p[rc..],
            .INTR => continue,
            else => return false,
        }
    }
    return true;
}

fn lstatMode(path: [:0]const u8) ?u32 {
    var st: linux.Statx = undefined;
    if (!ok(linux.statx(linux.AT.FDCWD, path.ptr, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true }, &st))) return null;
    return st.mode;
}

fn exists(path: [:0]const u8) bool {
    return lstatMode(path) != null;
}

/// каталоги на пути к файлу, как mkdir -p
fn mkdirs(a: mem.Allocator, dir: []const u8) void {
    var i: usize = 1;
    while (i <= dir.len) : (i += 1) {
        if (i < dir.len and dir[i] != '/') continue;
        const p = a.dupeSentinel(u8, dir[0..i], 0) catch oom();
        _ = linux.mkdir(p.ptr, 0o755);
    }
}

/// Строка в конец файла (создаётся с заголовком); O_NOFOLLOW — не по симлинку.
fn appendLine(a: mem.Allocator, path: [:0]const u8, header: []const u8, line: []const u8) void {
    mkdirs(a, std.fs.path.dirname(path) orelse "/");
    const fd = openRetry(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .NOFOLLOW = true }, 0o644) orelse {
        say("{s}: не удалось записать", .{path});
        return;
    };
    defer _ = linux.close(fd);
    var st: linux.Statx = undefined;
    if (ok(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &st)) and st.size == 0)
        _ = writeAll(fd, header);
    _ = writeAll(fd, std.fmt.allocPrint(a, "{s}\n", .{line}) catch oom());
}

/// Новый файл (не перезаписывает существующий): маска для udev/sysctl.
fn createFile(a: mem.Allocator, path: [:0]const u8, text: []const u8) bool {
    mkdirs(a, std.fs.path.dirname(path) orelse "/");
    const fd = openRetry(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true }, 0o644) orelse return false;
    defer _ = linux.close(fd);
    return writeAll(fd, text);
}

// ---------------------------------------------------------------- отчёт

/// сообщение в stderr: «thor: …»
fn say(comptime f: []const u8, args: anytype) void {
    var buf: [2048]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "thor: " ++ f ++ "\n", args) catch return;
    _ = writeAll(2, s);
}

/// действие политики: в stderr и в журнал /var/log/thor.log
fn act(c: *Config, pkgver: []const u8, comptime f: []const u8, args: anytype) void {
    const a = tmp_arena.allocator();
    const msg = std.fmt.allocPrint(a, f, args) catch oom();
    say("{s}: {s}", .{ pkgver, msg });
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(ts.sec, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    const line = std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {s}: {s}", .{
        day.year,                 md.month.numeric(),         md.day_index + 1,
        ds.getHoursIntoDay(),     ds.getMinutesIntoHour(),    ds.getSecondsIntoMinute(),
        pkgver,                   msg,
    }) catch oom();
    appendLine(a, join(a, c.root, "/var/log/thor.log"), "", line);
}

/// режим learn: путь — в базовый список
fn learn(c: *Config, path: []const u8) void {
    if (c.baseline.contains(path)) return;
    const a = cfg_arena.allocator();
    const p = a.dupe(u8, path) catch oom();
    c.baseline.put(a, p, {}) catch oom();
    appendLine(tmp_arena.allocator(), join(tmp_arena.allocator(), c.root, "/etc/thor/baseline"),
        "# thor: хуки, модули dracut, скрипты входа, sysctl.d и правила udev базовой системы —\n" ++
        "# политика их не трогает (docs/18). Записан при установке (mode=learn).\n", path);
}

// ---------------------------------------------------------------- категории путей

fn base(p: []const u8) []const u8 {
    return std.fs.path.basename(p);
}

fn isKernelHook(p: []const u8) bool {
    return mem.startsWith(u8, p, "/etc/kernel.d/");
}

/// каталог модуля dracut: /usr/lib/dracut/modules.d/90foo/
fn dracutModule(p: []const u8) ?[]const u8 {
    const pre = "/usr/lib/dracut/modules.d/";
    if (!mem.startsWith(u8, p, pre)) return null;
    const slash = mem.indexOfScalarPos(u8, p, pre.len, '/') orelse return null;
    return p[0 .. slash + 1];
}

fn isLoginScript(p: []const u8) bool {
    return (mem.startsWith(u8, p, "/etc/profile.d/") and mem.endsWith(u8, p, ".sh") and p.len > 18) or
        (mem.startsWith(u8, p, "/etc/bash/bashrc.d/") and p.len > 19);
}

fn isSysctl(p: []const u8) bool {
    return (mem.startsWith(u8, p, "/usr/lib/sysctl.d/") or mem.startsWith(u8, p, "/run/sysctl.d/")) and
        mem.endsWith(u8, p, ".conf") and base(p).len > 5;
}

fn isUdevRule(p: []const u8) bool {
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

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or ch == 0x0b or ch == 0x0c;
}

fn allowed(c: *Config, key: []const u8) bool {
    return c.baseline.contains(key) or c.keep.contains(key);
}

/// пустой одноимённый файл в /etc маскирует файл пакета (udev, sysctl)
fn mask(c: *Config, path: []const u8, dst_dir: []const u8, why: []const u8) []const u8 {
    const a = tmp_arena.allocator();
    const dst = std.fmt.allocPrint(a, "{s}/{s}", .{ dst_dir, base(path) }) catch oom();
    const text = std.fmt.allocPrint(a, "# void-hardened (thor): маскирует {s} — {s}\n", .{ path, why }) catch oom();
    const full = join(a, c.root, dst);
    if (exists(full)) return std.fmt.allocPrint(a, "уже есть {s}", .{dst}) catch oom();
    if (!createFile(a, full, text)) return std.fmt.allocPrint(a, "НЕ замаскирован: не удалось создать {s}", .{dst}) catch oom();
    return std.fmt.allocPrint(a, "замаскирован файлом {s}", .{dst}) catch oom();
}

// ---------------------------------------------------------------- точки входа (C)

fn span(p: [*:0]const u8) []const u8 {
    return mem.span(p);
}

export fn thor_unpack_entry(rootdir_c: [*:0]const u8, pkgver_c: [*:0]const u8, path_c: [*:0]const u8, mode: *c_uint) c_int {
    defer _ = tmp_arena.reset(.retain_capacity);
    const c = config(span(rootdir_c));
    const pkgver = span(pkgver_c);
    const path = span(path_c);

    // SUID/SGID — до записи на диск, в любом режиме
    const m: u32 = mode.*;
    if (m & 0o170000 == 0o100000 and m & 0o6000 != 0) {
        const keep = for (suid_allowed) |s| {
            if (mem.eql(u8, s, path)) break true;
        } else c.keep.contains(path);
        if (!keep) {
            mode.* = m & ~@as(c_uint, 0o6000);
            act(c, pkgver, "SUID/SGID снят: {s} (для root программа работает и так)", .{path});
        }
    }

    const key: ?[]const u8 = if (isKernelHook(path) or isLoginScript(path)) path else dracutModule(path);
    if (key) |k| {
        if (allowed(c, k)) return THOR_EXTRACT;
        if (c.learn) {
            learn(c, k);
            return THOR_EXTRACT;
        }
        const why = if (isKernelHook(path))
            "хук ядра: исполняется от root при каждой сборке UKI"
        else if (isLoginScript(path))
            "скрипт входа: исполнялся бы в каждом шелле, в том числе у админа"
        else
            "модуль dracut: попал бы в initramfs";
        act(c, pkgver, "{s} не распакован — {s} (разрешить: doas thor keep {s})", .{ path, why, k });
        return THOR_SKIP;
    }

    if (isSysctl(path) and !allowed(c, path)) {
        if (c.learn) {
            learn(c, path);
        } else {
            const r = mask(c, path, "/etc/sysctl.d", "перекрыл бы sysctl защиты");
            act(c, pkgver, "sysctl {s}: {s}", .{ path, r });
        }
    }
    return THOR_EXTRACT;
}

export fn thor_after_extract(rootdir_c: [*:0]const u8, pkgver_c: [*:0]const u8, path_c: [*:0]const u8) void {
    defer _ = tmp_arena.reset(.retain_capacity);
    const path = span(path_c);
    if (!isUdevRule(path)) return;
    const c = config(span(rootdir_c));
    if (allowed(c, path)) return;
    const a = tmp_arena.allocator();
    const full = join(a, c.root, path);
    const mode = lstatMode(full) orelse return;
    if (mode & 0o170000 != 0o100000) return;
    const text = readFile(a, full) orelse return;
    if (!udevWorldMode(text)) return;
    if (c.learn) {
        learn(c, path);
        return;
    }
    const pkgver = span(pkgver_c);
    if (mem.startsWith(u8, path, "/etc/")) {
        // файл в /etc нечем замаскировать — удаляется (обновление распакует его снова,
        // и политика удалит его снова)
        _ = linux.unlink(full.ptr);
        act(c, pkgver, "udev {s}: даёт устройство всем (MODE 0666) — удалён", .{path});
    } else {
        const r = mask(c, path, "/etc/udev/rules.d", "устройство для всех");
        act(c, pkgver, "udev {s}: даёт устройство всем (MODE 0666) — {s}", .{ path, r });
    }
}

export fn thor_transaction_pkg(rootdir_c: [*:0]const u8, pkgname_c: [*:0]const u8, reason: *?[*:0]const u8) c_int {
    const c = config(span(rootdir_c));
    const name = span(pkgname_c);
    const why = denyReason(name) orelse return 0;
    if (c.allow.contains(name)) return 0;
    reason.* = why.ptr;
    return 1;
}

export fn thor_post_file(rootdir_c: [*:0]const u8, pkgver_c: [*:0]const u8, path_c: [*:0]const u8, installed: c_int) void {
    defer _ = tmp_arena.reset(.retain_capacity);
    const c = config(span(rootdir_c));
    const pkgver = span(pkgver_c);
    const path = span(path_c);
    const a = tmp_arena.allocator();
    const full = join(a, c.root, path);
    const mode = lstatMode(full) orelse return;
    const reg = mode & 0o170000 == 0o100000;
    const keep = c.keep.contains(path) or for (suid_allowed) |s| {
        if (mem.eql(u8, s, path)) break true;
    } else false;

    if (reg and !keep) {
        // SUID/SGID, который поставил скрипт INSTALL
        if (mode & 0o6000 != 0) {
            if (ok(linux.fchmodat(linux.AT.FDCWD, full.ptr, mode & 0o7777 & ~@as(u32, 0o6000)))) {
                act(c, pkgver, "SUID/SGID снят: {s} (поставил скрипт пакета)", .{path});
            } else {
                act(c, pkgver, "SUID/SGID НЕ снят: {s} — снимите вручную", .{path});
            }
        }
        // file capabilities (setcap в скрипте INSTALL)
        var buf: [256]u8 = undefined;
        if (ok(linux.lgetxattr(full.ptr, "security.capability", &buf, buf.len))) {
            if (ok(linux.lremovexattr(full.ptr, "security.capability"))) {
                act(c, pkgver, "capabilities сняты: {s}", .{path});
            } else {
                act(c, pkgver, "capabilities НЕ сняты: {s} — setcap -r {s}", .{ path, path });
            }
        }
    }
    if (installed == 0 or c.learn) return;

    // только отчёт: в этой системе это не запускается само (как vh-pkg)
    if (mem.startsWith(u8, path, "/etc/sv/") and mem.endsWith(u8, path, "/run") and path.len > 12 and
        mem.indexOfScalarPos(u8, path, 8, '/') == path.len - 4)
    {
        const svc = path[8 .. path.len - 4];
        const link = join(a, c.root, std.fmt.allocPrint(a, "/var/service/{s}", .{svc}) catch oom());
        say("{s}: сервис runit {s}: {s}", .{ pkgver, svc, if (exists(link)) "ВКЛЮЧЁН — проверьте, нужен ли" else "установлен, но не включён (Void сам не включает)" });
    } else if (mem.startsWith(u8, path, "/usr/share/dbus-1/system-services/")) {
        say("{s}: D-Bus-сервис {s}: не запустится сам (активация выключена)", .{ pkgver, base(path) });
    } else if (mem.startsWith(u8, path, "/etc/xdg/autostart/") or mem.startsWith(u8, path, "/etc/cron")) {
        say("{s}: автозапуск {s}: mango и runit его не исполняют", .{ pkgver, path });
    } else if (mem.startsWith(u8, path, "/usr/lib/modprobe.d/") or mem.startsWith(u8, path, "/etc/modprobe.d/")) {
        say("{s}: modprobe.d {s}: проверьте (modules_disabled, module_blacklist)", .{ pkgver, path });
    } else if (reg and isUdevRule(path) and !allowed(c, path)) {
        const text = readFile(a, full) orelse return;
        if (mem.indexOf(u8, text, "RUN=") != null or mem.indexOf(u8, text, "RUN+=") != null or
            mem.indexOf(u8, text, "MODE") != null or mem.indexOf(u8, text, "GROUP") != null or
            mem.indexOf(u8, text, "OWNER") != null)
            say("{s}: udev {s}: правило прав/запуска — проверьте", .{ pkgver, path });
    }
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
