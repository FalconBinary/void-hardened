//! vh-deep-clean — полная очистка системы: удаляется только ненужное (docs/12, раздел «Очистка»).
//!
//!   doas vh-deep-clean                    план: что удалится и сколько места освободится;
//!                                         ничего не меняет
//!   doas vh-deep-clean --apply [-y]       выполнить; каждая группа — с вопросом [y/N]
//!                  [--user]               плюс мусор пользователей (~/.cache, кэш Firefox, корзина)
//!                  [--only ГРУППА,…]      только эти группы
//!   doas vh-deep-clean restore            вернуть файлы из последнего резерва
//!
//! Группы:
//!   orphans   зависимости, которые больше никому не нужны (xbps-remove -o). Пакеты из
//!             /etc/vh/deep-clean.keep и ядро системы сначала помечаются ручными и остаются.
//!   conf      конфиги без владельца из двух точных источников: *.new-ВЕРСИЯ, которые xbps
//!             оставляет рядом с изменённым конфигом при обновлении, и изменённые конфиги
//!             удалённых пакетов (их conf_files: журнал vh-pkg rm и сироты этого запуска).
//!             Правила «ничей файл в /etc — мусор» нет: там ключи, fstab, файлы самой системы.
//!   services  битые ссылки в /etc/runit/runsvdir/УРОВЕНЬ (пакет сервиса удалён).
//!   kernels   старые ядра — vkpurge (он не трогает работающее ядро и ядра установленных
//!             пакетов; хуки ядра убирают UKI и запись Limine) и каталоги модулей без ядра.
//!   cache     скачанные пакеты в /var/cache/xbps (xbps скачает их снова при надобности).
//!   user      (--user) ~/.cache людей и root, кэш Firefox пользователя браузера (не профиль),
//!             корзина. Удаляется от имени владельца; занятое программами остаётся.
//!
//! Конфиги и ссылки сервисов не удаляются, а переносятся в /var/lib/vh/deep-clean/last
//! (0700); restore возвращает их, следующий --apply удаляет прошлый резерв. Пакеты, ядра и
//! кэши — без резерва: они ставятся или создаются заново. До и после --apply запускается
//! vh-audit: новые [FAIL] печатаются, код выхода 1. Журналы, /etc/vh, ключи, профили и
//! настройки пользователей не трогаются никогда.
const std = @import("std");
const vh = @import("vh");
const linux = std.os.linux;
const mem = std.mem;

const BK_DIR = "/var/lib/vh/deep-clean";
const BK_LAST = BK_DIR ++ "/last";
const CONF_LEDGER = "/var/lib/vh/removed-conf.list";
const KEEP_FILE = "/etc/vh/deep-clean.keep";
const AUDIT = "/usr/local/sbin/vh-audit";
const CACHE_DIR = "/var/cache/xbps";

const Group = enum { orphans, conf, services, kernels, cache, user };

var apply = false;
var yes = false;
var keep_pkgs: vh.Strv = .{};
var keep_paths: vh.Strv = .{};
var env: vh.Kv = .{};
var boot: vh.Kv = .{};
/// conf_files сирот, удалённых в этом запуске
var orphan_conf: vh.Strv = .{};
/// освобождено (или будет освобождено) байт
var total: u64 = 0;
var bk_ready = false;

// ---------- мелочи

fn hsize(n: u64) []const u8 {
    const u = [_][]const u8{ "Б", "КБ", "МБ", "ГБ", "ТБ" };
    var v: f64 = @floatFromInt(n);
    var k: usize = 0;
    while (v >= 1024 and k < 4) : (k += 1) v /= 1024;
    return if (k > 0) vh.fmt("{d:.1} {s}", .{ v, u[k] }) else vh.fmt("{d:.0} {s}", .{ v, u[k] });
}

fn pkgname(pkgver: []const u8) []const u8 {
    const d = mem.lastIndexOfScalar(u8, pkgver, '-') orelse return pkgver;
    return pkgver[0..d];
}

fn section(title: []const u8) void {
    vh.out("\n── {s}\n", .{title});
}

/// непустые строки без пробелов по краям
fn lines(text: []const u8) []const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const l = vh.strip(raw);
        if (l.len > 0) out.append(vh.gpa, l) catch vh.oom();
    }
    return out.items;
}

fn blocks(st: vh.Stat) u64 {
    return st.blocks * 512;
}

fn dev(st: vh.Stat) u64 {
    return (@as(u64, st.dev_major) << 32) | st.dev_minor;
}

// ---------- обход каталогов без перехода по симлинкам

const dir_flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true };

/// Содержимое каталога dfd: размер на диске, при del — удалить. По симлинкам не идёт,
/// в другие ФС (точки монтирования) не заходит.
fn tree(dfd: vh.fd_t, del: bool, depth: u32) u64 {
    const dst = vh.fstat(dfd) catch return 0;
    const names = vh.listDirFd(dfd) catch return 0;
    var sum: u64 = 0;
    for (names) |name| {
        const st = vh.statAt(dfd, name, false) catch continue;
        if (vh.S.isDir(st.mode)) {
            if (dev(st) != dev(dst) or depth > 64) continue;
            const sub = vh.openAt(dfd, name, dir_flags) catch continue;
            sum += tree(sub, del, depth + 1);
            vh.close(sub);
            sum += blocks(st);
            if (del) vh.unlinkAt(dfd, name, true) catch {};
        } else {
            sum += blocks(st);
            if (del) vh.unlinkAt(dfd, name, false) catch if (vh.errno != .NOENT) vh.warn("{s}: {s}", .{ name, vh.serr() });
        }
    }
    return sum;
}

/// один объект name в каталоге dfd: размер; при del — удалить целиком
fn entry(dfd: vh.fd_t, name: []const u8, del: bool) u64 {
    const st = vh.statAt(dfd, name, false) catch return 0;
    var sum = blocks(st);
    if (vh.S.isDir(st.mode)) {
        if (vh.openAt(dfd, name, dir_flags)) |sub| {
            sum += tree(sub, del, 0);
            vh.close(sub);
        } else |_| {}
        if (del) vh.unlinkAt(dfd, name, true) catch if (vh.errno != .NOENT) vh.warn("{s}: {s}", .{ name, vh.serr() });
    } else if (del) {
        vh.unlinkAt(dfd, name, false) catch if (vh.errno != .NOENT) vh.warn("{s}: {s}", .{ name, vh.serr() });
    }
    return sum;
}

/// путь целиком (файл или каталог): размер; при del — удалить
fn pathEntry(path: []const u8, del: bool) u64 {
    const slash = mem.lastIndexOfScalar(u8, path, '/') orelse return 0;
    if (slash + 1 == path.len) return 0;
    const dir = if (slash == 0) "/" else path[0..slash];
    const dfd = vh.openFd(dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch return 0;
    defer vh.close(dfd);
    return entry(dfd, path[slash + 1 ..], del);
}

/// каталог rel внутри base, ни один компонент — не симлинк; null, если нет
fn openUnder(base: []const u8, rel: []const u8) ?vh.fd_t {
    var fd = vh.openFd(base, dir_flags, 0) catch return null;
    var it = mem.tokenizeScalar(u8, rel, '/');
    while (it.next()) |c| {
        const n = vh.openAt(fd, c, dir_flags) catch {
            vh.close(fd);
            return null;
        };
        vh.close(fd);
        fd = n;
    }
    return fd;
}

// ---------- процессы

fn pids() []const []const u8 {
    const all = vh.listDir("/proc") catch return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (all) |n| if (n[0] >= '1' and n[0] <= '9') out.append(vh.gpa, n) catch vh.oom();
    return out.items;
}

fn procCommRunning(names: []const []const u8) bool {
    for (pids()) |p| {
        const comm = vh.rd(vh.fmt("/proc/{s}/comm", .{p}));
        for (names) |n| if (vh.eql(comm, n)) return true;
    }
    return false;
}

fn uidHasProcs(uid: u32) bool {
    for (pids()) |p| {
        const t = vh.readFile(vh.fmt("/proc/{s}/status", .{p})) catch continue;
        const u = mem.indexOf(u8, t, "\nUid:") orelse continue;
        var it = mem.tokenizeAny(u8, t[u + 5 ..], " \t\n");
        const r = std.fmt.parseInt(u32, it.next() orelse continue, 10) catch continue;
        if (r == uid) return true;
    }
    return false;
}

/// все файлы, открытые или отображённые в память процессами
fn openPaths() vh.Strv {
    var out: vh.Strv = .{};
    for (pids()) |p| {
        const fdd = vh.fmt("/proc/{s}/fd", .{p});
        if (vh.listDir(fdd)) |fds| {
            for (fds) |f| {
                const l = vh.readlink(vh.fmt("{s}/{s}", .{ fdd, f })) catch continue;
                if (l.len > 0 and l[0] == '/') out.add(l);
            }
        } else |_| {}
        const m = vh.readFile(vh.fmt("/proc/{s}/maps", .{p})) catch continue;
        for (lines(m)) |line| {
            if (mem.indexOfScalar(u8, line, '/')) |i| out.add(line[i..]);
        }
    }
    return out;
}

/// path или что-то внутри него открыто процессом
fn inUse(used: *const vh.Strv, path: []const u8) bool {
    for (used.slice()) |u| {
        if (vh.startsWith(u, path) and (u.len == path.len or u[path.len] == '/')) return true;
    }
    return false;
}

// ---------- xbps

fn capture(argv: []const []const u8) []const u8 {
    var o: std.ArrayList(u8) = .empty;
    _ = vh.runOpts(argv, .{ .out = &o });
    return o.items;
}

fn owned(pattern: []const u8) bool {
    return vh.strip(capture(&.{ "xbps-query", "-o", pattern })).len > 0;
}

fn confFiles(name: []const u8, out: *vh.Strv) void {
    for (lines(capture(&.{ "xbps-query", "-p", "conf_files", name }))) |l|
        if (l[0] == '/' and !out.has(l)) out.add(l);
}

const Orphan = struct { pkgver: []const u8, size: u64 };

/// сироты: pkgver и установленный размер каждого (xbps-remove -on)
fn orphans() []const Orphan {
    var out: std.ArrayList(Orphan) = .empty;
    for (lines(capture(&.{ "xbps-remove", "-on" }))) |l| {
        var f: [5][]const u8 = undefined;
        var n: usize = 0;
        var it = mem.tokenizeAny(u8, l, vh.space);
        while (it.next()) |w| : (n += 1) {
            if (n == 5) break;
            f[n] = w;
        }
        if (n < 2 or !vh.eql(f[1], "remove")) continue;
        const size: u64 = if (n == 5) std.fmt.parseInt(u64, f[4], 10) catch 0 else 0;
        out.append(vh.gpa, .{ .pkgver = f[0], .size = size }) catch vh.oom();
    }
    return out.items;
}

// ---------- защита путей

fn protectedPath(p: []const u8) bool {
    if (vh.startsWith(p, "/etc/vh/") or vh.eql(p, "/etc/vh")) return true;
    for (keep_paths.slice()) |k| {
        if (vh.startsWith(p, k) and (p.len == k.len or p[k.len] == '/' or k[k.len - 1] == '/')) return true;
    }
    // файл самой void-hardened (её копия — в /root/vh)
    for ([_][]const u8{ "", ".in", ".cin" }) |sfx|
        if (vh.pathExists(vh.fmt("/root/vh/rootfs{s}{s}", .{ p, sfx }))) return true;
    return false;
}

fn loadKeep() void {
    const t = vh.readFile(KEEP_FILE) catch return;
    for (lines(t)) |l| {
        if (l[0] == '#') continue;
        if (l[0] == '/') keep_paths.add(l) else keep_pkgs.add(l);
    }
}

// ---------- резерв

fn copyOne(src: []const u8, dst: []const u8) void {
    const st = vh.stat(src, false) catch vh.die("{s}: {s}", .{ src, vh.serr() });
    if (vh.S.isLnk(st.mode)) {
        const l = vh.readlink(src) catch vh.die("{s}: {s}", .{ src, vh.serr() });
        _ = vh.sys(linux.symlink(vh.z(l).ptr, vh.z(dst).ptr)) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
        _ = vh.sys(linux.fchownat(linux.AT.FDCWD, vh.z(dst).ptr, st.uid, st.gid, linux.AT.SYMLINK_NOFOLLOW)) catch
            vh.warn("{s}: {s}", .{ dst, vh.serr() });
        return;
    }
    if (!vh.S.isReg(st.mode)) vh.die("{s}: не обычный файл", .{src});
    const in = vh.openFd(src, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true }, 0) catch vh.die("{s}: {s}", .{ src, vh.serr() });
    const out = vh.openFd(dst, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o600) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    var b: [65536]u8 = undefined;
    while (true) {
        const n = vh.readFd(in, &b) catch vh.die("{s}: {s}", .{ src, vh.serr() });
        if (n == 0) break;
        vh.writeAllFd(out, b[0..n]) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    }
    const times = [2]linux.timespec{
        .{ .sec = st.atime.sec, .nsec = st.atime.nsec },
        .{ .sec = st.mtime.sec, .nsec = st.mtime.nsec },
    };
    _ = vh.sys(linux.fchown(out, st.uid, st.gid)) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    _ = vh.sys(linux.fchmod(out, st.mode & 0o7777)) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    _ = vh.sys(linux.futimens(out, &times)) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    _ = vh.sys(linux.fsync(out)) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    vh.close(out);
    vh.close(in);
}

/// переименовать, а между ФС — скопировать и удалить исходный
fn move(src: []const u8, dst: []const u8) bool {
    if (vh.sys(linux.rename(vh.z(src).ptr, vh.z(dst).ptr))) |_| return true else |_| {}
    if (vh.errno != .XDEV) {
        vh.warn("{s}: {s}", .{ src, vh.serr() });
        return false;
    }
    copyOne(src, dst);
    vh.unlink(src) catch {
        vh.warn("{s}: {s}", .{ src, vh.serr() });
        return false;
    };
    return true;
}

fn bkStart() void {
    if (bk_ready) return;
    vh.mkdirs(BK_DIR, 0o700);
    _ = linux.chmod(BK_DIR, 0o700);
    if (vh.pathExists(BK_LAST)) _ = pathEntry(BK_LAST, true);
    _ = vh.sys(linux.mkdir(BK_LAST, 0o700)) catch vh.die("{s}: {s}", .{ BK_LAST, vh.serr() });
    vh.writeAtomic(BK_LAST ++ "/when", vh.fmt("{s} UTC\n", .{vh.utcTime(vh.now())}), 0o600);
    bk_ready = true;
}

/// файл или ссылку — в резерв
fn bkMove(path: []const u8) bool {
    bkStart();
    const dst = vh.fmt("{s}/root{s}", .{ BK_LAST, path });
    vh.mkdirs(std.fs.path.dirname(dst).?, 0o700);
    return move(path, dst);
}

var restored: usize = 0;
var skipped: usize = 0;

fn restoreWalk(bk: []const u8, target: []const u8) void {
    const names = vh.listDir(bk) catch return;
    for (names) |name| {
        const b = vh.fmt("{s}/{s}", .{ bk, name });
        const t = vh.fmt("{s}/{s}", .{ target, name });
        const st = vh.stat(b, false) catch continue;
        if (vh.S.isDir(st.mode)) {
            restoreWalk(b, t);
        } else if (vh.pathExists(t)) {
            vh.out("  уже есть, оставлен в резерве: {s}\n", .{t});
            skipped += 1;
        } else {
            const dir = std.fs.path.dirname(t) orelse "";
            if (dir.len > 0) vh.mkdirs(dir, 0o755);
            if (move(b, t)) {
                vh.out("  вернул {s}\n", .{t});
                restored += 1;
            } else {
                skipped += 1;
            }
        }
    }
}

fn doRestore() u8 {
    if (!vh.isDir(BK_LAST ++ "/root")) vh.die("резерва нет ({s})", .{BK_LAST});
    const when = vh.readFile(BK_LAST ++ "/when") catch "?\n";
    vh.out("Резерв от {s}", .{when});
    restoreWalk(BK_LAST ++ "/root", "");
    if (skipped == 0) _ = pathEntry(BK_LAST, true);
    vh.out("Возвращено: {d}, оставлено в резерве: {d}\n", .{ restored, skipped });
    if (restored > 0) vh.outs("Сервисы, вернувшиеся в /etc/runit/runsvdir, runit запустит сам. Проверка: doas vh-audit\n");
    return if (skipped > 0) 1 else 0;
}

// ---------- группы

/// в режиме плана — false; при --apply — вопрос (или -y)
fn confirm(q: []const u8) bool {
    if (!apply) return false;
    if (!vh.ask(q, yes)) {
        vh.outs("   пропущено\n");
        return false;
    }
    return true;
}

fn gOrphans() void {
    section("orphans: зависимости, которые больше никому не нужны");
    const kernel = env.get("VH_KERNEL", "");
    var list = orphans();
    var kept: vh.Strv = .{};
    // keep-список и ядро системы — в ручные: тогда xbps не считает сиротами ни их,
    // ни их зависимости
    for (list) |o| {
        const n = pkgname(o.pkgver);
        if (keep_pkgs.has(n) or (kernel.len > 0 and vh.eql(n, kernel))) kept.add(n);
    }
    for (kept.slice()) |k| {
        vh.out("   остаётся (deep-clean.keep или ядро системы): {s}\n", .{k});
        if (apply) _ = vh.run(&.{ "xbps-pkgdb", "-m", "manual", k });
    }
    if (apply and kept.len() > 0) list = orphans();
    var sz: u64 = 0;
    var shown: usize = 0;
    for (list) |o| {
        if (kept.has(pkgname(o.pkgver))) continue; // в плане keep-пакеты ещё в списке
        vh.out("   {s}\n", .{o.pkgver});
        sz += o.size;
        shown += 1;
    }
    if (shown == 0) return vh.outs("   нет\n");
    vh.out("   пакетов: {d}, {s}; их изменённые конфиги уйдут в резерв (conf)\n", .{ shown, hsize(sz) });
    if (!confirm("Удалить эти пакеты?")) {
        if (!apply) total += sz;
        return;
    }
    for (list) |o| confFiles(pkgname(o.pkgver), &orphan_conf);
    if (vh.run(&.{ "xbps-remove", "-oy" }) != 0) vh.warn("xbps-remove -o завершился с ошибкой", .{}) else total += sz;
}

/// «.new-ВЕРСИЯ_РЕВИЗИЯ» в конце имени: так xbps кладёт новую версию изменённого конфига
fn xbpsNewName(name: []const u8) bool {
    const p0 = mem.lastIndexOf(u8, name, ".new-") orelse return false;
    if (p0 == 0) return false;
    const p = name[p0 + 5 ..];
    const us = mem.lastIndexOfScalar(u8, p, '_') orelse return false;
    if (us == 0 or us + 1 == p.len) return false;
    for (p[0..us]) |ch| if (!(mem.indexOfScalar(u8, ".+~-", ch) != null or std.ascii.isAlphanumeric(ch))) return false;
    for (p[us + 1 ..]) |ch| if (!std.ascii.isDigit(ch)) return false;
    return true;
}

fn findNew(dir: []const u8, out: *vh.Strv, depth: u32) void {
    if (depth > 16 or vh.eql(dir, "/etc/vh")) return;
    const names = vh.listDir(dir) catch return;
    for (names) |name| {
        const p = vh.fmt("{s}/{s}", .{ dir, name });
        const st = vh.stat(p, false) catch continue;
        if (vh.S.isDir(st.mode)) {
            findNew(p, out, depth + 1);
        } else if ((vh.S.isReg(st.mode) or vh.S.isLnk(st.mode)) and xbpsNewName(name)) {
            out.add(p);
        }
    }
}

fn gConf() void {
    section("conf: конфиги, которые больше ничему не принадлежат (→ резерв)");
    var cand: vh.Strv = .{};
    var why: vh.Strv = .{};
    var found: vh.Strv = .{};
    findNew("/etc", &found, 0);
    for (found.slice()) |f| {
        cand.add(f);
        why.add("новая версия конфига от xbps, не применена (действует старая)");
    }
    const ledger: ?[]u8 = vh.readFile(CONF_LEDGER) catch null;
    if (ledger) |t| for (lines(t)) |l| {
        if (l[0] == '/' and !cand.has(l)) {
            cand.add(l);
            why.add("конфиг удалённого пакета");
        }
    };
    for (orphan_conf.slice()) |c| if (!cand.has(c)) {
        cand.add(c);
        why.add("конфиг удалённой зависимости");
    };
    var go: vh.Strv = .{};
    var sz: u64 = 0;
    for (cand.slice(), 0..) |p, i| {
        const st = vh.stat(p, false) catch continue;
        if (!(vh.S.isReg(st.mode) or vh.S.isLnk(st.mode))) continue;
        if (protectedPath(p) or owned(p)) continue;
        vh.out("   {s}  — {s}\n", .{ p, why.slice()[i] });
        go.add(p);
        sz += blocks(st);
    }
    if (go.len() == 0) {
        vh.outs("   нет\n");
        if (apply and ledger != null) vh.unlink(CONF_LEDGER) catch {};
        return;
    }
    vh.out("   файлов: {d}, {s} (вернуть: doas vh-deep-clean restore)\n", .{ go.len(), hsize(sz) });
    if (!confirm("Убрать в резерв?")) {
        if (!apply) total += sz;
        return;
    }
    for (go.slice()) |p| if (!bkMove(p)) {
        sz = 0;
    };
    total += sz;
    vh.unlink(CONF_LEDGER) catch {};
}

fn gServices() void {
    section("services: битые ссылки сервисов (→ резерв)");
    var go: vh.Strv = .{};
    const levels = vh.listDir("/etc/runit/runsvdir") catch &.{};
    for (levels) |lv| {
        if (lv[0] == '.') continue;
        const lvl = vh.fmt("/etc/runit/runsvdir/{s}", .{lv});
        const st = vh.stat(lvl, false) catch continue;
        if (!vh.S.isDir(st.mode)) continue;
        const svcs = vh.listDir(lvl) catch continue;
        for (svcs) |s| {
            const p = vh.fmt("{s}/{s}", .{ lvl, s });
            const ls = vh.stat(p, false) catch continue;
            if (!vh.S.isLnk(ls.mode)) continue;
            if (vh.stat(p, true)) |_| continue else |_| if (vh.errno != .NOENT) continue;
            if (protectedPath(p)) continue;
            const t = vh.readlink(p) catch "";
            vh.out("   {s} → {s} (нет)\n", .{ p, t });
            go.add(p);
        }
    }
    if (go.len() == 0) {
        vh.outs("   нет\n");
    } else if (confirm("Убрать ссылки в резерв?")) {
        for (go.slice()) |p| _ = bkMove(p);
    }
}

fn release() []const u8 {
    var u: linux.utsname = undefined;
    _ = linux.uname(&u);
    return vh.dupe(mem.sliceTo(&u.release, 0));
}

fn gKernels() void {
    section("kernels: старые ядра");
    const rel = release();
    if (!owned("/boot/vmlinu[xz]-*")) return vh.outs("   установленное ядро не найдено в базе xbps — группа пропущена\n");
    var vk: vh.Strv = .{};
    var stale: vh.Strv = .{};
    for (lines(capture(&.{ "vkpurge", "list" }))) |l|
        if (!vh.eql(l, rel) and mem.indexOfScalar(u8, l, '/') == null) vk.add(l);
    var sz: u64 = 0;
    for (vk.slice()) |v| {
        var s = pathEntry(vh.fmt("/usr/lib/modules/{s}", .{v}), false);
        for ([_][]const u8{ "/boot/vmlinuz-", "/boot/vmlinux-", "/boot/config-", "/boot/System.map-" }) |bf|
            s += pathEntry(vh.fmt("{s}{s}", .{ bf, v }), false);
        vh.out("   ядро {s} — {s} (UKI и запись Limine уберёт хук ядра)\n", .{ v, hsize(s) });
        sz += s;
    }
    // каталоги модулей без ядра: остаются после удаления пакета (modules.dep и др.)
    const mods = vh.listDir("/usr/lib/modules") catch &.{};
    for (mods) |v| {
        if (v[0] == '.' or vh.eql(v, rel) or vk.has(v)) continue;
        const m = vh.fmt("/usr/lib/modules/{s}", .{v});
        if (!vh.pathExists(vh.fmt("/boot/vmlinuz-{s}", .{v})) and !vh.pathExists(vh.fmt("/boot/vmlinux-{s}", .{v})) and
            vh.isDir(m) and !owned(vh.fmt("/usr/lib/modules/{s}/*", .{v})))
        {
            const s = pathEntry(m, false);
            vh.out("   {s} — каталог модулей без ядра, {s}\n", .{ m, hsize(s) });
            stale.add(m);
            sz += s;
        }
    }
    if (vk.len() == 0 and stale.len() == 0) return vh.outs("   нет (работающее ядро и ядра пакетов не удаляются никогда)\n");
    vh.out("   всего {s}; работающее ядро {s} остаётся\n", .{ hsize(sz), rel });
    if (!confirm("Удалить старые ядра?")) {
        if (!apply) total += sz;
        return;
    }
    if (vk.len() > 0) purge: {
        const offline = vh.eql(boot.get("KEYS_OFFLINE", "no"), "yes");
        var keys = false;
        if (offline) {
            if (yes) {
                vh.outs("   ключи Secure Boot на отдельном носителе: без вопросов ядра не удаляются (запустите без -y)\n");
                break :purge;
            }
            vh.outs("Вставьте носитель с ключами Secure Boot и нажмите Enter… ");
            vh.flush();
            if (vh.readLine() == null or vh.run(&.{ "/usr/local/sbin/vh-keys", "mount" }) != 0) {
                vh.outs("   носитель не подключён — ядра не удалены\n");
                break :purge;
            }
            keys = true;
        }
        var a: std.ArrayList([]const u8) = .empty;
        a.appendSlice(vh.gpa, &.{ "vkpurge", "rm" }) catch vh.oom();
        a.appendSlice(vh.gpa, vk.slice()) catch vh.oom();
        if (vh.run(a.items) != 0) vh.warn("vkpurge завершился с ошибкой", .{});
        if (keys) _ = vh.run(&.{ "/usr/local/sbin/vh-keys", "umount" });
    }
    for (stale.slice()) |m| _ = pathEntry(m, true);
    total += sz;
}

fn gCache() void {
    section("cache: скачанные пакеты (" ++ CACHE_DIR ++ ")");
    const dfd = vh.openFd(CACHE_DIR, dir_flags, 0) catch return vh.outs("   нет\n");
    defer vh.close(dfd);
    var go: vh.Strv = .{};
    var sz: u64 = 0;
    const names = vh.listDirFd(dfd) catch &.{};
    for (names) |n| {
        const st = vh.statAt(dfd, n, false) catch continue;
        if (!vh.S.isReg(st.mode)) continue;
        go.add(n);
        sz += blocks(st);
    }
    if (go.len() == 0) return vh.outs("   пусто\n");
    vh.out("   файлов: {d}, {s} (xbps скачает заново, если понадобится)\n", .{ go.len(), hsize(sz) });
    if (confirm("Очистить кэш?")) {
        for (go.slice()) |n| _ = entry(dfd, n, true);
        total += sz;
    } else if (!apply) {
        total += sz;
    }
}

/// что удалить у одного пользователя: каталог rel в home и его записи names
const UTarget = struct { rel: []const u8, names: vh.Strv = .{}, size: u64 = 0 };

/// удалить от имени владельца: ошибка в путях пользователя не станет ошибкой root
fn clearAs(uid: u32, gid: u32, home: []const u8, ts: []const UTarget) void {
    vh.flush();
    const pid_rc = vh.sys(linux.fork()) catch vh.die("fork: {s}", .{vh.serr()});
    if (pid_rc == 0) {
        if (uid != 0) {
            if (linux.errno(linux.setgroups(0, &[_]linux.gid_t{})) != .SUCCESS or
                linux.errno(linux.setresgid(gid, gid, gid)) != .SUCCESS or
                linux.errno(linux.setresuid(uid, uid, uid)) != .SUCCESS or linux.getuid() != uid)
                linux.exit_group(1);
        }
        for (ts) |t| {
            const fd = openUnder(home, t.rel) orelse continue;
            for (t.names.slice()) |n| _ = entry(fd, n, true);
            vh.close(fd);
        }
        linux.exit_group(0);
    }
    var st: u32 = 0;
    while (true) {
        const rc = linux.wait4(@intCast(pid_rc), @ptrCast(&st), 0, null);
        const e = linux.errno(rc);
        if (e == .SUCCESS) break;
        if (e != .INTR) {
            vh.errno = e;
            vh.die("waitpid: {s}", .{vh.serr()});
        }
    }
}

/// записи каталога rel (кроме занятых программами) — в цель
fn collect(home: []const u8, rel: []const u8, used: ?*const vh.Strv, label: []const u8) UTarget {
    var t: UTarget = .{ .rel = rel };
    const fd = openUnder(home, rel) orelse return t;
    defer vh.close(fd);
    var busy: vh.Strv = .{};
    const names = vh.listDirFd(fd) catch &.{};
    for (names) |n| {
        const full = vh.fmt("{s}/{s}/{s}", .{ home, rel, n });
        if (used != null and inUse(used.?, full)) {
            busy.add(n);
        } else {
            t.names.add(n);
            t.size += entry(fd, n, false);
        }
    }
    if (t.names.len() > 0 or busy.len() > 0) {
        vh.out("   {s}/{s} — {s}{s}", .{ home, rel, hsize(t.size), label });
        if (busy.len() > 0) vh.out(" (занято программами, остаётся: {s})", .{busy.join(", ")});
        vh.outs("\n");
    }
    return t;
}

fn gUser() void {
    section("user: мусор пользователей");
    const used = openPaths();
    const browser = env.get("VH_BROWSER_USER", "");
    const pw = vh.readFile("/etc/passwd") catch vh.die("/etc/passwd: {s}", .{vh.serr()});
    const User = struct { uid: u32, gid: u32, home: []const u8, t: std.ArrayList(UTarget) = .empty };
    var us: std.ArrayList(User) = .empty;
    var sz: u64 = 0;
    for (lines(pw)) |l| {
        var f: [7][]const u8 = @splat("");
        var it = mem.splitScalar(u8, l, ':');
        var nf: usize = 0;
        while (it.next()) |x| : (nf += 1) {
            if (nf == 7) break;
            f[nf] = x;
        }
        if (nf < 6 or us.items.len >= 64) continue;
        const uid = std.fmt.parseInt(u32, f[2], 10) catch 0;
        const gid = std.fmt.parseInt(u32, f[3], 10) catch 0;
        const human = uid >= 1000 and uid < 60000 and vh.startsWith(f[5], "/home/");
        const is_browser = browser.len > 0 and vh.eql(f[0], browser);
        if (!human and uid != 0 and !is_browser) continue;
        if (!vh.isDir(f[5])) continue;
        var u: User = .{ .uid = uid, .gid = gid, .home = f[5] };
        if (is_browser) {
            if (uidHasProcs(uid)) {
                vh.out("   {s}: Firefox запущен — кэш браузера пропущен\n", .{f[0]});
                continue;
            }
            for ([_][]const u8{ "trusted/.cache", "trusted/profile/cache2", "trusted/profile/startupCache", "trusted/profile/thumbnails", "trusted/profile/shader-cache" }) |rel|
                u.t.append(vh.gpa, collect(u.home, rel, null, " (кэш Firefox)")) catch vh.oom();
        } else {
            u.t.append(vh.gpa, collect(u.home, ".cache", &used, "")) catch vh.oom();
            u.t.append(vh.gpa, collect(u.home, ".local/share/Trash", null, " (корзина)")) catch vh.oom();
        }
        for (u.t.items) |t| sz += t.size;
        us.append(vh.gpa, u) catch vh.oom();
    }
    if (sz == 0) return vh.outs("   нет\n");
    vh.out("   всего {s}; программы создадут кэш заново\n", .{hsize(sz)});
    if (confirm("Очистить?")) {
        for (us.items) |u| clearAs(u.uid, u.gid, u.home, u.t.items);
        total += sz;
    } else if (!apply) {
        total += sz;
    }
}

// ---------- проверка системы

fn audit(fails: *vh.Strv) bool {
    if (!vh.isRegular(AUDIT)) return false;
    var o: std.ArrayList(u8) = .empty;
    _ = vh.runOpts(&.{AUDIT}, .{ .out = &o, .err = &o });
    for (lines(o.items)) |l| if (vh.startsWith(l, "[FAIL]")) fails.add(l);
    return true;
}

/// строки WARNING/ERROR проверки базы пакетов (xbps-pkgdb -a)
fn pkgdb(errs: *vh.Strv) void {
    var o: std.ArrayList(u8) = .empty;
    _ = vh.runOpts(&.{ "xbps-pkgdb", "-a" }, .{ .out = &o, .err = &o });
    for (lines(o.items)) |l| errs.add(l);
}

/// строки из after, которых не было в before; true, если такие есть
fn reportNew(before: *const vh.Strv, after: *const vh.Strv, title: []const u8) bool {
    var fresh: usize = 0;
    for (after.slice()) |a| if (!before.has(a)) {
        if (fresh == 0) vh.out("!! {s}:\n", .{title});
        fresh += 1;
        vh.out("   {s}\n", .{a});
    };
    return fresh > 0;
}

fn usage() noreturn {
    vh.flush();
    vh.writeAllFd(2,
        \\doas vh-deep-clean                       план (ничего не меняет)
        \\doas vh-deep-clean --apply [-y] [--user] [--only ГРУППА,…]
        \\doas vh-deep-clean restore               вернуть файлы из резерва
        \\группы: orphans conf services kernels cache user
        \\
    ) catch {};
    vh.exit(2);
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-deep-clean");
    vh.setenv("PATH", "/usr/bin");
    _ = linux.syscall1(.umask, 0o022);
    var groups = std.EnumSet(Group).initMany(&.{ .orphans, .conf, .services, .kernels, .cache });
    var user = false;
    var restore = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (vh.eql(a, "restore") and i == 0 and args.len == 1) {
            restore = true;
        } else if (vh.eql(a, "--apply")) {
            apply = true;
        } else if (vh.eql(a, "-y") or vh.eql(a, "--yes")) {
            yes = true;
        } else if (vh.eql(a, "--user")) {
            user = true;
        } else if (vh.eql(a, "--only") and i + 1 < args.len) {
            i += 1;
            groups = .empty;
            var it = mem.tokenizeScalar(u8, args[i], ',');
            while (it.next()) |g| groups.insert(std.meta.stringToEnum(Group, g) orelse usage());
        } else {
            usage();
        }
    }
    if (user) groups.insert(.user);
    if (yes and !apply) usage();
    if (linux.geteuid() != 0) vh.die("запустите: doas vh-deep-clean …", .{});
    if (restore) vh.exit(doRestore());
    if (procCommRunning(&.{ "xbps-install", "xbps-remove", "xbps-reconfigure", "xbps-pkgdb", "vkpurge", "vh-update", "vh-pkg", "thor" }))
        vh.die("сейчас работает xbps (установка или обновление) — запустите после него", .{});
    env.read("/etc/vh/vh.env", false);
    boot.read("/etc/vh/boot.conf", true);
    loadKeep();

    var before: vh.Strv = .{};
    var db_before: vh.Strv = .{};
    var audited = false;
    if (apply) {
        vh.outs("Проверка системы до очистки (vh-audit, xbps-pkgdb)…\n");
        audited = audit(&before);
        pkgdb(&db_before);
    } else {
        vh.outs("План очистки — ничего не изменено. Выполнить: doas vh-deep-clean --apply\n");
    }
    if (groups.contains(.orphans)) gOrphans();
    if (groups.contains(.conf)) gConf();
    if (groups.contains(.services)) gServices();
    if (groups.contains(.kernels)) gKernels();
    if (groups.contains(.cache)) gCache();
    if (groups.contains(.user)) {
        gUser();
    } else if (!apply) {
        vh.outs("\n(мусор пользователей — ~/.cache, кэш Firefox, корзина — добавляет --user)\n");
    }

    vh.out("\n{s}: {s}\n", .{ if (apply) "Освобождено" else "Можно освободить", hsize(total) });
    if (!apply) vh.exit(0);
    var rc: u8 = 0;
    var db_after: vh.Strv = .{};
    pkgdb(&db_after);
    if (reportNew(&db_before, &db_after, "Новые ошибки базы пакетов (xbps-pkgdb -a)")) rc = 1;
    if (bk_ready) vh.out("Резерв: {s} (вернуть: doas vh-deep-clean restore)\n", .{BK_LAST});
    if (audited) {
        vh.outs("Проверка системы после очистки (vh-audit)…\n");
        var after: vh.Strv = .{};
        _ = audit(&after);
        if (reportNew(&before, &after, "Новые FAIL после очистки")) {
            vh.outs("   Вернуть файлы из резерва: doas vh-deep-clean restore\n");
            rc = 1;
        } else {
            vh.out("vh-audit: новых FAIL нет (было и осталось: {d})\n", .{after.len()});
        }
    }
    if (rc == 0) vh.outs("Система в порядке.\n");
    vh.exit(rc);
}

test "xbpsNewName" {
    try std.testing.expect(xbpsNewName("foo.conf.new-1.2_1"));
    try std.testing.expect(xbpsNewName("a.new-2.0rc1_12"));
    try std.testing.expect(!xbpsNewName("bar.new-notversion"));
    try std.testing.expect(!xbpsNewName(".new-1.0_1"));
    try std.testing.expect(!xbpsNewName("x.new-1.0_"));
    try std.testing.expect(!xbpsNewName("x.new-1.0_1a"));
}

test "hsize как printf" {
    try std.testing.expectEqualStrings("512 Б", hsize(512));
    try std.testing.expectEqualStrings("1.5 КБ", hsize(1536));
    try std.testing.expectEqualStrings("2.0 МБ", hsize(2 << 20));
}
