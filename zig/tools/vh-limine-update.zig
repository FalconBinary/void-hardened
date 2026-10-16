//! vh-limine-update — пересборка цепочки загрузки на ESP (docs/03-boot.md).
//!
//! 1. Оставляет на ESP KEEP последних UKI (+ UKI работающего ядра), остальные удаляет.
//! 2. Подписывает UKI ключом db (sbctl).
//! 3. Пишет limine.conf: по записи на UKI, путь с хэшем BLAKE2B (Limine сверяет файл).
//! 4. Берёт чистый BOOTX64.EFI из пакета limine, вписывает в него BLAKE2B конфига
//!    (limine enroll-config), подписывает и атомарно заменяет копию на ESP.
//!
//! С Secure Boot и вписанным хэшем Limine проверяет конфиг при каждой загрузке,
//! отключает редактор и требует хэши у всех путей.
//!
//!   vh-limine-update [--new ВЕРСИЯ] [--dry-run]
const std = @import("std");
const vh = @import("vh");
const hash = @import("hash");
const linux = std.os.linux;
const mem = std.mem;

const ESP = "/boot/efi";
const UKI_DIR = ESP ++ "/EFI/void";
const LIMINE_DIR = ESP ++ "/EFI/BOOT";
const LIMINE_SRC = "/usr/share/limine/BOOTX64.EFI";
const BOOT_CONF = "/etc/vh/boot.conf";
const DB_KEY = "/var/lib/sbctl/keys/db/db.key";

const Uki = struct {
    name: []const u8,
    /// «6.18.56_1» — как в имени файла
    ver: []const u8,
    v: [4]u64,
};

/// linux-A.B.C_D.efi → номера версии; null — не UKI
pub fn parseUki(name: []const u8) ?Uki {
    if (!vh.startsWith(name, "linux-") or !vh.endsWith(name, ".efi")) return null;
    const end = name.len - 4;
    const seps = [3]u8{ '.', '.', '_' };
    var u: Uki = .{ .name = name, .ver = name[6..end], .v = undefined };
    var p: usize = 6;
    for (0..4) |i| {
        var q = p;
        while (q < end and std.ascii.isDigit(name[q])) q += 1;
        if (q == p or q - p > 9) return null;
        u.v[i] = std.fmt.parseInt(u64, name[p..q], 10) catch return null;
        if (i < 3 and (q >= end or name[q] != seps[i])) return null;
        if (i == 3 and q != end) return null;
        p = q + 1;
    }
    return u;
}

/// по убыванию версии, при равенстве — по убыванию имени (как qsort в C-версии)
fn ukiDesc(_: void, x: Uki, y: Uki) bool {
    for (0..4) |i| if (x.v[i] != y.v[i]) return x.v[i] > y.v[i];
    return mem.order(u8, x.name, y.name) == .gt;
}

fn secureBootEnabled() bool {
    const dir = "/sys/firmware/efi/efivars";
    const names = vh.listDir(dir) catch return false;
    var first: ?[]const u8 = null;
    for (names) |n| if (vh.startsWith(n, "SecureBoot-")) {
        if (first == null or vh.lessStr({}, n, first.?)) first = n;
    };
    const d = vh.readFile(vh.fmt("{s}/{s}", .{ dir, first orelse return false })) catch return false;
    return d.len > 4 and d[4] == 1;
}

fn isMount(path: []const u8) bool {
    const a = vh.stat(path, false) catch return false;
    if (vh.S.isLnk(a.mode)) return false;
    const b = vh.stat(vh.fmt("{s}/..", .{path}), false) catch return false;
    return a.dev_major != b.dev_major or a.dev_minor != b.dev_minor or a.ino == b.ino;
}

fn sign(path: []const u8, dry: bool, offline: bool) void {
    if (!vh.pathExists(DB_KEY)) {
        if (offline)
            vh.die("носитель с ключом не подключён (" ++ DB_KEY ++ ") — подпись невозможна.\n" ++
                "  Подключите его и повторите: doas vh-keys mount && doas xbps-reconfigure -f " ++
                "<пакет ядра>; затем doas vh-keys umount (docs/13, sb-offline-keys)", .{});
        if (secureBootEnabled())
            vh.die("Secure Boot включён, а ключа " ++ DB_KEY ++ " нет: неподписанную UKI прошивка не " ++
                "загрузит. limine.conf не изменён — загрузится прежнее ядро", .{});
        vh.out("  ключей Secure Boot ещё нет (" ++ DB_KEY ++ ") — {s} не подписан\n", .{path});
        return;
    }
    if (dry) return vh.out("  + sbctl sign {s}\n", .{path});
    var out: std.ArrayList(u8) = .empty;
    var err: std.ArrayList(u8) = .empty;
    if (vh.runOpts(&.{ "sbctl", "sign", path }, .{ .out = &out, .err = &err }) != 0)
        vh.die("sbctl sign {s}: {s}{s}", .{ path, out.items, err.items });
}

fn copyFile(src: []const u8, dst: []const u8) void {
    const d = vh.readFile(src) catch vh.die("{s}: {s}", .{ src, vh.serr() });
    const fd = vh.openFd(dst, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o644) catch
        vh.die("{s}: {s}", .{ dst, vh.serr() });
    vh.writeAllFd(fd, d) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
    _ = vh.sys(linux.close(fd)) catch vh.die("{s}: {s}", .{ dst, vh.serr() });
}

fn replaceAtomic(src: []const u8, dst: []const u8) void {
    const d = vh.readFile(src) catch vh.die("{s}: {s}", .{ src, vh.serr() });
    vh.writeAtomic(dst, d, 0o644);
}

/// mkdtemp: каталог 0700 со случайным суффиксом
fn mkdtemp(prefix: []const u8) []const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (0..100) |_| {
        var r: [6]u8 = undefined;
        _ = linux.getrandom(&r, r.len, 0);
        var s: [6]u8 = undefined;
        for (r, 0..) |b, i| s[i] = alphabet[b % alphabet.len];
        const p = vh.fmt("{s}{s}", .{ prefix, s });
        if (vh.sys(linux.mkdir(vh.z(p).ptr, 0o700))) |_| return p else |_| if (vh.errno != .EXIST) break;
    }
    vh.die("mkdtemp: {s}", .{vh.serr()});
}

fn usage() noreturn {
    vh.writeAllFd(2, "vh-limine-update [--new ВЕРСИЯ] [--dry-run]\n") catch {};
    vh.exit(2);
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-limine-update");
    vh.setenv("PATH", "/usr/bin");
    var newver: ?[]const u8 = null;
    var dry = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (vh.eql(args[i], "--dry-run")) {
            dry = true;
        } else if (vh.eql(args[i], "--new") and i + 1 < args.len) {
            i += 1;
            newver = args[i];
        } else if (vh.startsWith(args[i], "--new=")) {
            newver = args[i][6..];
        } else usage();
    }

    if (!isMount(ESP)) vh.die(ESP ++ " не смонтирован — подпись отменена (UKI не должна лечь на корень)", .{});
    var conf: vh.Kv = .{};
    conf.set("KEEP", "2");
    conf.set("TIMEOUT", "1");
    conf.set("KEYS_OFFLINE", "no");
    conf.read(BOOT_CONF, false);
    const keep_n = conf.int("KEEP", "2");
    const timeout = conf.int("TIMEOUT", "1");
    if (keep_n < 1 or keep_n > 5 or timeout < 0 or timeout > 30) vh.die("неверные KEEP/TIMEOUT в " ++ BOOT_CONF, .{});
    const offline = vh.eql(conf.get("KEYS_OFFLINE", "no"), "yes");

    var ukis: std.ArrayList(Uki) = .empty;
    const names = vh.listDir(UKI_DIR) catch &.{};
    for (names) |n| {
        if (parseUki(n)) |u| {
            ukis.append(vh.gpa, u) catch vh.oom();
        } else if (vh.endsWith(n, ".efi")) {
            vh.out("  внимание: незнакомый файл " ++ UKI_DIR ++ "/{s} — не трогаю\n", .{n});
        }
    }
    if (ukis.items.len == 0) vh.die("в " ++ UKI_DIR ++ " нет UKI", .{});
    mem.sort(Uki, ukis.items, {}, ukiDesc);
    if (newver) |nv| {
        const found = for (ukis.items) |u| {
            if (vh.eql(u.ver, nv)) break true;
        } else false;
        if (!found) vh.die("UKI для {s} не создана — смотрите вывод dracut выше", .{nv});
    }

    // keep: индексы в ukis
    var keep: std.ArrayList(usize) = .empty;
    for (0..@min(ukis.items.len, @as(usize, @intCast(keep_n)))) |k| keep.append(vh.gpa, k) catch vh.oom();
    var un: linux.utsname = undefined;
    _ = linux.uname(&un);
    const release = mem.sliceTo(&un.release, 0);
    for (ukis.items, 0..) |u, k| {
        if (vh.eql(u.ver, release) and mem.indexOfScalar(usize, keep.items, k) == null)
            keep.append(vh.gpa, k) catch vh.oom(); // ядро, на котором работаем, не удаляем никогда
    }

    // Сначала проверка и подпись, потом удаление: сбой подписи оставляет ESP как был
    // (прежний limine.conf ссылается на прежние, подписанные UKI).
    if (offline and newver != null and !dry) {
        const path = vh.fmt(UKI_DIR ++ "/linux-{s}.efi", .{newver.?});
        if (vh.run(&.{ "/usr/local/sbin/vh-uki-verify", path, newver.? }) != 0)
            vh.die("проверка входных данных UKI не пройдена — подпись отменена (docs/13)", .{});
    }
    for (keep.items) |k| sign(vh.fmt(UKI_DIR ++ "/{s}", .{ukis.items[k].name}), dry, offline);
    for (ukis.items, 0..) |u, k| {
        if (mem.indexOfScalar(usize, keep.items, k) != null) continue;
        vh.out("  удаляю устаревшую UKI {s}\n", .{u.name});
        const path = vh.fmt(UKI_DIR ++ "/{s}", .{u.name});
        if (!dry) vh.unlink(path) catch vh.die("{s}: {s}", .{ path, vh.serr() });
    }

    var c: std.ArrayList(u8) = .empty;
    c.print(vh.gpa, "# Сгенерировано vh-limine-update — не редактировать вручную:\n" ++
        "# хэш этого файла вписан в BOOTX64.EFI, любая правка = отказ загрузки.\n" ++
        "timeout: {d}\neditor_enabled: no\nhash_mismatch_panic: yes\nverbose: no\n", .{timeout}) catch vh.oom();
    for (keep.items, 0..) |k, j| {
        const u = ukis.items[k];
        const path = vh.fmt(UKI_DIR ++ "/{s}", .{u.name});
        const h = hash.blake2bFile(path) catch vh.die("{s}: {s}", .{ path, vh.serr() });
        c.print(vh.gpa, "\n/Void Linux {s}{s}\n    protocol: efi\n    path: boot():/EFI/void/{s}#{s}\n", .{
            u.ver, if (j > 0) " (предыдущее ядро)" else "", u.name, h,
        }) catch vh.oom();
    }
    const conf_hash = hash.blake2bHex(c.items);

    if (newver != null and !dry and vh.pathExists("/etc/vh/totp.conf")) {
        // optional/tpm2-totp: новая UKI меняет PCR 4 — при следующей загрузке initramfs
        // предложит перезапечатать секрет (флаг: только факт наличия файла)
        vh.mkdirs("/var/lib/vh", 0o700);
        if (vh.openFd("/var/lib/vh/totp-reseal", .{ .ACCMODE = .WRONLY, .CREAT = true, .NOFOLLOW = true }, 0o600)) |fd| vh.close(fd) else |_| {}
        vh.outs("  tpm2-totp: при следующей загрузке код один раз не совпадёт — перезапечатайте (RESEAL)\n");
    }

    if (dry) {
        vh.out("{s}\n", .{c.items});
        vh.out("  + limine enroll-config BOOTX64.EFI {s}\n", .{conf_hash});
        vh.exit(0);
    }

    vh.mkdirs(LIMINE_DIR, 0o755);
    const td = mkdtemp("/tmp/vh-limine.");
    const cfg_tmp = vh.fmt("{s}/limine.conf", .{td});
    const efi_tmp = vh.fmt("{s}/BOOTX64.EFI", .{td});
    {
        const fd = vh.openFd(cfg_tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true }, 0o644) catch
            vh.die("{s}: {s}", .{ cfg_tmp, vh.serr() });
        vh.writeAllFd(fd, c.items) catch vh.die("{s}: {s}", .{ cfg_tmp, vh.serr() });
        _ = vh.sys(linux.close(fd)) catch vh.die("{s}: {s}", .{ cfg_tmp, vh.serr() });
    }
    copyFile(LIMINE_SRC, efi_tmp); // чистая копия: подпись и старый хэш не наследуются
    var out: std.ArrayList(u8) = .empty;
    var err: std.ArrayList(u8) = .empty;
    if (vh.runOpts(&.{ "limine", "enroll-config", efi_tmp, conf_hash }, .{ .out = &out, .err = &err }) != 0) {
        vh.unlink(cfg_tmp) catch {};
        vh.unlink(efi_tmp) catch {};
        _ = linux.rmdir(vh.z(td).ptr);
        vh.die("limine enroll-config: {s}{s}", .{ out.items, err.items });
    }
    sign(efi_tmp, false, offline);
    // Порядок важен: сначала конфиг, потом загрузчик. Сбой между ними даёт
    // «хэш не совпал» (отказ загрузки, но не обход проверки); повторный запуск чинит.
    replaceAtomic(cfg_tmp, LIMINE_DIR ++ "/limine.conf");
    replaceAtomic(efi_tmp, LIMINE_DIR ++ "/BOOTX64.EFI");
    vh.unlink(cfg_tmp) catch {};
    vh.unlink(efi_tmp) catch {};
    _ = linux.rmdir(vh.z(td).ptr);
    linux.sync();
    vh.out("  limine.conf: {d} записей, хэш конфига {s}… вписан в Limine\n", .{ keep.items.len, conf_hash[0..16] });
    vh.exit(0);
}

test "parseUki" {
    const u = parseUki("linux-6.18.56_1.efi").?;
    try std.testing.expectEqualStrings("6.18.56_1", u.ver);
    try std.testing.expectEqual(@as(u64, 56), u.v[2]);
    try std.testing.expect(parseUki("linux-6.18_1.efi") == null);
    try std.testing.expect(parseUki("linux-6.18.56_1x.efi") == null);
    try std.testing.expect(parseUki("linux-6.18.1234567890_1.efi") == null);
    try std.testing.expect(parseUki("other.efi") == null);
}
