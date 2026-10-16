//! vh-deadman — стирание ключа LUKS и открытого текста из RAM (optional/deadman, docs/13).
//!
//! Два режима выключения:
//!   тревожный  — извлечение метки (USB-устройство) или комбинация клавиш на встроенной
//!                клавиатуре: ключ тома стирается за доли секунды, данные последних секунд
//!                не сохраняются;
//!   штатный    — стадия 3 runit (кнопка питания, крышка, простой, doas poweroff): сервисы
//!                остановлены, данные сброшены, корень только для чтения — затем то же
//!                стирание (shutdown.d/85-vh-deadman.sh вызывает «vh-deadman final»).
//!
//! Порядок после триггера (без fork, exec, чтения с диска и выделения памяти — всё открыто
//! и закреплено в RAM заранее, mlockall):
//!   1. DM_DEV_SUSPEND с NOFLUSH|SKIP_LOCKFS + DM_TARGET_MSG «key wipe» для каждого тома
//!      dm-crypt — ключ тома стёрт из памяти ядра; после этого читать с диска нельзя;
//!   2. kill(-1, SIGKILL) — память процессов освобождается и (init_on_free=1) обнуляется;
//!   3. swapoff и reset zram — zsmalloc не обнуляет освобождённые объекты сам;
//!   4. drop_caches=3 — page cache с расшифрованными файлами, dentry и inode;
//!   5. MOR есть: флаг VhPoweroff в NVRAM и sysrq b — прошивка стирает RAM при POST, а
//!      initramfs по флагу выключает машину (91vhdeadman); MOR нет: sysrq o (выключение).
//! Остаточный риск: процессы, застрявшие в D-state на приостановленном томе, и грязные
//! страницы недавно записанных файлов (без MOR — в RAM до потери питания); длинное нажатие
//! кнопки питания обходит всё это.
//!
//!   vh-deadman daemon   — резидентный режим (runit-сервис vh-deadman)
//!   vh-deadman final    — финал штатного выключения (стадия 3)
//!   vh-deadman test     — показать, что найдено, ничего не делая
const std = @import("std");
const vh = @import("vh");
const linux = std.os.linux;
const mem = std.mem;

const CONF = "/etc/vh/deadman.conf";
/// GUID LINUX_EFI_CRASH_GUID: переменные с ним efivarfs создаёт удаляемыми — initramfs
/// снимет флаг без chattr. Имя не начинается с dump- — efi-pstore его не трогает.
const EFI_FLAG = "VhPoweroff-cfc8fc79-be2e-4ddc-97f0-9f98bfe298a0";
const MOR_VAR = "/sys/firmware/efi/efivars/MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829";
const MAX_VOL = 16;

const usage_text =
    \\vh-deadman daemon   — резидентный режим (runit-сервис vh-deadman)
    \\vh-deadman final    — финал штатного выключения (стадия 3)
    \\vh-deadman test     — показать, что найдено, ничего не делая
    \\
;

// ---------------------------------------------------------------- device-mapper (linux/dm-ioctl.h)

const DM_NAME_LEN = 128;
const DM_UUID_LEN = 129;
const DM_VERSION_MAJOR = 4;
const DM_SUSPEND_FLAG: u32 = 1 << 1;
const DM_SKIP_LOCKFS_FLAG: u32 = 1 << 10;
const DM_NOFLUSH_FLAG: u32 = 1 << 11;

/// struct dm_ioctl
pub const DmIoctl = extern struct {
    version: [3]u32,
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [DM_NAME_LEN]u8,
    uuid: [DM_UUID_LEN]u8,
    data: [7]u8,
};
comptime {
    std.debug.assert(@sizeOf(DmIoctl) == 312);
}

fn dmIowr(cmd: u32) u32 {
    return (3 << 30) | (@as(u32, @sizeOf(DmIoctl)) << 16) | (0xfd << 8) | cmd;
}
pub const DM_DEV_SUSPEND = dmIowr(6);
pub const DM_TARGET_MSG = dmIowr(14);

/// struct dm_ioctl с данными; размер кратен 8
const DmReq = extern struct { io: DmIoctl, data: [64]u8 };

fn dmInit(r: *DmReq, name: []const u8, flags: u32, payload: []const u8) void {
    r.* = mem.zeroes(DmReq);
    r.io.version = .{ DM_VERSION_MAJOR, 0, 0 };
    r.io.data_size = @intCast((@sizeOf(DmIoctl) + payload.len + 7) & ~@as(usize, 7));
    r.io.data_start = @sizeOf(DmIoctl);
    r.io.flags = flags;
    const n = @min(name.len, DM_NAME_LEN - 1);
    @memcpy(r.io.name[0..n], name[0..n]);
    const bytes: [*]u8 = @ptrCast(r);
    @memcpy(bytes[@sizeOf(DmIoctl)..][0..payload.len], payload);
}

const Vol = struct { name: []const u8, susp: DmReq, msg: DmReq };

/// всё, что нужно для стирания, — открыто и подготовлено заранее
var W: struct {
    dmctl: vh.fd_t = -1,
    drop: vh.fd_t = -1,
    sysrq: vh.fd_t = -1,
    efi: vh.fd_t = -1,
    vol: [MAX_VOL]Vol = undefined,
    nvol: usize = 0,
    zdev: [MAX_VOL][:0]const u8 = undefined,
    zreset: [MAX_VOL]vh.fd_t = undefined,
    nz: usize = 0,
} = .{};

/// записи каталога с префиксом, по имени (как glob)
fn globDir(dir: []const u8, prefix: []const u8) []const []const u8 {
    const names = vh.listDir(dir) catch return &.{};
    var s: vh.Strv = .{};
    for (names) |n| if (vh.startsWith(n, prefix)) s.add(n);
    s.sort();
    return s.slice();
}

fn wiperInit() void {
    if (linux.errno(linux.mlockall(.{ .CURRENT = true, .FUTURE = true })) != .SUCCESS)
        vh.log("mlockall: {s} — память демона может уйти в zram", .{vh.strerror(linux.errno(linux.mlockall(.{ .CURRENT = true, .FUTURE = true })))});
    W.dmctl = vh.openFd("/dev/mapper/control", .{ .ACCMODE = .RDWR }, 0) catch vh.die("/dev/mapper/control: {s}", .{vh.serr()});
    for (globDir("/sys/block", "dm-")) |b| {
        if (W.nvol >= MAX_VOL) break;
        const d = vh.fmt("/sys/block/{s}/dm", .{b});
        if (!vh.pathExists(d)) continue;
        if (!vh.startsWith(vh.rd(vh.fmt("{s}/uuid", .{d})), "CRYPT-")) continue;
        const name = vh.rd(vh.fmt("{s}/name", .{d}));
        const v = &W.vol[W.nvol];
        W.nvol += 1;
        v.name = name[0..@min(name.len, DM_NAME_LEN - 1)];
        dmInit(&v.susp, name, DM_SUSPEND_FLAG | DM_SKIP_LOCKFS_FLAG | DM_NOFLUSH_FLAG, "");
        // struct dm_target_msg: сектор (u64) и текст сообщения
        dmInit(&v.msg, name, 0, "\x00\x00\x00\x00\x00\x00\x00\x00key wipe\x00");
    }
    for (globDir("/sys/block", "zram")) |n| {
        if (W.nz >= MAX_VOL) break;
        const fd = vh.openFd(vh.fmt("/sys/block/{s}/reset", .{n}), .{ .ACCMODE = .WRONLY }, 0) catch continue;
        W.zdev[W.nz] = vh.z(vh.fmt("/dev/{s}", .{n}));
        W.zreset[W.nz] = fd;
        W.nz += 1;
    }
    W.drop = vh.openFd("/proc/sys/vm/drop_caches", .{ .ACCMODE = .WRONLY }, 0) catch
        vh.die("/proc/sys/vm/drop_caches, /proc/sysrq-trigger: {s}", .{vh.serr()});
    W.sysrq = vh.openFd("/proc/sysrq-trigger", .{ .ACCMODE = .WRONLY }, 0) catch
        vh.die("/proc/sys/vm/drop_caches, /proc/sysrq-trigger: {s}", .{vh.serr()});
    if (vh.pathExists(MOR_VAR))
        W.efi = vh.openFd("/sys/firmware/efi/efivars", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch -1;
    // прогрев: первые вызовы не должны ничего подгружать
    if (linux.errno(linux.write(W.drop, "1", 1)) != .SUCCESS)
        vh.log("drop_caches: {s}", .{vh.strerror(linux.errno(linux.write(W.drop, "1", 1)))});
}

fn describe() []const u8 {
    var names: std.ArrayList(u8) = .empty;
    for (W.vol[0..W.nvol], 0..) |v, i| names.print(vh.gpa, "{s}{s}", .{ if (i > 0) ", " else "", v.name }) catch vh.oom();
    return vh.fmt("тома dm-crypt: {s}; zram: {d}; MOR: {s}", .{
        if (W.nvol > 0) names.items else "нет", W.nz, if (W.efi >= 0) "есть" else "нет",
    });
}

/// Только системные вызовы над заранее открытыми дескрипторами: ни памяти, ни диска.
fn wipe(reboot: bool) noreturn {
    for (W.vol[0..W.nvol]) |*v| {
        // следующий том стираем, даже если с этим не вышло
        _ = linux.ioctl(W.dmctl, DM_DEV_SUSPEND, @intFromPtr(&v.susp));
        _ = linux.ioctl(W.dmctl, DM_TARGET_MSG, @intFromPtr(&v.msg));
    }
    _ = linux.kill(-1, .KILL);
    var ts: linux.timespec = .{ .sec = 0, .nsec = 300 * 1000 * 1000 };
    _ = linux.nanosleep(&ts, null); // процессы выходят, слоты swap освобождаются
    for (0..W.nz) |i| {
        _ = linux.syscall1(.swapoff, @intFromPtr(W.zdev[i].ptr));
        _ = linux.write(W.zreset[i], "1", 1); // занятое устройство — RAM всё равно стирается ниже
    }
    _ = linux.write(W.drop, "3", 1);
    if (W.efi < 0) {
        // MOR нет: прошивка RAM не сотрёт — выключение мимо userspace, без перезагрузки
        _ = linux.write(W.sysrq, if (reboot) "b" else "o", 1);
        while (true) _ = linux.pause();
    }
    if (!reboot) {
        const rc = linux.openat(W.efi, EFI_FLAG, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o644);
        if (linux.errno(rc) == .SUCCESS) {
            const fd: vh.fd_t = @intCast(rc);
            const v = [_]u8{ 0x07, 0x00, 0x00, 0x00, 0x01 }; // NV|BS|RT + 1 байт
            _ = linux.write(fd, &v, v.len);
            _ = linux.close(fd);
        }
    }
    _ = linux.write(W.sysrq, "b", 1); // перезагрузка через прошивку: MOR стирает RAM
    while (true) _ = linux.pause();
}

/// число hex как strtoul(…, 16): необязательный «0x»; null — нет цифр или больше 0xFFFF
fn hex16(s: []const u8) ?u16 {
    const t = if (vh.startsWith(s, "0x") or vh.startsWith(s, "0X")) s[2..] else s;
    if (t.len == 0) return null;
    return std.fmt.parseInt(u16, t, 16) catch null;
}

/// TAG = vid:pid (hex, как в lsusb)
pub fn parseTag(tag: []const u8) ?[2]u16 {
    const colon = mem.indexOfScalar(u8, tag, ':') orelse return null;
    const rest = tag[colon + 1 ..];
    const end = mem.indexOfScalar(u8, rest, ':') orelse rest.len;
    return .{ hex16(tag[0..colon]) orelse return null, hex16(rest[0..end]) orelse return null };
}

fn parseTagOrDie(tag: []const u8) [2]u16 {
    return parseTag(tag) orelse vh.die("TAG={s}: нужен vid:pid (lsusb)", .{tag});
}

/// есть ли такое USB-устройство; его DEVPATH (без /sys)
fn tagPresent(vp: [2]u16) ?[]const u8 {
    for (globDir("/sys/bus/usb/devices", "")) |n| {
        const d = vh.fmt("/sys/bus/usb/devices/{s}", .{n});
        const v = vh.rd(vh.fmt("{s}/idVendor", .{d}));
        if (v.len == 0) continue;
        const q = vh.rd(vh.fmt("{s}/idProduct", .{d}));
        if ((hex16(v) orelse continue) != vp[0] or (hex16(q) orelse continue) != vp[1]) continue;
        const real = vh.realpath(d) catch continue;
        if (vh.startsWith(real, "/sys")) return real[4..];
    }
    return null;
}

fn status(s: []const u8) void {
    const fd = vh.openFd("/run/vh/deadman", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o644) catch return;
    defer vh.close(fd);
    vh.writeAllFd(fd, vh.fmt("{s}\n", .{s})) catch {};
}

/// значение KEY= в сообщении uevent (поля через \0)
pub fn uev(d: []const u8, key: []const u8) []const u8 {
    var it = mem.splitScalar(u8, d, 0);
    while (it.next()) |f| {
        if (f.len > key.len and vh.startsWith(f, key) and f[key.len] == '=') return f[key.len + 1 ..];
    }
    return "";
}

const EV_KEY = 1;
const KEY_RIGHTCTRL = 97;
const KEY_RIGHTALT = 100;
const KEY_END = 107;
const InputEvent = extern struct { sec: i64, usec: i64, type: u16, code: u16, value: i32 };

fn daemonLoop(conf: *const vh.Kv) noreturn {
    const tag = conf.get("TAG", "");
    var armed: [512]u8 = undefined;
    var armed_len: usize = 0;
    var prod_buf: [32]u8 = undefined;
    var prod: []const u8 = "";
    var pfd: [2]linux.pollfd = undefined;
    var np: usize = 0;
    var nl: vh.fd_t = -1;
    var kbd: vh.fd_t = -1;
    var wd: vh.fd_t = -1;
    if (tag.len > 0) {
        const vp = parseTagOrDie(tag);
        prod = std.fmt.bufPrint(&prod_buf, "{x}/{x}/", .{ vp[0], vp[1] }) catch unreachable;
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 15); // NETLINK_KOBJECT_UEVENT
        nl = @intCast(vh.sys(rc) catch vh.die("netlink uevent: {s}", .{vh.serr()}));
        var sa = mem.zeroes(linux.sockaddr.nl);
        sa.family = linux.AF.NETLINK;
        sa.groups = 1;
        _ = vh.sys(linux.bind(nl, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl))) catch vh.die("netlink uevent: {s}", .{vh.serr()});
        pfd[np] = .{ .fd = nl, .events = linux.POLL.IN, .revents = 0 };
        np += 1;
        if (tagPresent(vp)) |p| {
            armed_len = @min(p.len, armed.len);
            @memcpy(armed[0..armed_len], p[0..armed_len]);
        }
    }
    if (vh.eql(conf.get("COMBO", "no"), "yes")) {
        for (globDir("/sys/class/input", "event")) |e| {
            // только встроенная клавиатура i8042
            if (!vh.startsWith(vh.rd(vh.fmt("/sys/class/input/{s}/device/phys", .{e})), "isa0060/serio0")) continue;
            kbd = vh.openFd(vh.fmt("/dev/input/{s}", .{e}), .{ .ACCMODE = .RDONLY }, 0) catch -1;
            if (kbd >= 0) break;
        }
        if (kbd >= 0) {
            pfd[np] = .{ .fd = kbd, .events = linux.POLL.IN, .revents = 0 };
            np += 1;
        }
    }
    if (vh.eql(conf.get("WATCHDOG", "no"), "yes") and vh.pathExists("/dev/watchdog"))
        wd = vh.openFd("/dev/watchdog", .{ .ACCMODE = .WRONLY }, 0) catch -1;
    vh.mkdirs("/run/vh", 0o755);
    status(if (armed_len > 0) "armed" else "disarmed");
    vh.log("{s}; метка {s}: {s}; комбинация: {s}; сторож: {s}", .{
        describe(),                              if (tag.len > 0) tag else "—",
        if (armed_len > 0) "вставлена" else "нет", if (kbd >= 0) "да" else "нет",
        if (wd >= 0) "да" else "нет",
    });
    var rctrl = false;
    var ralt = false;
    var end = false;
    const S = struct {
        var buf: [8192]u8 = undefined;
    };
    while (true) {
        if (wd >= 0) {
            const e = linux.errno(linux.write(wd, "\x00", 1));
            if (e != .SUCCESS) vh.log("watchdog: {s}", .{vh.strerror(e)});
        }
        const r = linux.poll(&pfd, np, if (wd >= 0) 10000 else -1);
        const pe = linux.errno(r);
        if (pe != .SUCCESS and pe != .INTR) {
            vh.errno = pe;
            vh.die("poll: {s}", .{vh.serr()});
        }
        if (pe != .SUCCESS) continue;
        for (pfd[0..np]) |p| {
            if (p.revents == 0) continue;
            if (p.fd == nl) {
                var from: linux.sockaddr.nl = undefined;
                var fl: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
                const n = linux.recvfrom(nl, &S.buf, S.buf.len - 1, 0, @ptrCast(&from), &fl);
                if (linux.errno(n) != .SUCCESS or n == 0 or from.pid != 0) continue; // только сообщения ядра
                const d = S.buf[0..n];
                if (!vh.eql(uev(d, "SUBSYSTEM"), "usb") or !vh.eql(uev(d, "DEVTYPE"), "usb_device") or
                    !vh.startsWith(uev(d, "PRODUCT"), prod)) continue;
                const action = uev(d, "ACTION");
                const devpath = uev(d, "DEVPATH");
                if (vh.eql(action, "add")) {
                    armed_len = @min(devpath.len, armed.len);
                    @memcpy(armed[0..armed_len], devpath[0..armed_len]);
                    status("armed");
                } else if (vh.eql(action, "remove") and armed_len > 0 and vh.eql(devpath, armed[0..armed_len])) {
                    vh.log("метка извлечена — тревожное выключение", .{});
                    wipe(false);
                }
            } else if (p.fd == kbd) {
                var ev: [64]InputEvent = undefined;
                const n = linux.read(kbd, @ptrCast(&ev), @sizeOf(@TypeOf(ev)));
                if (linux.errno(n) != .SUCCESS or n == 0) continue;
                for (ev[0 .. n / @sizeOf(InputEvent)]) |x| {
                    if (x.type != EV_KEY or x.value == 2) continue;
                    const down = x.value == 1;
                    switch (x.code) {
                        KEY_RIGHTCTRL => rctrl = down,
                        KEY_RIGHTALT => ralt = down,
                        KEY_END => end = down,
                        else => {},
                    }
                    if (rctrl and ralt and end) {
                        vh.log("тревожная комбинация — выключение", .{});
                        wipe(false);
                    }
                }
            }
        }
    }
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-deadman");
    if (linux.geteuid() != 0) vh.die("нужен root", .{});
    const mode: []const u8 = if (args.len > 0) args[0] else "";
    var conf: vh.Kv = .{};
    conf.set("TAG", "");
    conf.set("COMBO", "no");
    conf.set("WATCHDOG", "no");
    conf.read(CONF, true);
    if (vh.eql(mode, "test")) {
        wiperInit();
        const tag = conf.get("TAG", "");
        const armed: ?[]const u8 = if (tag.len > 0) tagPresent(parseTagOrDie(tag)) else null;
        vh.out("{s} | метка: {s} {s}\n", .{ describe(), if (tag.len > 0) tag else "—", if (armed != null) "вставлена" else "" });
    } else if (vh.eql(mode, "final")) {
        wiperInit();
        if (vh.eql(conf.get("WATCHDOG", "no"), "yes")) {
            if (vh.openFd("/dev/watchdog", .{ .ACCMODE = .WRONLY }, 0)) |wd| _ = linux.write(wd, "\x00", 1) else |_| {}
        }
        const reboot = linux.errno(linux.access("/run/runit/reboot", linux.X_OK)) == .SUCCESS;
        vh.out("vh-deadman: стирание ключа и RAM ({s})\n", .{if (reboot) "перезагрузка" else "выключение"});
        vh.flush();
        wipe(reboot);
    } else if (vh.eql(mode, "daemon")) {
        wiperInit();
        daemonLoop(&conf);
    } else {
        vh.outs(usage_text);
        vh.exit(2);
    }
    vh.exit(0);
}

test "parseTag и uev" {
    try std.testing.expectEqual([2]u16{ 0x1050, 0x0407 }, parseTag("1050:0407").?);
    try std.testing.expectEqual([2]u16{ 0x1050, 0x407 }, parseTag("0x1050:407:x").?);
    try std.testing.expect(parseTag("10500:1") == null);
    try std.testing.expect(parseTag("xyz") == null);
    const m = "add@/devices/x\x00ACTION=add\x00DEVPATH=/devices/pci/usb1/1-2\x00SUBSYSTEM=usb\x00";
    try std.testing.expectEqualStrings("/devices/pci/usb1/1-2", uev(m, "DEVPATH"));
    try std.testing.expectEqualStrings("", uev(m, "PRODUCT"));
}
