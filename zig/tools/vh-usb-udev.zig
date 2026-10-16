//! vh-usb-udev — решение об авторизации USB (optional/usb-auth, docs/13). Вызывается udev.
//!
//! Ядро загружено с usbcore.authorized_default=2: устройства на внутренних портах
//! (connect_type=hardwired по ACPI) авторизуются сами, внешние — нет. У корневых хабов
//! interface_authorized_default=0: даже у авторизованного устройства интерфейсы
//! создаются неавторизованными, драйвер к ним не привязывается. Этот помощник решает:
//!
//!   интерфейс внутреннего устройства  → авторизовать (кроме камеры при VH_CAMERA=no и
//!                                        Bluetooth при VH_BLUETOOTH=off);
//!   свой FIDO2-ключ из /etc/vh/usb-keys.conf (точный порт, VID:PID, serial,
//!   один интерфейс HID)              → авторизовать устройство и его интерфейс;
//!   устройство, подключённое «vh-usb attach» → только интерфейсы класса 08 (накопитель);
//!   всё прочее                        → остаётся неавторизованным (BadUSB-клавиатура мертва).
//!
//! Дескрипторы устройства пишет само устройство — разбор с проверкой каждой длины
//! (и проверками границ ReleaseSafe поверх).
//!
//!   vh-usb-udev device|interface DEVPATH
const std = @import("std");
const vh = @import("vh");
const mem = std.mem;

const KEYS = "/etc/vh/usb-keys.conf";
const ENV = "/etc/vh/vh.env";
const ATTACH_DIR = "/run/vh/usb-attach";

/// сообщение в журнал ядра (как C: сообщение до 511 байт, строка до 599)
fn klog(comptime f: []const u8, args: anytype) void {
    const full = vh.fmt(f, args);
    // строки производителя и товара пишет само устройство: управляющие байты
    // (перевод строки, ESC) в журнал не пропускаем
    var buf: [600]u8 = undefined;
    const pre = "<5>vh-usb: ";
    @memcpy(buf[0..pre.len], pre);
    var n: usize = pre.len;
    for (full[0..@min(full.len, 511)]) |ch| {
        buf[n] = if (ch < 0x20 or ch == 0x7f) '?' else ch;
        n += 1;
    }
    buf[n] = '\n';
    const line = buf[0 .. n + 1];
    const fd = vh.openFd("/dev/kmsg", .{ .ACCMODE = .WRONLY }, 0) catch return;
    defer vh.close(fd);
    vh.writeAllFd(fd, line) catch {};
}

fn attr(dev: []const u8, name: []const u8) []const u8 {
    return vh.rd(vh.fmt("{s}/{s}", .{ dev, name }));
}

fn wr(dev: []const u8, name: []const u8, val: []const u8) void {
    const p = vh.fmt("{s}/{s}", .{ dev, name });
    if (!vh.writeStr(p, val)) klog("запись {s}: {s}", .{ p, vh.serr() });
}

/// порт устройства «hardwired» по ACPI (встроенная камера, Bluetooth, клавиатура)
fn internal(dev: []const u8) bool {
    return vh.eql(attr(dev, "port/connect_type"), "hardwired");
}

const Ifs = struct { n: usize = 0, cls0: i32 = -1, proto0: i32 = -1 };

/// интерфейсы из сырых дескрипторов (у неавторизованного устройства активной
/// конфигурации нет, но дескрипторы прочитаны): число и класс/протокол первого
pub fn interfaces(raw: []const u8) Ifs {
    var r: Ifs = .{};
    var off: usize = 0;
    while (off + 2 <= raw.len) {
        const ln: usize = raw[off];
        // дескриптор, выходящий за буфер, — обрыв или подделка: дальше не разбираем
        if (ln < 2 or off + ln > raw.len) break;
        if (raw[off + 1] == 4 and ln >= 9) { // INTERFACE
            if (r.n == 0) {
                r.cls0 = raw[off + 5];
                r.proto0 = raw[off + 7];
            }
            r.n += 1;
        }
        off += ln;
    }
    return r;
}

fn keyMatch(dev: []const u8) bool {
    const port = std.fs.path.basename(dev);
    const vidpid = vh.fmt("{s}:{s}", .{ attr(dev, "idVendor"), attr(dev, "idProduct") });
    const serial = attr(dev, "serial");
    const text = vh.readFile(KEYS) catch return false;
    var lines = mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var f = mem.tokenizeAny(u8, line, " \t");
        const f0 = f.next() orelse continue;
        const f1 = f.next() orelse continue;
        const f2 = f.next() orelse continue;
        if (!vh.eql(f0, port) or !vh.eql(f1, vidpid) or !vh.eql(f2, serial)) continue;
        // FIDO: ровно один интерфейс, HID, без boot-протокола клавиатуры/мыши
        const raw = vh.readFile(vh.fmt("{s}/descriptors", .{dev})) catch return false;
        const i = interfaces(raw);
        return i.n == 1 and i.cls0 == 0x03 and i.proto0 == 0x00;
    }
    return false;
}

fn onDevice(dev: []const u8) void {
    const port = std.fs.path.basename(dev);
    if (vh.eql(attr(dev, "authorized"), "1")) return;
    if (keyMatch(dev)) {
        klog("свой FIDO-ключ на {s} — авторизую", .{port});
        return wr(dev, "authorized", "1");
    }
    klog("заблокировано: {s} {s}:{s} «{s} {s}» — флешка: vh-usb attach", .{
        port, attr(dev, "idVendor"), attr(dev, "idProduct"), attr(dev, "manufacturer"), attr(dev, "product"),
    });
    vh.mkdirs("/run/vh", 0o755);
    const fd = vh.openFd("/run/vh/usb-blocked", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, 0o644) catch return;
    defer vh.close(fd);
    vh.writeAllFd(fd, port) catch {};
}

fn onInterface(intf: []const u8) void {
    const dev = std.fs.path.dirname(intf).?;
    const c = attr(intf, "bInterfaceClass");
    const cls: u32 = std.fmt.parseInt(u8, if (c.len > 0) c else "ff", 16) catch 0xFF;
    if (vh.eql(attr(intf, "authorized"), "1")) return;
    if (vh.pathExists(vh.fmt(ATTACH_DIR ++ "/{s}", .{std.fs.path.basename(dev)}))) {
        if (cls == 0x08) wr(intf, "authorized", "1");
        return;
    }
    if (keyMatch(dev) and cls == 0x03) return wr(intf, "authorized", "1");
    if (internal(dev)) {
        var e: vh.Kv = .{};
        e.read(ENV, false);
        if (cls == 0x0E and !vh.eql(e.get("VH_CAMERA", ""), "yes")) return; // камера: только профиль звонков
        if (cls == 0xE0 and vh.eql(e.get("VH_BLUETOOTH", ""), "off")) return;
        wr(intf, "authorized", "1");
    }
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-usb-udev");
    if (args.len != 2) vh.exit(2);
    const real = vh.realpath(vh.fmt("/sys{s}", .{args[1]})) catch vh.exit(2);
    if (!vh.startsWith(real, "/sys/devices/") or mem.indexOfScalar(u8, real[13..], '/') == null) vh.exit(2);
    if (vh.eql(args[0], "device")) onDevice(real) else onInterface(real);
}

test "дескрипторы: обрыв и нулевая длина" {
    const hid = [_]u8{ 9, 2, 0, 0, 1, 1, 0, 0x80, 0x32, 9, 4, 0, 0, 1, 3, 0, 0, 0 };
    const r = interfaces(&hid);
    try std.testing.expectEqual(@as(usize, 1), r.n);
    try std.testing.expectEqual(@as(i32, 3), r.cls0);
    try std.testing.expectEqual(@as(usize, 0), interfaces(&[_]u8{ 9, 4, 0 }).n);
    try std.testing.expectEqual(@as(usize, 0), interfaces(&[_]u8{ 0, 4 }).n);
    try std.testing.expectEqual(@as(usize, 0), interfaces(&[_]u8{ 255, 4, 1, 2, 3, 4, 5, 6, 7 }).n);
    // интерфейс обрезан посередине (bLength 9, байтов 8) — не считается
    try std.testing.expectEqual(@as(usize, 0), interfaces(&[_]u8{ 9, 2, 0, 0, 1, 1, 0, 0x80, 0x32, 9, 4, 0, 0, 1, 3, 0 }).n);
}
