//! vh-pkg — установка и удаление программ (docs/12, раздел «Программы»).
//!
//!   doas vh-pkg add ПАКЕТ… [--ignore ЗАВИСИМОСТЬ…] [--keep ПУТЬ…] [-y]
//!   doas vh-pkg rm ПАКЕТ…                — удалить вместе с ненужными больше зависимостями
//!   doas vh-pkg scan ПАКЕТ…              — SUID и capabilities, вернувшиеся после обновлений
//!
//! Обезвреживание пакетов делает политика thor внутри libxbps (docs/18): SUID снимается
//! ещё до записи на диск, хуки kernel.d/dracut/profile.d не распаковываются, sysctl.d и
//! правила udev 0666 маскируются, чёрный список проверяется и при обновлениях. vh-pkg
//! остался обёрткой с привычными ключами:
//!   --ignore ИМЯ  — зависимость не ставится (ignorepkg в /etc/xbps.d; проверьте, что
//!                   программа работает без неё);
//!   --keep ПУТЬ   — исключение политики (thor keep);
//!   после установки и удаления — сироты (xbps-remove -o). Изменённые конфиги удаляемых
//!   пакетов xbps оставляет на месте — их пути пишутся в /var/lib/vh/removed-conf.list,
//!   и vh-deep-clean убирает их в резерв.
const std = @import("std");
const vh = @import("vh");
const mem = std.mem;

const IGNORE = "/etc/xbps.d/51-vh-pkg-ignore.conf";
const CONF_LEDGER = "/var/lib/vh/removed-conf.list";

fn pkgname(pkgver: []const u8) []const u8 {
    const d = mem.lastIndexOfScalar(u8, pkgver, '-') orelse return pkgver;
    return pkgver[0..d];
}

/// строка в файл, если её там нет; первая строка нового файла — заголовок
fn appendUnique(path: []const u8, line: []const u8, header: []const u8) bool {
    const text = vh.readFile(path) catch "";
    var it = mem.tokenizeScalar(u8, text, '\n');
    var empty = true;
    while (it.next()) |l| {
        if (vh.eql(l, line)) return false;
        empty = false;
    }
    var b: std.ArrayList(u8) = .empty;
    if (empty) {
        b.print(vh.gpa, "{s}\n", .{header}) catch vh.oom();
    } else {
        b.appendSlice(vh.gpa, text) catch vh.oom();
        if (text[text.len - 1] != '\n') b.append(vh.gpa, '\n') catch vh.oom();
    }
    b.print(vh.gpa, "{s}\n", .{line}) catch vh.oom();
    vh.writeAtomic(path, b.items, 0o644);
    return true;
}

fn must(argv: []const []const u8) void {
    const rc = vh.run(argv);
    if (rc != 0) vh.die("{s}: код {d}", .{ argv[0], rc });
}

/// конфиги пакетов, которые удалит plan (xbps-remove -…n), — в журнал для vh-deep-clean
fn recordConf(plan: []const []const u8) void {
    var o: std.ArrayList(u8) = .empty;
    _ = vh.runOpts(plan, .{ .out = &o });
    var lines = mem.tokenizeScalar(u8, o.items, '\n');
    while (lines.next()) |l| {
        var f = mem.tokenizeAny(u8, l, vh.space);
        const f0 = f.next() orelse continue;
        const f1 = f.next() orelse continue;
        if (!vh.eql(f1, "remove")) continue;
        var c: std.ArrayList(u8) = .empty;
        _ = vh.runOpts(&.{ "xbps-query", "-p", "conf_files", pkgname(f0) }, .{ .out = &c });
        var files = mem.tokenizeScalar(u8, c.items, '\n');
        while (files.next()) |raw| {
            const file = vh.strip(raw);
            if (file.len == 0 or file[0] != '/') continue;
            vh.mkdirs("/var/lib/vh", 0o755);
            _ = appendUnique(CONF_LEDGER, file, "# void-hardened: конфиги удалённых пакетов — их убирает vh-deep-clean");
        }
    }
}

fn removeOrphans() void {
    recordConf(&.{ "xbps-remove", "-on" });
    _ = vh.run(&.{ "xbps-remove", "-oy" });
}

fn stripQuiet() void {
    var o: std.ArrayList(u8) = .empty;
    _ = vh.runOpts(&.{ "/usr/local/sbin/vh-suid-strip", "--quiet" }, .{ .out = &o, .err = &o });
}

fn usage() noreturn {
    vh.flush();
    vh.writeAllFd(2,
        \\doas vh-pkg add ПАКЕТ… [--ignore ЗАВИСИМОСТЬ…] [--keep ПУТЬ…] [-y]
        \\doas vh-pkg scan ПАКЕТ…
        \\doas vh-pkg rm ПАКЕТ…
        \\
    ) catch {};
    vh.exit(2);
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-pkg");
    // программы — только из /usr/bin (vh.run ищет по PATH процесса)
    vh.setenv("PATH", "/usr/bin");
    if (std.os.linux.geteuid() != 0) vh.die("запустите: doas vh-pkg …", .{});
    if (args.len < 1) usage();
    const cmd = args[0];
    const is_add = vh.eql(cmd, "add");
    const is_scan = vh.eql(cmd, "scan");
    const is_rm = vh.eql(cmd, "rm");
    if (!is_add and !is_scan and !is_rm) usage();

    var pkgs: vh.Strv = .{};
    var ignore: vh.Strv = .{};
    var keep: vh.Strv = .{};
    var yes = false;
    var opts = true;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (opts and vh.eql(a, "--")) {
            opts = false;
        } else if (opts and is_add and vh.eql(a, "--ignore") and i + 1 < args.len) {
            i += 1;
            ignore.add(args[i]);
        } else if (opts and is_add and vh.startsWith(a, "--ignore=")) {
            ignore.add(a[9..]);
        } else if (opts and !is_rm and vh.eql(a, "--keep") and i + 1 < args.len) {
            i += 1;
            keep.add(args[i]);
        } else if (opts and !is_rm and vh.startsWith(a, "--keep=")) {
            keep.add(a[7..]);
        } else if (opts and is_add and (vh.eql(a, "-y") or vh.eql(a, "--yes"))) {
            yes = true;
        } else if (opts and a.len > 0 and a[0] == '-') {
            usage();
        } else {
            pkgs.add(a);
        }
    }
    if (pkgs.len() == 0) usage();

    if (is_scan) {
        // разбор файлов делает thor при каждой установке и обновлении (docs/18);
        // здесь — только SUID и capabilities, вернувшиеся мимо xbps
        stripQuiet();
        vh.outs("файлы пакетов проверяет thor при установке и обновлении (журнал: /var/log/thor.log)\n");
        vh.flush();
        return;
    }
    if (is_rm) {
        var a: std.ArrayList([]const u8) = .empty;
        a.appendSlice(vh.gpa, &.{ "xbps-remove", "-Rn" }) catch vh.oom();
        a.appendSlice(vh.gpa, pkgs.slice()) catch vh.oom();
        recordConf(a.items);
        a.items[1] = "-Ry";
        must(a.items);
        removeOrphans();
        return;
    }

    // add
    for (keep.slice()) |k| must(&.{ "thor", "keep", k });
    for (ignore.slice()) |dep| {
        const line = vh.fmt("ignorepkg={s}", .{dep});
        if (appendUnique(IGNORE, line, "# void-hardened: зависимости, которые vh-pkg по просьбе админа не ставит (docs/12)"))
            vh.out("{s}: зависимость не будет ставиться (проверьте, что программа работает)\n", .{line});
    }
    var a: std.ArrayList([]const u8) = .empty;
    a.appendSlice(vh.gpa, &.{ "thor", "install" }) catch vh.oom();
    if (yes) a.append(vh.gpa, "-y") catch vh.oom();
    a.appendSlice(vh.gpa, pkgs.slice()) catch vh.oom();
    const rc = vh.run(a.items);
    if (rc != 0) vh.exit(rc);
    removeOrphans();
    stripQuiet();
    vh.outs("\nПроверка всей системы: doas vh-audit\n");
    vh.flush();
}
