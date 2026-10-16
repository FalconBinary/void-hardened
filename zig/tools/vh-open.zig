//! vh-open — открыть недоверенный файл в песочнице (optional/viewers, docs/12, docs/13).
//!
//!   vh-open ФАЙЛ          — PDF → zathura, картинки → imv, видео/аудио → mpv, текст → less
//!   vh-open --gpu ФАЙЛ    — mpv с аппаратным декодированием (свои файлы: render node i915)
//!
//! Песочница bwrap: без сети и user namespace, свой /proc без счётчиков прерываний, /tmp —
//! каталог на noexec-tmpfs хоста, Wayland — только через фильтр vh-wlfilter, звук — через
//! ограниченный сокет PipeWire (без микрофона), seccomp-фильтр (тот же генератор, что
//! vh-seccomp viewer), PR_SET_MDWE (W^X силами ядра) для программ без JIT.
//!
//! Файл открывается без гонки «проверил путь — открыл другой»: компоненты пути проходятся
//! через openat(O_NOFOLLOW) от каталога, последний — O_PATH|O_NOFOLLOW, затем fstat —
//! обычный файл; в bwrap передаётся дескриптор (--ro-bind-fd), путь больше не используется.
//! Симлинки, подложенные браузером, отвергаются (а на /home/xfer — nosymfollow и так).
const std = @import("std");
const vh = @import("vh");
const seccomp = @import("seccomp");
const linux = std.os.linux;
const mem = std.mem;

const WL = "/run/vh-sandbox/wayland";
const PULSE = "/run/vh-sandbox/pulse";
const MFD_NOEXEC_SEAL: u32 = 0x0008;
const PR_SET_MDWE = 65;

const usage_text =
    \\vh-open ФАЙЛ          — PDF → zathura, картинки → imv, видео/аудио → mpv, текст → less
    \\vh-open --gpu ФАЙЛ    — mpv с аппаратным декодированием (свои файлы: render node i915)
    \\
;

/// абсолютный путь без «.» и «..» (как os.path.abspath: без разрешения симлинков)
fn abspath(p: []const u8) []const u8 {
    var in: []const u8 = p;
    if (p.len == 0 or p[0] != '/') {
        var cwd: [4096]u8 = undefined;
        const n = vh.sys(linux.getcwd(&cwd, cwd.len)) catch vh.die("getcwd: {s}", .{vh.serr()});
        in = vh.fmt("{s}/{s}", .{ mem.sliceTo(cwd[0..n], 0), p });
    }
    var parts: std.ArrayList([]const u8) = .empty;
    var it = mem.tokenizeScalar(u8, in, '/');
    while (it.next()) |t| {
        if (vh.eql(t, ".")) continue;
        if (vh.eql(t, "..")) {
            _ = parts.pop();
            continue;
        }
        parts.append(vh.gpa, t) catch vh.oom();
    }
    if (parts.items.len == 0) return "/";
    var out: std.ArrayList(u8) = .empty;
    for (parts.items) |t| out.print(vh.gpa, "/{s}", .{t}) catch vh.oom();
    return out.items;
}

/// O_PATH-дескриптор обычного файла; ни один компонент пути не симлинк
fn openNofollow(path: []const u8, name: *[]const u8) vh.fd_t {
    const last = mem.lastIndexOfScalar(u8, path, '/') orelse vh.die("{s}: не файл", .{path});
    if (last + 1 == path.len) vh.die("{s}: не файл", .{path});
    name.* = path[last + 1 ..];
    var fd = vh.openFd("/", .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true }, 0) catch vh.die("/: {s}", .{vh.serr()});
    var it = mem.tokenizeScalar(u8, path[0..last], '/');
    while (it.next()) |t| {
        const nfd = vh.openAt(fd, t, .{ .ACCMODE = .RDONLY, .PATH = true, .DIRECTORY = true, .NOFOLLOW = true }) catch
            vh.die("{s}: {s} (симлинк или нет файла)", .{ path, vh.serr() });
        vh.close(fd);
        fd = nfd;
    }
    // без O_CLOEXEC: дескриптор наследует bwrap (--ro-bind-fd)
    const rc = linux.openat(fd, vh.z(name.*).ptr, .{ .ACCMODE = .RDONLY, .PATH = true, .NOFOLLOW = true }, 0);
    const ffd: vh.fd_t = @intCast(vh.sys(rc) catch vh.die("{s}: {s} (симлинк или нет файла)", .{ path, vh.serr() }));
    vh.close(fd);
    const st = vh.fstat(ffd) catch vh.die("{s}: не обычный файл", .{path});
    if (!vh.S.isReg(st.mode)) vh.die("{s}: не обычный файл", .{path});
    return ffd;
}

fn pre(h: []const u8, sig: []const u8) bool {
    return mem.startsWith(u8, h, sig);
}

/// тип по сигнатуре (а не только по расширению): без libmagic вне песочницы
pub fn kindOf(h: []const u8, name: []const u8) ?[]const u8 {
    var ext_buf: [16]u8 = undefined;
    var ext: []const u8 = "";
    if (mem.lastIndexOfScalar(u8, name, '.')) |dot| {
        const e = name[dot + 1 ..];
        if (e.len < ext_buf.len) ext = std.ascii.lowerString(&ext_buf, e);
    }
    const n = h.len;
    const riff = pre(h, "RIFF") and n >= 12;
    if (pre(h, "%PDF")) return "pdf";
    if (pre(h, "\x89PNG\r\n\x1a\n") or pre(h, "\xff\xd8\xff") or pre(h, "GIF87a") or pre(h, "GIF89a") or
        (riff and mem.eql(u8, h[8..12], "WEBP")))
        return "image";
    if ((n >= 8 and mem.eql(u8, h[4..8], "ftyp")) or pre(h, "\x1a\x45\xdf\xa3") or pre(h, "OggS") or
        pre(h, "fLaC") or pre(h, "ID3\x03") or pre(h, "ID3\x04") or
        (riff and (mem.eql(u8, h[8..12], "AVI ") or mem.eql(u8, h[8..12], "WAVE"))) or
        vh.eql(ext, "mp3") or vh.eql(ext, "opus") or vh.eql(ext, "m4a"))
        return "media";
    if (mem.indexOfScalar(u8, h, 0) == null) return "text";
    return null;
}

fn readHead(fd: vh.fd_t, name: []const u8, buf: []u8) []const u8 {
    // переоткрытие O_PATH-дескриптора через «магическую» ссылку /proc/self/fd: она ведёт
    // на тот же объект файла, а не на путь (подмена по пути невозможна). O_NOFOLLOW здесь
    // нельзя — ядро ответило бы ELOOP
    const rfd = vh.openFd(vh.fmt("/proc/self/fd/{d}", .{fd}), .{ .ACCMODE = .RDONLY }, 0) catch
        vh.die("{s}: {s}", .{ name, vh.serr() });
    defer vh.close(rfd);
    const n = vh.readFd(rfd, buf) catch 0;
    return buf[0..n];
}

/// фильтр seccomp в memfd (без возможности исполнения), наследуется bwrap
fn seccompFd() vh.fd_t {
    var prog: [seccomp.max_ins]seccomp.Ins = undefined;
    var bytes: [seccomp.max_ins * 8]u8 = undefined;
    const b = seccomp.bytes(seccomp.build("viewer", &prog).?, &bytes);
    var rc = linux.memfd_create("vh-seccomp", MFD_NOEXEC_SEAL);
    if (linux.errno(rc) != .SUCCESS) rc = linux.memfd_create("vh-seccomp", 0);
    const fd: vh.fd_t = @intCast(vh.sys(rc) catch vh.die("memfd: {s}", .{vh.serr()}));
    vh.writeAllFd(fd, b) catch vh.die("memfd: {s}", .{vh.serr()});
    _ = vh.sys(linux.lseek(fd, 0, linux.SEEK.SET)) catch vh.die("memfd: {s}", .{vh.serr()});
    return fd;
}

/// домашний каталог из /etc/passwd (как getpwuid)
fn homeOf(uid: u32) []const u8 {
    const pw = vh.readFile("/etc/passwd") catch return "/";
    var lines = mem.tokenizeScalar(u8, pw, '\n');
    while (lines.next()) |l| {
        var f = mem.splitScalar(u8, l, ':');
        _ = f.next();
        _ = f.next();
        const u = f.next() orelse continue;
        _ = f.next();
        _ = f.next();
        const home = f.next() orelse continue;
        if ((std.fmt.parseInt(u32, u, 10) catch continue) == uid) return home;
    }
    return "/";
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-open");
    var gpu = false;
    var ai: usize = 0;
    if (args.len > 0 and vh.eql(args[0], "--gpu")) {
        gpu = true;
        ai = 1;
    }
    if (args.len - ai != 1) {
        vh.outs(usage_text);
        vh.exit(2);
    }
    const path = abspath(args[ai]);
    var name: []const u8 = undefined;
    const ffd = openNofollow(path, &name);
    var hbuf: [64]u8 = undefined;
    const kind = kindOf(readHead(ffd, name, &hbuf), name) orelse
        vh.die("{s}: неизвестный тип — откройте вручную в нужной программе с песочницей", .{name});
    const uid = linux.getuid();
    const rt = vh.fmt("/run/user/{d}", .{uid});
    const home = blk: {
        const h = vh.getenv("HOME") orelse "";
        break :blk if (h.len > 0) h else homeOf(uid);
    };
    const work = vh.fmt("/tmp/vh-open-{d}-{d}", .{ uid, linux.getpid() });
    _ = vh.sys(linux.mkdir(vh.z(work).ptr, 0o700)) catch vh.die("{s}: {s}", .{ work, vh.serr() });
    const wtmp = vh.fmt("{s}/tmp", .{work});
    const whome = vh.fmt("{s}/home", .{work});
    const wrun = vh.fmt("{s}/run", .{work});
    for ([_][]const u8{ wtmp, whome, wrun }) |d|
        _ = vh.sys(linux.mkdir(vh.z(d).ptr, 0o700)) catch vh.die("{s}: {s}", .{ work, vh.serr() });
    const target = vh.fmt("/input/{s}", .{name});
    const sfd = vh.fmt("{d}", .{seccompFd()});
    const ffds = vh.fmt("{d}", .{ffd});
    const lang = vh.getenv("LANG") orelse "";
    const term = vh.getenv("TERM") orelse "";

    var b: std.ArrayList([]const u8) = .empty;
    b.appendSlice(vh.gpa, &.{
        "bwrap",
        "--unshare-all",    "--unshare-user",       "--disable-userns", "--assert-userns-disabled",
        "--die-with-parent", "--new-session",       "--cap-drop",       "ALL",
        "--clearenv",
        "--ro-bind",        "/usr",                 "/usr",
        "--symlink",        "usr/bin",              "/bin",             "--symlink",
        "usr/bin",          "/sbin",                "--symlink",        "usr/lib",
        "/lib",             "--symlink",            "usr/lib",          "/lib64",
        "--ro-bind",        "/etc/fonts",           "/etc/fonts",
        "--ro-bind-try",    "/etc/ld.so.cache",     "/etc/ld.so.cache",
        "--ro-bind",        "/etc/localtime",       "/etc/localtime",
        "--ro-bind-try",    "/var/cache/fontconfig", "/var/cache/fontconfig",
        "--proc",           "/proc",
        "--ro-bind",        "/dev/null",            "/proc/interrupts",
        "--ro-bind",        "/dev/null",            "/proc/softirqs",
        "--ro-bind",        "/dev/null",            "/proc/stat",
        "--dev",            "/dev",
        "--bind",           wtmp,                   "/tmp",
        "--bind",           whome,                  home,
        "--bind",           wrun,                   rt,
        "--ro-bind-fd",     ffds,                   target,
        "--seccomp",        sfd,
        "--setenv",         "HOME",                 home,               "--setenv",
        "PATH",             "/usr/bin",
        "--setenv",         "XDG_RUNTIME_DIR",      rt,                 "--setenv",
        "LANG",             if (lang.len > 0) lang else "C.UTF-8",
        "--setenv",         "GDK_BACKEND",          "wayland",          "--setenv",
        "NO_AT_BRIDGE",     "1",
        "--setenv",         "GSETTINGS_BACKEND",    "memory",           "--chdir",
        "/tmp",
    }) catch vh.oom();
    if (!vh.eql(kind, "text")) {
        if (!vh.pathExists(WL)) vh.die("нет " ++ WL ++ " — vh-wlfilter не запущен", .{});
        b.appendSlice(vh.gpa, &.{ "--bind", WL, vh.fmt("{s}/wayland-0", .{rt}), "--setenv", "WAYLAND_DISPLAY", "wayland-0" }) catch vh.oom();
    }
    var cmd: std.ArrayList([]const u8) = .empty;
    var jit = false;
    if (vh.eql(kind, "pdf")) {
        cmd.append(vh.gpa, "zathura") catch vh.oom();
    } else if (vh.eql(kind, "image")) {
        cmd.append(vh.gpa, "imv") catch vh.oom();
    } else if (vh.eql(kind, "media")) {
        b.appendSlice(vh.gpa, &.{ "--bind-try", PULSE, vh.fmt("{s}/pulse/native", .{rt}), "--setenv", "PULSE_SERVER", vh.fmt("unix:{s}/pulse/native", .{rt}) }) catch vh.oom();
        cmd.appendSlice(vh.gpa, &.{ "mpv", "--no-config", "--load-scripts=no", "--ytdl=no", "--osc=no" }) catch vh.oom();
        if (gpu) {
            b.appendSlice(vh.gpa, &.{ "--dev-bind-try", "/dev/dri/renderD128", "/dev/dri/renderD128", "--ro-bind", "/sys", "/sys" }) catch vh.oom();
            cmd.append(vh.gpa, "--hwdec=vaapi") catch vh.oom();
        } else {
            cmd.appendSlice(vh.gpa, &.{ "--vo=wlshm", "--hwdec=no" }) catch vh.oom();
        }
        jit = true; // mpv: Lua (возможно LuaJIT) — без MDWE
    } else {
        b.appendSlice(vh.gpa, &.{ "--setenv", "LESSSECURE", "1", "--setenv", "LESSHISTFILE", "-", "--setenv", "TERM", if (term.len > 0) term else "xterm" }) catch vh.oom();
        cmd.append(vh.gpa, "less") catch vh.oom();
    }
    cmd.appendSlice(vh.gpa, &.{ "--", target }) catch vh.oom();
    b.append(vh.gpa, "--") catch vh.oom();
    b.appendSlice(vh.gpa, cmd.items) catch vh.oom();
    // PR_SET_MDWE(PR_MDWE_REFUSE_EXEC_GAIN): отображение не станет исполняемым после
    // создания. Наследуется через fork/exec. Не для программ с JIT.
    if (!jit) {
        const e = linux.errno(linux.prctl(PR_SET_MDWE, 1, 0, 0, 0));
        if (e != .SUCCESS) {
            vh.errno = e;
            vh.warn("PR_SET_MDWE не включён ({s})", .{vh.serr()});
        }
    }
    const cargv = vh.gpa.allocSentinel(?[*:0]const u8, b.items.len, null) catch vh.oom();
    for (b.items, 0..) |a, i| cargv[i] = vh.z(a).ptr;
    vh.flush();
    // абсолютный путь: PATH не доверяем
    vh.errno = linux.errno(linux.execve("/usr/bin/bwrap", cargv.ptr, vh.envp));
    vh.die("bwrap: {s}", .{vh.serr()});
}

test "kindOf" {
    try std.testing.expectEqualStrings("pdf", kindOf("%PDF-1.7", "a.pdf").?);
    try std.testing.expectEqualStrings("image", kindOf("RIFF\x00\x00\x00\x00WEBPVP8", "x").?);
    try std.testing.expectEqualStrings("media", kindOf("abc", "song.MP3").?);
    try std.testing.expectEqualStrings("text", kindOf("hello", "x").?);
    try std.testing.expect(kindOf("a\x00b", "x") == null);
    try std.testing.expectEqualStrings("text", kindOf("RIFF", "x").?); // короткий RIFF — не картинка
}

test "abspath" {
    try std.testing.expectEqualStrings("/a/c", abspath("/a/b/../c/."));
    try std.testing.expectEqualStrings("/", abspath("/.."));
}
