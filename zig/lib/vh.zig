//! void-hardened: общие функции инструментов на Zig (zig/README.md).
//! Только Linux и только системные вызовы (std.os.linux): строки, файлы, конфиги KEY=VALUE,
//! запуск программ без шелла. std.Io намеренно не используется — его API меняется от релиза
//! к релизу, а набор системных вызовов стабилен. Программы короткоживущие: вся память —
//! из одной арены процесса, ошибка выделения — die().
const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;

pub const E = linux.E;
pub const fd_t = linux.fd_t;
pub const mode_t = linux.mode_t;

/// имя программы для сообщений: «vh-pkg: …»
pub var prog: []const u8 = "vh";
var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
/// память процесса (освобождает ОС при выходе)
pub const gpa = arena_state.allocator();
/// окружение процесса — для execve
pub var envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
/// код последней ошибки системного вызова — как errno в C
pub var errno: E = .SUCCESS;

pub const Error = error{Sys};

/// Начало программы: имя для сообщений, окружение, аргументы (без argv[0]).
pub fn init(m: std.process.Init.Minimal, name: []const u8) []const [:0]const u8 {
    prog = name;
    if (@TypeOf(m.environ.block) == std.process.Environ.PosixBlock) envp = m.environ.block.slice.ptr;
    var list: std.ArrayList([:0]const u8) = .empty;
    var it = m.args.iterate();
    _ = it.skip();
    while (it.next()) |a| list.append(gpa, a) catch oom();
    return list.items;
}

// ---------------------------------------------------------------- сообщения и вывод

/// Буфер stdout: сбрасывается перед сообщениями в stderr, запуском программ и выходом.
var out_buf: std.ArrayList(u8) = .empty;

pub fn out(comptime f: []const u8, args: anytype) void {
    out_buf.print(gpa, f, args) catch oom();
    if (out_buf.items.len >= 8192) flush();
}

pub fn outs(s: []const u8) void {
    out_buf.appendSlice(gpa, s) catch oom();
    if (out_buf.items.len >= 8192) flush();
}

pub fn flush() void {
    writeAllFd(1, out_buf.items) catch {};
    out_buf.clearRetainingCapacity();
}

fn msgTo(fd: fd_t, comptime f: []const u8, args: anytype) void {
    const s = std.fmt.allocPrint(gpa, "{s}: " ++ f ++ "\n", .{prog} ++ args) catch oom();
    writeAllFd(fd, s) catch {};
}

pub fn die(comptime f: []const u8, args: anytype) noreturn {
    flush();
    msgTo(2, f, args);
    exit(1);
}

/// в stderr с префиксом
pub fn warn(comptime f: []const u8, args: anytype) void {
    flush();
    msgTo(2, f, args);
}

/// в stdout с префиксом (журнал сервиса)
pub fn log(comptime f: []const u8, args: anytype) void {
    out("{s}: " ++ f ++ "\n", .{prog} ++ args);
    flush();
}

pub fn exit(code: u8) noreturn {
    flush();
    linux.exit_group(code);
}

pub fn oom() noreturn {
    die("нет памяти", .{});
}

/// Текст ошибки как у strerror() glibc — вывод совпадает с C-версией.
pub fn strerror(e: E) []const u8 {
    return switch (e) {
        .SUCCESS => "Success",
        .PERM => "Operation not permitted",
        .NOENT => "No such file or directory",
        .SRCH => "No such process",
        .INTR => "Interrupted system call",
        .IO => "Input/output error",
        .NXIO => "No such device or address",
        .@"2BIG" => "Argument list too long",
        .NOEXEC => "Exec format error",
        .BADF => "Bad file descriptor",
        .CHILD => "No child processes",
        .AGAIN => "Resource temporarily unavailable",
        .NOMEM => "Cannot allocate memory",
        .ACCES => "Permission denied",
        .FAULT => "Bad address",
        .BUSY => "Device or resource busy",
        .EXIST => "File exists",
        .XDEV => "Invalid cross-device link",
        .NODEV => "No such device",
        .NOTDIR => "Not a directory",
        .ISDIR => "Is a directory",
        .INVAL => "Invalid argument",
        .NFILE => "Too many open files in system",
        .MFILE => "Too many open files",
        .NOTTY => "Inappropriate ioctl for device",
        .TXTBSY => "Text file busy",
        .FBIG => "File too large",
        .NOSPC => "No space left on device",
        .SPIPE => "Illegal seek",
        .ROFS => "Read-only file system",
        .MLINK => "Too many links",
        .PIPE => "Broken pipe",
        .RANGE => "Numerical result out of range",
        .NAMETOOLONG => "File name too long",
        .NOSYS => "Function not implemented",
        .NOTEMPTY => "Directory not empty",
        .LOOP => "Too many levels of symbolic links",
        .NODATA => "No data available",
        .OPNOTSUPP => "Operation not supported",
        .CONNREFUSED => "Connection refused",
        .TIMEDOUT => "Connection timed out",
        .HOSTUNREACH => "No route to host",
        .NETUNREACH => "Network is unreachable",
        .CONNRESET => "Connection reset by peer",
        .DQUOT => "Disk quota exceeded",
        .NOKEY => "Required key not available",
        else => std.fmt.allocPrint(gpa, "Unknown error {d}", .{@intFromEnum(e)}) catch oom(),
    };
}

/// errno → текст: «%s: %s» как в C
pub fn serr() []const u8 {
    return strerror(errno);
}

// ---------------------------------------------------------------- системные вызовы

/// Результат системного вызова: число или ошибка (errno сохраняется в vh.errno).
pub fn sys(rc: usize) Error!usize {
    const e = linux.errno(rc);
    if (e != .SUCCESS) {
        errno = e;
        return error.Sys;
    }
    return rc;
}

/// то же, с повтором при EINTR
pub fn sysRetry(comptime f: anytype, args: anytype) Error!usize {
    while (true) {
        const rc = @call(.auto, f, args);
        const e = linux.errno(rc);
        if (e == .INTR) continue;
        if (e != .SUCCESS) {
            errno = e;
            return error.Sys;
        }
        return rc;
    }
}

/// строка с нулём на конце для системного вызова
pub fn z(s: []const u8) [:0]const u8 {
    return gpa.dupeSentinel(u8, s, 0) catch oom();
}

pub fn fmt(comptime f: []const u8, args: anytype) []u8 {
    return std.fmt.allocPrint(gpa, f, args) catch oom();
}

pub fn dupe(s: []const u8) []u8 {
    return gpa.dupe(u8, s) catch oom();
}

pub fn openFd(path: []const u8, flags: linux.O, perm: mode_t) Error!fd_t {
    var f = flags;
    f.CLOEXEC = true;
    return @intCast(try sysRetry(linux.open, .{ z(path).ptr, f, perm }));
}

pub fn close(fd: fd_t) void {
    _ = linux.close(fd);
}

pub fn readFd(fd: fd_t, buf: []u8) Error!usize {
    return sysRetry(linux.read, .{ fd, buf.ptr, buf.len });
}

pub fn writeAllFd(fd: fd_t, data: []const u8) Error!void {
    var p = data;
    while (p.len > 0) {
        const w = try sysRetry(linux.write, .{ fd, p.ptr, p.len });
        p = p[w..];
    }
}

/// весь файл в память; ошибка — errno
pub fn readFile(path: []const u8) Error![]u8 {
    const fd = try openFd(path, .{ .ACCMODE = .RDONLY }, 0);
    defer close(fd);
    return readAll(fd);
}

pub fn readAll(fd: fd_t) Error![]u8 {
    var b: std.ArrayList(u8) = .empty;
    while (true) {
        b.ensureUnusedCapacity(gpa, 65536) catch oom();
        const r = try readFd(fd, b.unusedCapacitySlice());
        if (r == 0) break;
        b.items.len += r;
    }
    return b.items;
}

/// файл sysfs/proc одной строкой без пробелов по краям; "" при ошибке
pub fn rd(path: []const u8) []const u8 {
    const fd = openFd(path, .{ .ACCMODE = .RDONLY }, 0) catch return "";
    defer close(fd);
    var buf: [4096]u8 = undefined;
    const n = readFd(fd, buf[0 .. buf.len - 1]) catch 0;
    return dupe(strip(buf[0..n]));
}

/// запись строки в файл (sysfs); false при ошибке, errno сохраняется
pub fn writeStr(path: []const u8, s: []const u8) bool {
    const fd = openFd(path, .{ .ACCMODE = .WRONLY }, 0) catch return false;
    defer close(fd);
    const w = sysRetry(linux.write, .{ fd, s.ptr, s.len }) catch return false;
    return w == s.len;
}

/// атомарная замена: path.new → fsync → rename
pub fn writeAtomic(path: []const u8, data: []const u8, mode: mode_t) void {
    const tmp = fmt("{s}.new", .{path});
    const fd = openFd(tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true }, mode) catch
        die("{s}: {s}", .{ tmp, serr() });
    writeAllFd(fd, data) catch die("{s}: {s}", .{ tmp, serr() });
    _ = sys(linux.fchmod(fd, mode)) catch die("{s}: {s}", .{ tmp, serr() });
    _ = sys(linux.fsync(fd)) catch die("{s}: {s}", .{ tmp, serr() });
    _ = sys(linux.close(fd)) catch die("{s}: {s}", .{ tmp, serr() });
    _ = sys(linux.rename(z(tmp).ptr, z(path).ptr)) catch die("{s}: {s}", .{ path, serr() });
}

pub const Stat = linux.Statx;

/// stat/lstat; follow=false — сам симлинк
pub fn stat(path: []const u8, follow: bool) Error!Stat {
    var st: Stat = undefined;
    const flags: u32 = if (follow) 0 else linux.AT.SYMLINK_NOFOLLOW;
    _ = try sys(linux.statx(linux.AT.FDCWD, z(path).ptr, flags, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true, .MTIME = true, .INO = true, .NLINK = true }, &st));
    return st;
}

pub fn fstat(fd: fd_t) Error!Stat {
    var st: Stat = undefined;
    _ = try sys(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true, .MTIME = true, .INO = true, .NLINK = true }, &st));
    return st;
}

pub const S = struct {
    pub const IFMT: u32 = 0o170000;
    pub const IFREG: u32 = 0o100000;
    pub const IFDIR: u32 = 0o040000;
    pub const IFLNK: u32 = 0o120000;
    pub const IFCHR: u32 = 0o020000;
    pub const IFBLK: u32 = 0o060000;
    pub const IFIFO: u32 = 0o010000;
    pub const IFSOCK: u32 = 0o140000;
    pub const ISUID: u32 = 0o4000;
    pub const ISGID: u32 = 0o2000;
    pub fn isReg(m: u32) bool {
        return m & IFMT == IFREG;
    }
    pub fn isDir(m: u32) bool {
        return m & IFMT == IFDIR;
    }
    pub fn isLnk(m: u32) bool {
        return m & IFMT == IFLNK;
    }
};

/// lexists: и битый симлинк
pub fn pathExists(path: []const u8) bool {
    _ = stat(path, false) catch return false;
    return true;
}

/// по симлинку, как os.path.isfile
pub fn isRegular(path: []const u8) bool {
    const st = stat(path, true) catch return false;
    return S.isReg(st.mode);
}

pub fn isDir(path: []const u8) bool {
    const st = stat(path, true) catch return false;
    return S.isDir(st.mode);
}

/// как mkdir -p
pub fn mkdirs(path: []const u8, mode: mode_t) void {
    var i: usize = 1;
    while (i < path.len) : (i += 1) {
        if (path[i] != '/') continue;
        _ = sys(linux.mkdir(z(path[0..i]).ptr, 0o755)) catch if (errno != .EXIST) die("{s}: {s}", .{ path[0..i], serr() });
    }
    _ = sys(linux.mkdir(z(path).ptr, mode)) catch if (errno != .EXIST) die("{s}: {s}", .{ path, serr() });
}

pub fn unlink(path: []const u8) Error!void {
    _ = try sys(linux.unlink(z(path).ptr));
}

pub fn readlink(path: []const u8) Error![]u8 {
    var buf: [4096]u8 = undefined;
    const n = try sys(linux.readlink(z(path).ptr, &buf, buf.len));
    return dupe(buf[0..n]);
}

/// Записи каталога (без . и ..), в порядке getdents.
pub fn listDir(path: []const u8) Error![]const []const u8 {
    const fd = try openFd(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    defer close(fd);
    return listDirFd(fd);
}

/// открыть name относительно каталога dfd (O_CLOEXEC добавляется)
pub fn openAt(dfd: fd_t, name: []const u8, flags: linux.O) Error!fd_t {
    var f = flags;
    f.CLOEXEC = true;
    return @intCast(try sysRetry(linux.openat, .{ dfd, z(name).ptr, f, @as(mode_t, 0) }));
}

/// stat относительно каталога dfd; follow=false — сам симлинк
pub fn statAt(dfd: fd_t, name: []const u8, follow: bool) Error!Stat {
    var st: Stat = undefined;
    const flags: u32 = if (follow) 0 else linux.AT.SYMLINK_NOFOLLOW;
    _ = try sys(linux.statx(dfd, z(name).ptr, flags, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .SIZE = true, .BLOCKS = true, .MTIME = true, .ATIME = true, .INO = true, .NLINK = true }, &st));
    return st;
}

pub fn unlinkAt(dfd: fd_t, name: []const u8, dir: bool) Error!void {
    _ = try sys(linux.unlinkat(dfd, z(name).ptr, if (dir) linux.AT.REMOVEDIR else 0));
}

/// Записи открытого каталога (без . и ..), в порядке getdents.
pub fn listDirFd(fd: fd_t) Error![]const []const u8 {
    _ = try sys(linux.lseek(fd, 0, linux.SEEK.SET));
    var names: std.ArrayList([]const u8) = .empty;
    var buf: [16384]u8 align(8) = undefined;
    while (true) {
        const n = try sys(linux.getdents64(fd, &buf, buf.len));
        if (n == 0) break;
        var off: usize = 0;
        while (off < n) {
            const d: *align(1) linux.dirent64 = @ptrCast(&buf[off]);
            const name = mem.sliceTo(@as([*:0]u8, @ptrCast(&d.name)), 0);
            if (!mem.eql(u8, name, ".") and !mem.eql(u8, name, ".."))
                names.append(gpa, dupe(name)) catch oom();
            off += d.reclen;
        }
    }
    return names.items;
}

/// канонический путь (как realpath): все симлинки раскрыты; ошибка — путь не существует
pub fn realpath(path: []const u8) Error![]u8 {
    const fd = try openFd(path, .{ .ACCMODE = .RDONLY, .PATH = true }, 0);
    defer close(fd);
    return readlink(fmt("/proc/self/fd/{d}", .{fd}));
}

/// строка из stdin (без перевода строки); null — конец ввода
pub fn readLine() ?[]const u8 {
    var line: std.ArrayList(u8) = .empty;
    while (true) {
        var c: [1]u8 = undefined;
        const r = readFd(0, &c) catch return null;
        if (r == 0) return if (line.items.len == 0) null else line.items;
        if (c[0] == '\n') return line.items;
        line.append(gpa, c[0]) catch oom();
    }
}

/// Время UTC «ГГГГ-ММ-ДД ЧЧ:ММ:СС» (без libc нет localtime — часовой пояс не учитывается).
pub fn utcTime(secs: i64) []u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(secs, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return fmt("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

pub fn now() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return ts.sec;
}

// ---------------------------------------------------------------- строки

pub const space = " \t\n\r\x0c\x0b";

pub fn isSpace(c: u8) bool {
    return mem.indexOfScalar(u8, space, c) != null;
}

/// пробелы с краёв
pub fn strip(s: []const u8) []const u8 {
    return mem.trim(u8, s, space);
}

pub fn startsWith(s: []const u8, p: []const u8) bool {
    return mem.startsWith(u8, s, p);
}

pub fn endsWith(s: []const u8, p: []const u8) bool {
    return mem.endsWith(u8, s, p);
}

pub fn eql(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, a, b);
}

/// Список строк (копии в арене).
pub const Strv = struct {
    items: std.ArrayList([]const u8) = .empty,

    pub fn add(self: *Strv, s: []const u8) void {
        self.items.append(gpa, dupe(s)) catch oom();
    }
    pub fn has(self: *const Strv, s: []const u8) bool {
        for (self.items.items) |x| if (eql(x, s)) return true;
        return false;
    }
    pub fn sort(self: *Strv) void {
        mem.sort([]const u8, self.items.items, {}, lessStr);
    }
    pub fn join(self: *const Strv, sep: []const u8) []u8 {
        return mem.join(gpa, sep, self.items.items) catch oom();
    }
    pub fn slice(self: *const Strv) []const []const u8 {
        return self.items.items;
    }
    pub fn len(self: *const Strv) usize {
        return self.items.items.len;
    }
};

/// порядок strcmp (байтовый)
pub fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return mem.order(u8, a, b) == .lt;
}

// ---------------------------------------------------------------- конфиги KEY=VALUE

/// Конфиг KEY=VALUE. inline_comments: «#» до конца строки — комментарий; без него
/// комментарий — только строка, начинающаяся с «#». Кавычки " снимаются.
pub const Kv = struct {
    keys: std.ArrayList([]const u8) = .empty,
    vals: std.ArrayList([]const u8) = .empty,

    pub fn read(self: *Kv, path: []const u8, inline_comments: bool) void {
        const text = readFile(path) catch return;
        var lines = mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            var line = raw;
            if (inline_comments) {
                if (mem.indexOfScalar(u8, line, '#')) |h| line = line[0..h];
            }
            line = strip(line);
            if (line.len == 0 or line[0] == '#') continue;
            const eq = mem.indexOfScalar(u8, line, '=') orelse continue;
            const k = strip(line[0..eq]);
            var v = strip(line[eq + 1 ..]);
            v = mem.trimStart(u8, v, "\"");
            v = mem.trimEnd(u8, v, "\"");
            self.set(k, v);
        }
    }

    pub fn set(self: *Kv, k: []const u8, v: []const u8) void {
        for (self.keys.items, 0..) |key, i| if (eql(key, k)) {
            self.vals.items[i] = dupe(v);
            return;
        };
        self.keys.append(gpa, dupe(k)) catch oom();
        self.vals.append(gpa, dupe(v)) catch oom();
    }

    pub fn get(self: *const Kv, k: []const u8, def: []const u8) []const u8 {
        for (self.keys.items, 0..) |key, i| if (eql(key, k)) return self.vals.items[i];
        return def;
    }

    /// целое как strtol(…, 10) с проверкой хвоста; die при мусоре
    pub fn int(self: *const Kv, k: []const u8, def: []const u8) i64 {
        const s = self.get(k, def);
        return parseLong(s) orelse die("{s}={s}: нужно целое число", .{ k, s });
    }
};

/// strtol(s, 10): ведущие пробелы и знак, хвост — только пробелы
pub fn parseLong(s: []const u8) ?i64 {
    const t = mem.trimStart(u8, s, space);
    var end: usize = 0;
    if (end < t.len and (t[end] == '+' or t[end] == '-')) end += 1;
    const digits_start = end;
    while (end < t.len and std.ascii.isDigit(t[end])) end += 1;
    if (end == digits_start) return null;
    for (t[end..]) |c| if (!isSpace(c)) return null;
    const num = t[0..end];
    return std.fmt.parseInt(i64, if (num[0] == '+') num[1..] else num, 10) catch null;
}

// ---------------------------------------------------------------- запуск программ

/// Найти программу по PATH процесса (как execvp).
fn findExe(name: []const u8) ?[:0]const u8 {
    if (mem.indexOfScalar(u8, name, '/') != null) return z(name);
    const path = getenv("PATH") orelse "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin";
    var it = mem.splitScalar(u8, path, ':');
    while (it.next()) |dir| {
        const full = fmt("{s}/{s}", .{ if (dir.len == 0) "." else dir, name });
        if (linux.errno(linux.access(z(full).ptr, linux.X_OK)) == .SUCCESS) return z(full);
    }
    return null;
}

pub fn getenv(name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (envp[i]) |e| : (i += 1) {
        const s = mem.span(e);
        if (s.len > name.len and s[name.len] == '=' and mem.eql(u8, s[0..name.len], name))
            return s[name.len + 1 ..];
    }
    return null;
}

/// заменить или добавить переменную окружения (для запускаемых программ и поиска по PATH)
pub fn setenv(name: []const u8, value: []const u8) void {
    var list: std.ArrayList(?[*:0]const u8) = .empty;
    var i: usize = 0;
    while (envp[i]) |e| : (i += 1) {
        const s = mem.span(e);
        if (s.len > name.len and s[name.len] == '=' and mem.eql(u8, s[0..name.len], name)) continue;
        list.append(gpa, e) catch oom();
    }
    list.append(gpa, z(fmt("{s}={s}", .{ name, value })).ptr) catch oom();
    envp = (list.toOwnedSliceSentinel(gpa, null) catch oom()).ptr;
}

pub const RunOpts = struct {
    /// передать на stdin
    in: ?[]const u8 = null,
    /// собрать stdout / stderr; null — наследовать
    out: ?*std.ArrayList(u8) = null,
    err: ?*std.ArrayList(u8) = null,
};

/// Запуск программы без шелла (поиск по PATH процесса). Код выхода, 128+сигнал или 127,
/// если программа не запустилась.
pub fn runOpts(argv: []const []const u8, o: RunOpts) u8 {
    var pin = [2]fd_t{ -1, -1 };
    var pout = [2]fd_t{ -1, -1 };
    var perr = [2]fd_t{ -1, -1 };
    const cloexec: linux.O = .{ .CLOEXEC = true };
    if (o.in != null) _ = sys(linux.pipe2(&pin, cloexec)) catch die("pipe: {s}", .{serr()});
    if (o.out != null) _ = sys(linux.pipe2(&pout, cloexec)) catch die("pipe: {s}", .{serr()});
    if (o.err != null) _ = sys(linux.pipe2(&perr, cloexec)) catch die("pipe: {s}", .{serr()});

    // argv и путь готовятся до fork: в дочернем процессе — только системные вызовы
    const cargv = gpa.allocSentinel(?[*:0]const u8, argv.len, null) catch oom();
    for (argv, 0..) |a, i| cargv[i] = z(a).ptr;
    const exe = findExe(argv[0]);
    const failmsg = fmt("{s}: {s}: {s}\n", .{ prog, argv[0], strerror(.NOENT) });

    flush();
    const pid_rc = sys(linux.fork()) catch die("fork: {s}", .{serr()});
    if (pid_rc == 0) {
        resetSignal(linux.SIG.PIPE);
        if (o.in != null and linux.errno(linux.dup2(pin[0], 0)) != .SUCCESS) linux.exit_group(127);
        if (o.out != null and linux.errno(linux.dup2(pout[1], 1)) != .SUCCESS) linux.exit_group(127);
        if (o.err != null and linux.errno(linux.dup2(perr[1], 2)) != .SUCCESS) linux.exit_group(127);
        if (exe) |p| {
            const rc = linux.execve(p.ptr, cargv.ptr, envp);
            const msg = fmtStatic(argv[0], strerror(linux.errno(rc)));
            _ = linux.write(2, msg.ptr, msg.len);
        } else {
            _ = linux.write(2, failmsg.ptr, failmsg.len);
        }
        linux.exit_group(127);
    }
    const pid: linux.pid_t = @intCast(pid_rc);
    if (o.in != null) close(pin[0]);
    if (o.out != null) close(pout[1]);
    if (o.err != null) close(perr[1]);
    const old = ignoreSignal(linux.SIG.PIPE);
    pump(pin[1], o.in orelse "", pout[0], o.out, perr[0], o.err);
    restoreSignal(linux.SIG.PIPE, old);
    var st: u32 = 0;
    while (true) {
        const rc = linux.wait4(pid, @ptrCast(&st), 0, null);
        const e = linux.errno(rc);
        if (e == .SUCCESS) break;
        if (e != .INTR) {
            errno = e;
            die("waitpid: {s}", .{serr()});
        }
    }
    if (linux.W.IFEXITED(st)) return linux.W.EXITSTATUS(st);
    return @truncate(128 + @intFromEnum(linux.W.TERMSIG(st)));
}

// сообщение об ошибке execve: строится в дочернем процессе без выделения памяти
var exec_msg_buf: [512]u8 = undefined;
fn fmtStatic(name: []const u8, why: []const u8) []const u8 {
    return std.fmt.bufPrint(&exec_msg_buf, "{s}: {s}: {s}\n", .{ prog, name, why }) catch "exec failed\n";
}

pub fn run(argv: []const []const u8) u8 {
    return runOpts(argv, .{});
}

/// дочитать/дописать каналы, пока все не закрыты
fn pump(in_fd0: fd_t, in: []const u8, out_fd0: fd_t, ob: ?*std.ArrayList(u8), err_fd0: fd_t, eb: ?*std.ArrayList(u8)) void {
    var in_fd = in_fd0;
    var fds = [2]fd_t{ out_fd0, err_fd0 };
    const bufs = [2]?*std.ArrayList(u8){ ob, eb };
    var in_off: usize = 0;
    if (in_fd >= 0 and in.len == 0) {
        close(in_fd);
        in_fd = -1;
    }
    while (in_fd >= 0 or fds[0] >= 0 or fds[1] >= 0) {
        var p = [3]linux.pollfd{
            .{ .fd = in_fd, .events = linux.POLL.OUT, .revents = 0 },
            .{ .fd = fds[0], .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = fds[1], .events = linux.POLL.IN, .revents = 0 },
        };
        _ = sysRetry(linux.poll, .{ &p, 3, -1 }) catch die("poll: {s}", .{serr()});
        if (in_fd >= 0 and p[0].revents != 0) {
            const rc = linux.write(in_fd, in[in_off..].ptr, in.len - in_off);
            const e = linux.errno(rc);
            if (e == .SUCCESS) in_off += rc else if (e != .INTR and e != .AGAIN) in_off = in.len; // EPIPE: программа не читает stdin
            if (in_off == in.len) {
                close(in_fd);
                in_fd = -1;
            }
        }
        for (0..2) |i| {
            if (fds[i] < 0 or p[i + 1].revents == 0) continue;
            const b = bufs[i].?;
            b.ensureUnusedCapacity(gpa, 65536) catch oom();
            const rc = linux.read(fds[i], b.unusedCapacitySlice().ptr, 65536);
            const e = linux.errno(rc);
            if (e == .SUCCESS and rc > 0) {
                b.items.len += rc;
            } else if (e == .SUCCESS or (e != .INTR and e != .AGAIN)) {
                close(fds[i]);
                fds[i] = -1;
            }
        }
    }
}

fn sigact(sig: linux.SIG, handler: ?linux.Sigaction.handler_fn) linux.Sigaction {
    var sa = std.mem.zeroes(linux.Sigaction);
    sa.handler = .{ .handler = handler };
    var old: linux.Sigaction = undefined;
    _ = linux.sigaction(sig, &sa, &old);
    return old;
}

fn resetSignal(sig: linux.SIG) void {
    _ = sigact(sig, linux.SIG.DFL);
}

fn ignoreSignal(sig: linux.SIG) linux.Sigaction {
    return sigact(sig, linux.SIG.IGN);
}

fn restoreSignal(sig: linux.SIG, old: linux.Sigaction) void {
    _ = linux.sigaction(sig, &old, null);
}

/// закрыть все fd ≥ from (перед exec программы с меньшими правами)
pub fn closeFdsFrom(from: fd_t) void {
    if (linux.errno(linux.close_range(from, std.math.maxInt(fd_t), .{ .UNSHARE = false, .CLOEXEC = false })) == .SUCCESS) return;
    var fd: fd_t = from;
    while (fd < 1024) : (fd += 1) close(fd);
}

/// вопрос [y/N]: true на y, yes, д, да (любой регистр); yes — не спрашивать
pub fn ask(question: []const u8, yes: bool) bool {
    if (yes) return true;
    out("{s} [y/N] ", .{question});
    flush();
    // построчное чтение stdin по байту: остаток ввода остаётся следующему вопросу
    var line: [64]u8 = undefined;
    var n: usize = 0;
    while (n < line.len - 1) {
        var c: [1]u8 = undefined;
        const r = readFd(0, &c) catch return false;
        if (r == 0) {
            if (n == 0) return false;
            break;
        }
        line[n] = c[0];
        n += 1;
        if (c[0] == '\n') break;
    }
    var a = dupe(strip(line[0..n]));
    for (a) |*ch| ch.* = std.ascii.toLower(ch.*);
    // Д (D0 94) → д (D0 B4), А (D0 90) → а (D0 B0)
    var i: usize = 0;
    while (i + 1 < a.len) : (i += 1) {
        if (a[i] == 0xD0 and (a[i + 1] == 0x94 or a[i + 1] == 0x90)) a[i + 1] += 0x20;
    }
    return eql(a, "y") or eql(a, "yes") or eql(a, "д") or eql(a, "да");
}

test "parseLong как strtol" {
    try std.testing.expectEqual(@as(?i64, 42), parseLong(" 42 "));
    try std.testing.expectEqual(@as(?i64, -7), parseLong("-7"));
    try std.testing.expectEqual(@as(?i64, 5), parseLong("+5"));
    try std.testing.expectEqual(@as(?i64, null), parseLong("4x"));
    try std.testing.expectEqual(@as(?i64, null), parseLong(""));
    try std.testing.expectEqual(@as(?i64, null), parseLong("-"));
}

test "strip" {
    try std.testing.expectEqualStrings("a b", strip(" \t a b\n"));
    try std.testing.expectEqualStrings("", strip(" \n "));
}

test "run: вывод, stdin, код выхода, нет программы" {
    var o: std.ArrayList(u8) = .empty;
    var e: std.ArrayList(u8) = .empty;
    try std.testing.expectEqual(@as(u8, 0), runOpts(&.{ "sh", "-c", "cat; echo err >&2" }, .{ .in = "привет", .out = &o, .err = &e }));
    try std.testing.expectEqualStrings("привет", o.items);
    try std.testing.expectEqualStrings("err\n", e.items);
    try std.testing.expectEqual(@as(u8, 3), runOpts(&.{ "sh", "-c", "exit 3" }, .{}));
    try std.testing.expectEqual(@as(u8, 128 + 9), runOpts(&.{ "sh", "-c", "kill -9 $$" }, .{}));
    var e2: std.ArrayList(u8) = .empty;
    try std.testing.expectEqual(@as(u8, 127), runOpts(&.{"нет-такой-программы"}, .{ .err = &e2 }));
    try std.testing.expect(mem.indexOf(u8, e2.items, "No such file or directory") != null);
}

test "файлы: writeAtomic, readFile, stat, listDir, mkdirs, Kv" {
    const dir = "/tmp/vh-zig-test";
    _ = runOpts(&.{ "rm", "-rf", dir }, .{});
    mkdirs(dir ++ "/a/b", 0o700);
    try std.testing.expect(isDir(dir ++ "/a/b"));
    writeAtomic(dir ++ "/c.conf", "# комм\nA = \"1\"\nB=2 # x\n\nC\n", 0o600);
    const st = try stat(dir ++ "/c.conf", false);
    try std.testing.expectEqual(@as(u32, 0o600), st.mode & 0o7777);
    var kv: Kv = .{};
    kv.read(dir ++ "/c.conf", true);
    try std.testing.expectEqualStrings("1", kv.get("A", ""));
    try std.testing.expectEqual(@as(i64, 2), kv.int("B", "0"));
    var kv2: Kv = .{};
    kv2.read(dir ++ "/c.conf", false);
    try std.testing.expectEqualStrings("2 # x", kv2.get("B", ""));
    const names = try listDir(dir);
    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expect(!pathExists(dir ++ "/нет"));
    try std.testing.expectError(error.Sys, readFile(dir ++ "/нет"));
    try std.testing.expectEqual(E.NOENT, errno);
}
