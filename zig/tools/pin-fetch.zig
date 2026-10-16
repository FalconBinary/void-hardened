//! pin-fetch — корневой сертификат УЦ сервера TLS для пиннинга (optional/dns-pin, docs/13).
//!
//!   pin-fetch АДРЕС ПОРТ ИМЯ [ALPN]   → PEM корня цепочки на stdout, сводка на stderr
//!
//! Цепочка проверяется системным хранилищем УЦ и именем сервера; в пин берётся её корень
//! (якорь доверия): смена промежуточного сертификата у провайдера пин не ломает, а любой
//! другой из ~150 корневых УЦ перестаёт подходить. Запускается от пользователя сервиса
//! (_unbound, chrony), которому файрвол и так разрешает этот порт.
//!
//! TLS — OpenSSL системы (libssl, libcrypto): проверенная реализация с проверкой цепочки.
const std = @import("std");
const vh = @import("vh");
const hash = @import("hash");
const linux = std.os.linux;
const mem = std.mem;

const CAFILE = "/etc/ssl/certs/ca-certificates.crt";
const TIMEOUT = 15;

// OpenSSL 3: функции, которые в заголовках скрыты за макросами, — через *_ctrl
const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
const SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
const TLSEXT_NAMETYPE_host_name = 0;
const TLS1_2_VERSION = 0x0303;
const SSL_VERIFY_PEER = 0x01;
const X509_V_OK = 0;

const Ptr = ?*anyopaque;
extern fn TLS_client_method() Ptr;
extern fn SSL_CTX_new(method: Ptr) Ptr;
extern fn SSL_CTX_ctrl(ctx: Ptr, cmd: c_int, larg: c_long, parg: Ptr) c_long;
extern fn SSL_CTX_load_verify_locations(ctx: Ptr, file: [*:0]const u8, path: ?[*:0]const u8) c_int;
extern fn SSL_CTX_set_verify(ctx: Ptr, mode: c_int, cb: Ptr) void;
extern fn SSL_CTX_free(ctx: Ptr) void;
extern fn SSL_new(ctx: Ptr) Ptr;
extern fn SSL_ctrl(ssl: Ptr, cmd: c_int, larg: c_long, parg: ?*const anyopaque) c_long;
extern fn SSL_set1_host(ssl: Ptr, name: [*:0]const u8) c_int;
extern fn SSL_set_alpn_protos(ssl: Ptr, protos: [*]const u8, len: c_uint) c_int;
extern fn SSL_set_fd(ssl: Ptr, fd: c_int) c_int;
extern fn SSL_connect(ssl: Ptr) c_int;
extern fn SSL_get_verify_result(ssl: Ptr) c_long;
extern fn SSL_get0_verified_chain(ssl: Ptr) Ptr;
extern fn SSL_shutdown(ssl: Ptr) c_int;
extern fn SSL_free(ssl: Ptr) void;
extern fn OPENSSL_sk_num(sk: Ptr) c_int;
extern fn OPENSSL_sk_value(sk: Ptr, i: c_int) Ptr;
extern fn i2d_X509(x: Ptr, out: *?[*]u8) c_int;
extern fn CRYPTO_free(p: Ptr, file: [*:0]const u8, line: c_int) void;
extern fn ERR_get_error() c_ulong;
extern fn ERR_reason_error_string(e: c_ulong) ?[*:0]const u8;

fn tlsDie(what: []const u8) noreturn {
    const e = ERR_get_error();
    const why: []const u8 = if (e != 0) (if (ERR_reason_error_string(e)) |s| mem.span(s) else "ошибка TLS") else "ошибка TLS";
    vh.die("{s}: {s}", .{ what, why });
}

fn connectTo(addr: []const u8, port: []const u8) i32 {
    var hints = mem.zeroes(std.c.addrinfo);
    hints.socktype = std.c.SOCK.STREAM;
    hints.flags = .{ .NUMERICSERV = true };
    var res: ?*std.c.addrinfo = null;
    const r = std.c.getaddrinfo(vh.z(addr).ptr, vh.z(port).ptr, &hints, &res);
    if (@intFromEnum(r) != 0) vh.die("{s}: {s}", .{ addr, mem.span(std.c.gai_strerror(r)) });
    defer std.c.freeaddrinfo(res.?);
    var a = res;
    while (a) |ai| : (a = ai.next) {
        const rc = linux.socket(@intCast(ai.family), @as(u32, @intCast(ai.socktype)) | linux.SOCK.CLOEXEC, @intCast(ai.protocol));
        if (linux.errno(rc) != .SUCCESS) continue;
        const fd: i32 = @intCast(rc);
        const tv: linux.timeval = .{ .sec = TIMEOUT, .usec = 0 };
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, mem.asBytes(&tv), @sizeOf(linux.timeval));
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDTIMEO, mem.asBytes(&tv), @sizeOf(linux.timeval)); // и для connect
        if (linux.errno(linux.connect(fd, @ptrCast(ai.addr.?), ai.addrlen)) == .SUCCESS) return fd;
        vh.close(fd);
    }
    vh.die("{s}:{s}: нет соединения", .{ addr, port });
}

/// PEM сертификата: base64 DER строками по 64 символа (как PEM_write_X509)
pub fn pem(der: []const u8) []const u8 {
    const enc = std.base64.standard.Encoder;
    const b64 = vh.gpa.alloc(u8, enc.calcSize(der.len)) catch vh.oom();
    _ = enc.encode(b64, der);
    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(vh.gpa, "-----BEGIN CERTIFICATE-----\n") catch vh.oom();
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        out.appendSlice(vh.gpa, b64[i..@min(i + 64, b64.len)]) catch vh.oom();
        out.append(vh.gpa, '\n') catch vh.oom();
    }
    out.appendSlice(vh.gpa, "-----END CERTIFICATE-----\n") catch vh.oom();
    return out.items;
}

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "pin-fetch");
    if (args.len != 3 and args.len != 4) {
        vh.writeAllFd(2, "pin-fetch АДРЕС ПОРТ ИМЯ [ALPN]\n") catch {};
        vh.exit(2);
    }
    const addr = args[0];
    const port = args[1];
    const name = args[2];
    const ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == null or SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, null) == 0 or
        SSL_CTX_load_verify_locations(ctx, CAFILE, null) != 1)
        tlsDie("контекст TLS");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null);
    const ssl = SSL_new(ctx);
    if (ssl == null or SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, name.ptr) == 0 or
        SSL_set1_host(ssl, name.ptr) == 0)
        tlsDie("имя сервера");
    if (args.len == 4) {
        const alpn = args[3];
        if (alpn.len == 0 or alpn.len > 255) vh.die("ALPN: неверная длина", .{});
        var proto: [256]u8 = undefined;
        proto[0] = @intCast(alpn.len);
        @memcpy(proto[1 .. 1 + alpn.len], alpn);
        if (SSL_set_alpn_protos(ssl, &proto, @intCast(alpn.len + 1)) != 0) tlsDie("ALPN");
    }
    const fd = connectTo(addr, port);
    _ = SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1 or SSL_get_verify_result(ssl) != X509_V_OK)
        tlsDie("рукопожатие TLS (цепочка или имя не проверены)");
    const chain = SSL_get0_verified_chain(ssl);
    const n: c_int = if (chain != null) OPENSSL_sk_num(chain) else 0;
    if (n < 1) vh.die("нет проверенной цепочки", .{});
    const root = OPENSSL_sk_value(chain, n - 1);
    var der: ?[*]u8 = null;
    const dl = i2d_X509(root, &der);
    if (dl <= 0 or der == null) tlsDie("DER");
    const d = der.?[0..@intCast(dl)];
    const h = hash.sha256Hex(d);
    var fp: std.ArrayList(u8) = .empty;
    for (0..32) |i| {
        if (i > 0) fp.append(vh.gpa, ':') catch vh.oom();
        fp.append(vh.gpa, std.ascii.toUpper(h[2 * i])) catch vh.oom();
        fp.append(vh.gpa, std.ascii.toUpper(h[2 * i + 1])) catch vh.oom();
    }
    vh.writeAllFd(2, vh.fmt("{s} ({s}:{s}): цепочка {d} серт., корень SHA256 {s}\n", .{ name, addr, port, n, fp.items })) catch {};
    vh.writeAllFd(1, pem(d)) catch vh.die("запись PEM", .{});
    CRYPTO_free(der, "pin-fetch.zig", 0);
    _ = SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    vh.close(fd);
    vh.exit(0);
}
