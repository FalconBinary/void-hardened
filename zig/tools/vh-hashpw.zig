//! vh-hashpw — хэш пароля yescrypt через libcrypt (libxcrypt) — только для автотестов в VM.
//! chpasswd из shadow 4.8.1 не умеет yescrypt.
//!   printf '%s' ПАРОЛЬ | vh-hashpw [cost]  → $y$...
//! На реальной машине пароли задаются интерактивно командой passwd.
const std = @import("std");
const vh = @import("vh");

extern fn crypt_gensalt(prefix: [*:0]const u8, count: c_ulong, rbytes: ?[*]const u8, nrbytes: c_int) ?[*:0]const u8;
extern fn crypt(phrase: [*:0]const u8, setting: [*:0]const u8) ?[*:0]const u8;

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-hashpw");
    const cost: c_ulong = if (args.len > 0) @intCast(@max(vh.parseLong(args[0]) orelse 0, 0)) else 7;
    var pw: [1024]u8 = undefined;
    var n: usize = 0;
    while (n < pw.len - 1) {
        const r = vh.readFd(0, pw[n .. pw.len - 1]) catch break;
        if (r == 0) break;
        n += r;
    }
    pw[n] = 0;
    const salt = crypt_gensalt("$y$", cost, null, 0);
    const h = if (salt) |s| crypt(@ptrCast(&pw), s) else null;
    std.crypto.secureZero(u8, &pw);
    const hs = std.mem.span(h orelse vh.die("libcrypt не вернул yescrypt", .{}));
    if (!vh.startsWith(hs, "$y$")) vh.die("libcrypt не вернул yescrypt", .{});
    vh.out("{s}\n", .{hs});
    vh.exit(0);
}
