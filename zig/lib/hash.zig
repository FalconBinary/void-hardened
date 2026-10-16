//! void-hardened: SHA-256 и BLAKE2b-512 (std.crypto) — хэши файлов в hex.
const std = @import("std");
const vh = @import("vh");

pub const Sha256 = std.crypto.hash.sha2.Sha256;
/// 512 бит, без ключа — формат Limine
pub const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

pub fn hex(d: []const u8) []u8 {
    return vh.fmt("{x}", .{d});
}

fn fileHex(comptime H: type, path: []const u8) vh.Error![]u8 {
    const fd = try vh.openFd(path, .{ .ACCMODE = .RDONLY }, 0);
    defer vh.close(fd);
    var h = H.init(.{});
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = try vh.readFd(fd, &buf);
        if (n == 0) break;
        h.update(buf[0..n]);
    }
    var d: [H.digest_length]u8 = undefined;
    h.final(&d);
    return hex(&d);
}

/// хэш файла в hex; ошибка чтения — vh.errno
pub fn sha256File(path: []const u8) vh.Error![]u8 {
    return fileHex(Sha256, path);
}

pub fn blake2bFile(path: []const u8) vh.Error![]u8 {
    return fileHex(Blake2b512, path);
}

pub fn sha256Hex(data: []const u8) []u8 {
    var d: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &d, .{});
    return hex(&d);
}

pub fn blake2bHex(data: []const u8) []u8 {
    var d: [Blake2b512.digest_length]u8 = undefined;
    Blake2b512.hash(data, &d, .{});
    return hex(&d);
}

test "известные значения" {
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        sha256Hex("abc"),
    );
    try std.testing.expectEqualStrings(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        blake2bHex("abc"),
    );
}
