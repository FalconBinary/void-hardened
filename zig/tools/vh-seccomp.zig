//! vh-seccomp — фильтр seccomp-BPF для песочниц (docs/08, docs/13).
//!
//!   vh-seccomp browser > filter.bpf   — песочница браузера (browser-sandbox)
//!   vh-seccomp viewer  > filter.bpf   — просмотрщики (vh-open, optional/viewers)
//!   vh-seccomp --selftest
const std = @import("std");
const vh = @import("vh");
const seccomp = @import("seccomp");

pub fn main(init: std.process.Init.Minimal) void {
    const args = vh.init(init, "vh-seccomp");
    const kind: []const u8 = if (args.len > 0) args[0] else "";
    if (vh.eql(kind, "--selftest")) vh.exit(if (seccomp.selftest() > 0) 1 else 0);
    var prog: [seccomp.max_ins]seccomp.Ins = undefined;
    const p = seccomp.build(kind, &prog) orelse {
        vh.writeAllFd(2, "vh-seccomp browser|viewer > filter.bpf | --selftest\n") catch {};
        vh.exit(2);
    };
    var out: [seccomp.max_ins * 8]u8 = undefined;
    vh.writeAllFd(1, seccomp.bytes(p, &out)) catch vh.die("запись: ошибка вывода", .{});
}
