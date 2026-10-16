#!/usr/bin/env python3
"""Замер vh-wlfilter: CPU и память прокси на потоке сообщений Wayland.

  python3 tests/zig/bench_wlfilter.py "КОМАНДА ПРОКСИ" [СООБЩЕНИЙ]

Клиент шлёт поток коротких запросов (как wl_surface.attach/damage/commit), композитор
отвечает событиями (как wl_callback.done и wl_pointer.motion). Считается процессорное время
самого прокси (utime+stime из /proc) и его память (VmRSS) в простое и после потока.
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

LISTEN = "/run/vh-sandbox/wayland"


def msg(obj, op, body=b""):
    return struct.pack("<II", obj, ((8 + len(body)) << 16) | op) + body


def cpu(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


def rss(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def main():
    cmd = sys.argv[1].split()
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 200000
    rt = tempfile.mkdtemp()
    comp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    comp.bind(f"{rt}/wayland-0")
    comp.listen(1)
    os.makedirs("/run/vh-sandbox", exist_ok=True)
    if os.path.exists(LISTEN):
        os.unlink(LISTEN)
    p = subprocess.Popen(cmd, env=dict(os.environ, XDG_RUNTIME_DIR=rt), stderr=subprocess.DEVNULL)
    while not os.path.exists(LISTEN):
        time.sleep(0.01)
    time.sleep(0.3)
    idle_rss = rss(p.pid)
    cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.connect(LISTEN)
    srv, _ = comp.accept()
    # кадр: attach + damage_buffer + frame + commit (≈ то, что шлёт браузер на каждый кадр)
    frame = msg(10, 1, struct.pack("<Iii", 20, 0, 0)) + msg(10, 9, struct.pack("<iiii", 0, 0, 800, 600)) \
        + msg(10, 3, struct.pack("<I", 30)) + msg(10, 6)
    per = 4
    reply = msg(30, 0, struct.pack("<I", 1234)) + msg(40, 2, struct.pack("<Iii", 1, 256, 256))
    frames = n // per
    got = {"c": 0, "s": 0}

    def reader(sock, key, want):
        while got[key] < want:
            d = sock.recv(1 << 16)
            if not d:
                break
            got[key] += len(d)

    tr = threading.Thread(target=reader, args=(srv, "s", frames * len(frame)))
    tc = threading.Thread(target=reader, args=(cli, "c", frames * len(reply)))
    tr.start()
    tc.start()
    c0, t0 = cpu(p.pid), time.monotonic()
    batch = 64
    for i in range(0, frames, batch):
        k = min(batch, frames - i)
        cli.sendall(frame * k)
        srv.sendall(reply * k)
    tr.join()
    tc.join()
    t1, c1 = time.monotonic(), cpu(p.pid)
    total = frames * (per + 2)
    print(f"{' '.join(cmd[-1:])}: сообщений {total}, CPU прокси {c1 - c0:.2f} с "
          f"({(c1 - c0) / total * 1e6:.2f} мкс на сообщение), стена {t1 - t0:.2f} с, "
          f"память {idle_rss} КиБ в простое, {rss(p.pid)} КиБ после")
    p.terminate()


if __name__ == "__main__":
    main()
