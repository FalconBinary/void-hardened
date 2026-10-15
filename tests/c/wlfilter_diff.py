#!/usr/bin/env python3
"""Дифференциальный тест vh-wlfilter: эталон (Python, из истории git) против C-версии.

  python3 tests/c/wlfilter_diff.py ЭТАЛОН ПРОВЕРЯЕМЫЙ [--fuzz N]

Запускается от root в контейнере Void (tests/c/run.sh): прокси слушает
/run/vh-sandbox/wayland. Ненастоящий композитор принимает соединение прокси, тест-клиент
шлёт запросы и получает события; для каждого шага записываются байты и число fd на
другой стороне и факт разрыва. Протоколы обеих версий должны совпасть байт в байт.
"""
import array
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import time

LISTEN = "/run/vh-sandbox/wayland"
QUIET = 0.04


def msg(obj, op, body=b""):
    return struct.pack("<II", obj, ((8 + len(body)) << 16) | op) + body


def s(text):
    raw = text if isinstance(text, bytes) else text.encode()
    raw += b"\0"
    return struct.pack("<I", len(raw)) + raw + b"\0" * ((4 - len(raw) % 4) % 4)


def u(*vals):
    return struct.pack("<" + "I" * len(vals), *vals)


def drain(sock):
    """Всё, что придёт до тишины QUIET: (байты, число fd, закрыто ли)."""
    data, nfds, closed = b"", 0, False
    sock.settimeout(QUIET)
    while True:
        try:
            d, anc, _, _ = sock.recvmsg(65536, socket.CMSG_SPACE(253 * 4))
        except socket.timeout:
            break
        except OSError:
            closed = True
            break
        for level, typ, cdata in anc:
            if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                fds = array.array("i")
                fds.frombytes(cdata[:len(cdata) - len(cdata) % 4])
                nfds += len(fds)
                for fd in fds:
                    os.close(fd)
        if not d:
            closed = True
            break
        data += d
    return data, nfds, closed


def run(proxy, steps):
    """Прогнать сценарий через прокси; вернуть протокол."""
    rt = tempfile.mkdtemp()
    comp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    comp.bind(f"{rt}/wayland-0")
    comp.listen(4)
    os.makedirs("/run/vh-sandbox", exist_ok=True)
    if os.path.exists(LISTEN):
        os.unlink(LISTEN)
    env = dict(os.environ, XDG_RUNTIME_DIR=rt, WAYLAND_DISPLAY="wayland-0")
    p = subprocess.Popen(proxy, env=env, stderr=subprocess.PIPE)
    for _ in range(200):
        if os.path.exists(LISTEN):
            break
        time.sleep(0.01)
    time.sleep(0.05)
    cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.connect(LISTEN)
    srv, _ = comp.accept()
    log = []
    for side, data, nfds in steps:
        src, dst = (cli, srv) if side == "c" else (srv, cli)
        fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(nfds)]
        try:
            if fds:
                src.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
            else:
                src.sendall(data)
        except OSError:
            log.append((side, "send-failed"))
            break
        finally:
            for fd in fds:
                os.close(fd)
        got = drain(dst)
        log.append((side, got))
        if got[2]:
            break
    cli.close()
    srv.close()
    comp.close()
    p.terminate()
    try:
        _, err = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:      # под нагрузкой эталон может не успеть выйти
        p.kill()
        _, err = p.communicate()
    return log, err.decode(errors="replace")


ALLOWED = ["wl_compositor", "wl_shm", "wl_seat", "xdg_wm_base", "wp_viewporter"]
HIDDEN = ["zwlr_screencopy_manager_v1", "zwlr_layer_shell_v1", "zwp_virtual_keyboard_manager_v1"]
TITLES = ["Пример", "a\x1b[31mb", "x‮y", "zw​j", "😀 ok", "tab\tnl\n", "\x00\x01",
          b"\xff\xfe bad \xe2\x82", b"\xed\xa0\x80", "a" * 300, "Ю" * 150, "­ 　 "]


def scripted():
    """Ручные сценарии: всё, что фильтр обязан делать."""
    reg = [("c", msg(1, 1, u(2)), 0)]
    glob = [("s", b"".join(msg(2, 0, u(i + 1) + s(n) + u(1))
                           for i, n in enumerate(ALLOWED + HIDDEN)), 0)]
    base = reg + glob
    return {
        "globals": base,
        "bind-allowed": base + [("c", msg(2, 0, u(1) + s("wl_compositor") + u(4, 3)), 0)],
        "bind-hidden": base + [("c", msg(2, 0, u(6) + s("zwlr_screencopy_manager_v1") + u(1, 3)), 0)],
        "bind-wrong-name": base + [("c", msg(2, 0, u(1) + s("wl_shm") + u(1, 3)), 0)],
        "toplevel": base + [
            ("c", msg(2, 0, u(4) + s("xdg_wm_base") + u(1, 3)), 0),
            ("c", msg(3, 2, u(5, 4)), 0),
            ("c", msg(5, 1, u(6)), 0),
        ] + [("c", msg(6, 2, s(t)), 0) for t in TITLES] + [
            ("c", msg(6, 3, s("org.mozilla.firefox\x07")), 0),
            ("c", msg(6, 11, u(0)), 0),
            ("c", msg(6, 0, u(0)), 2),
        ],
        "remove-global": base + [("s", msg(2, 1, u(1)), 0), ("s", msg(2, 1, u(6)), 0),
                                  ("c", msg(2, 0, u(1) + s("wl_compositor") + u(4, 3)), 0)],
        "delete-id": base + [("s", msg(1, 1, u(2)), 0), ("s", msg(2, 0, u(99) + s("wl_shm") + u(1)), 0)],
        "fds-many": base + [("c", msg(7, 0, u(1)), 28), ("c", msg(7, 0, u(1)) * 4, 100)],
        "fds-no-data": base + [("c", b"\x01\x00", 28)] * 6,
        "bad-size": base + [("c", struct.pack("<II", 1, (6 << 16) | 1), 0)],
        "big-size": base + [("c", struct.pack("<II", 1, (8192 << 16) | 1), 0)],
        "split": base + [("c", msg(2, 0, u(1) + s("wl_compositor") + u(4, 3))[:5], 0),
                         ("c", msg(2, 0, u(1) + s("wl_compositor") + u(4, 3))[5:], 0)],
        "short-body": base + [("c", msg(2, 0, u(1)), 0)],
        "bad-string": base + [("c", msg(2, 0, u(1) + u(500) + b"abcd"), 0)],
        "zero-string": base + [("c", msg(2, 0, u(1) + u(0) + u(1, 3)), 0)],
    }


def fuzz(seed):
    """Случайная последовательность: в основном корректные сообщения с мусором."""
    r = random.Random(seed)
    steps = [("c", msg(1, 1, u(2)), 0),
             ("s", b"".join(msg(2, 0, u(i + 1) + s(n) + u(1)) for i, n in enumerate(ALLOWED + HIDDEN)), 0),
             ("c", msg(2, 0, u(4) + s("xdg_wm_base") + u(1, 3)), 0),
             ("c", msg(3, 2, u(5, 4)), 0), ("c", msg(5, 1, u(6)), 0)]
    for _ in range(r.randint(5, 40)):
        side = r.choice("cccs")
        obj = r.choice([1, 2, 3, 4, 5, 6, 7, r.randint(0, 2 ** 32 - 1)])
        op = r.choice([0, 1, 2, 3, 11, r.randint(0, 0xFFFF)])
        kind = r.random()
        if kind < 0.3:
            body = s(r.choice(TITLES + ALLOWED + HIDDEN))
        elif kind < 0.6:
            body = u(r.randint(0, 12)) + s(r.choice(ALLOWED + HIDDEN)) + u(r.randint(1, 4), r.randint(3, 20))
        elif kind < 0.9:
            body = bytes(r.getrandbits(8) for _ in range(r.choice([0, 4, 8, 12, 64])))
        else:
            body = u(r.randint(0, 2 ** 32 - 1)) + bytes(r.getrandbits(8) for _ in range(r.randint(0, 20)))
        m = msg(obj, op, body)
        if r.random() < 0.03:
            m = m[:r.randint(1, len(m))]
        steps.append((side, m, r.choice([0] * 8 + [1, 3, 30])))
    return steps


def main():
    ref, new = sys.argv[1].split(), sys.argv[2].split()
    n = int(sys.argv[sys.argv.index("--fuzz") + 1]) if "--fuzz" in sys.argv else 0
    cases = scripted()
    for i in range(n):
        cases[f"fuzz-{i}"] = fuzz(i)
    bad = 0
    for name, steps in cases.items():
        a, ea = run(ref, steps)
        b, eb = run(new, steps)
        if a != b:
            bad += 1
            print(f"РАЗЛИЧИЕ {name}")
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    print(f"  шаг {i}: эталон {x!r}\n          C      {y!r}")
                    break
            if len(a) != len(b):
                print(f"  длина протокола: {len(a)} против {len(b)}")
            print("  stderr эталона:", ea.strip()[-300:])
            print("  stderr C:      ", eb.strip()[-300:])
        elif not name.startswith("fuzz"):
            print(f"ok {name}")
    print(f"сценариев: {len(cases)}, различий: {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
