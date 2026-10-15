#!/usr/bin/env python3
"""Дифференциальный тест vh-uki-verify: эталон (Python) против C-версии.

  python3 tests/c/uki_diff.py "ЭТАЛОН" ПРОВЕРЯЕМЫЙ

Только в одноразовом контейнере: пишет в /etc, /run/vh-keys. Синтетическая UKI —
PE с секциями .cmdline, .uname, .initrd (ранний cpio + cpio, сжатый zstd).
"""
import os
import shutil
import struct
import subprocess
import sys

W = "/tmp/ukitest"
REF = "/run/vh-keys/ref"


def cpio(entries):
    out = b""
    for ino, (name, mode, data) in enumerate(entries + [("TRAILER!!!", 0, b"")], 1):
        nb = name.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08X" % v for v in
                                   (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0))
        out += hdr + nb
        out += b"\0" * ((4 - len(out) % 4) % 4)
        out += data
        out += b"\0" * ((4 - len(out) % 4) % 4)
    return out


def initrd(files):
    early = cpio([("kernel", 0o40755, b""), ("kernel/x86/microcode/GenuineIntel.bin", 0o100644, b"UCODE" * 100)])
    main = cpio(files)
    z = subprocess.run(["zstd", "-q", "-c"], input=main, capture_output=True, check=True).stdout
    return early + b"\0" * 512 + z


def pe(sections):
    """MZ + PE + таблица секций; данные секций подряд после заголовков."""
    nsec = len(sections)
    pe_off = 0x80
    opt = 0xF0
    hdr_end = pe_off + 24 + opt + 40 * nsec
    data_off = (hdr_end + 0x1FF) & ~0x1FF
    blob = bytearray(data_off)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, pe_off)
    blob[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HH", blob, pe_off + 4, 0x8664, nsec)
    struct.pack_into("<H", blob, pe_off + 20, opt)
    off = data_off
    body = b""
    for i, (name, data) in enumerate(sections):
        raw = data + b"\0" * ((0x200 - len(data) % 0x200) % 0x200)
        struct.pack_into("<8sIIII", blob, pe_off + 24 + opt + 40 * i, name.encode(), len(data), 0x1000 * (i + 1),
                         len(raw), off + len(body))
        body += raw
    return bytes(blob) + body


FILES = [("usr", 0o40755, b""), ("usr/bin", 0o40755, b""), ("usr/bin/sh", 0o100755, b"\x7fELF" + b"x" * 5000),
         ("lib", 0o120777, b"usr/lib"), ("usr/lib/modules/6.18.56_1/kernel/a.ko", 0o100644, b"MOD" * 99),
         ("etc/cmdline.d/vh.conf", 0o100644, b"rd.luks=1\n"), ("dev/console", 0o20600, b"")]


def uki(path, cmdline=b"root=/dev/mapper/cryptroot quiet", uname=b"6.18.56_1", files=FILES):
    with open(path, "wb") as f:
        f.write(pe([(".osrel", b"ID=void\n"), (".cmdline", cmdline + b"\0"), (".uname", uname + b"\0"),
                    (".initrd", initrd(files)), (".linux", b"KERNEL" * 1000)]))


def setup_inputs():
    for d in ("/etc/dracut.conf.d", "/etc/kernel.d/post-install", "/etc/modprobe.d", "/etc/vh",
              "/etc/default", "/usr/local/lib/dracut/modules.d/90x"):
        os.makedirs(d, exist_ok=True)
    files = {"/etc/dracut.conf": "x\n", "/etc/dracut.conf.d/10-vh.conf": "hostonly=yes\n",
             "/etc/default/dracut-uefi-hook": "KERNEL_CMDLINE=x\n", "/etc/vh/boot.conf": "KEEP=2\n",
             "/etc/vh/vh.env": 'VH_KERNEL="linux6.18"\n', "/etc/kernel.d/post-install/20-x": "#!/bin/sh\n",
             "/etc/modprobe.d/vh.conf": "blacklist x\n", "/usr/local/lib/dracut/modules.d/90x/module-setup.sh": "x\n",
             "/etc/modprobe.d/old.conf.vh-orig": "skip\n"}
    for p, t in files.items():
        with open(p, "w") as f:
            f.write(t)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def snapshot():
    return {n: open(f"{REF}/{n}", "rb").read() for n in sorted(os.listdir(REF))} if os.path.isdir(REF) else {}


def main():
    ref, new = sys.argv[1].split(), sys.argv[2]
    shutil.rmtree(W, ignore_errors=True)
    os.makedirs(W)
    setup_inputs()
    uki(f"{W}/a.efi")
    uki(f"{W}/cmd.efi", cmdline=b"root=/dev/mapper/cryptroot quiet init=/bin/evil")
    uki(f"{W}/uname.efi", uname=b"6.17.1_1")
    uki(f"{W}/mod.efi", files=FILES[:-2] + [("usr/bin/evil", 0o100755, b"EVIL")])
    bad = 0
    cases = [("init", ["--init", f"{W}/a.efi"]), ("verify-same", [f"{W}/a.efi", "6.18.56_1"]),
             ("verify-cmdline", [f"{W}/cmd.efi", "6.18.56_1"]), ("verify-uname", [f"{W}/uname.efi", "6.18.56_1"]),
             ("verify-initrd", [f"{W}/mod.efi", "6.18.56_1"]), ("usage", ["x"])]
    for name, args in cases:
        res = {}
        for impl, cmd in (("ref", ref), ("new", [new])):
            shutil.rmtree(REF, ignore_errors=True)
            if name != "init":
                run(ref + ["--init", f"{W}/a.efi"])     # одинаковые эталоны для обеих версий
            rc, out, err = run(cmd + args)
            res[impl] = (rc, out, err.strip(), snapshot())
        if name == "usage":          # справка C намеренно короче — сравнивается код
            res = {k: v[:1] for k, v in res.items()}
        if res["ref"] != res["new"]:
            bad += 1
            print(f"РАЗЛИЧИЕ {name}")
            for i, what in enumerate(("код", "stdout", "stderr", "эталоны")):
                if res["ref"][i] != res["new"][i]:
                    print(f"  {what}:\n    эталон {str(res['ref'][i])[:900]!s}\n    C      {str(res['new'][i])[:900]!s}")
        else:
            print(f"ok {name} (код {res['new'][0]})")
    # только C: скрытый файл в каталоге хуков ядра должен быть замечен
    shutil.rmtree(REF, ignore_errors=True)
    run([new, "--init", f"{W}/a.efi"])
    with open("/etc/kernel.d/post-install/.hidden", "w") as f:
        f.write("evil\n")
    rc, out, _ = run([new, f"{W}/a.efi", "6.18.56_1"])
    os.remove("/etc/kernel.d/post-install/.hidden")
    if rc != 0 and "новый: /etc/kernel.d/post-install/.hidden" in out:
        print("ok C видит скрытый файл в /etc/kernel.d")
    else:
        bad += 1
        print("ОШИБКА: скрытый файл не замечен\n" + out)
    print(f"различий: {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
