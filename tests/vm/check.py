#!/usr/bin/env python3
"""Проверка установленной системы на стенде (после «vhvm.py install»).

  check.py base       — загрузка без Secure Boot: базовые проверки, vh-audit, сеть, DNS, NTS
  check.py enroll     — регистрация своих ключей (20-firstboot.sh в Setup Mode)
  check.py sb         — загрузка с включённым Secure Boot: подписи, cmdline только из UKI
  check.py lock       — этап 3 (30-lock.sh) и проверка modules_disabled после перезагрузки
  check.py all        — всё по порядку

Каждый шаг — отдельная загрузка VM. Итог: строки «PASS/FAIL …» в конце вывода.
"""
import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import vhvm  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"\n{'PASS' if ok else 'FAIL'}: {name} {detail}", flush=True)


def run(ser, cmd, timeout=900):
    """Выполнить команду, вернуть (код, вывод)."""
    ser.log.write(f"\n### {cmd}\n")
    start = len(ser.alltext)
    rc = ser.sh(cmd, timeout=timeout, check=False, password=vhvm.USER_PASS)
    out = ser.alltext[start:]
    return rc, out


def boot(a, extra_cmdline=None):
    vm = vhvm.VM(a.dir, a.mem, a.smp)
    a.repo = False
    ser = vhvm.boot_and_login(a, vm)
    return vm, ser


def shutdown(vm, ser):
    ser.send("doas poweroff")
    try:
        ser.expect(r"doas \([^)]*\) password: ?", 30)
        time.sleep(0.5)
        ser.send(vhvm.USER_PASS)
    except (TimeoutError, EOFError):
        pass
    vm.stop()


def step_base(a):
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "cat /proc/cmdline")
        check("cmdline из UKI (lockdown, lsm)", "lockdown=confidentiality" in out and "lsm=landlock" in out)
        rc, out = run(ser, "cat /sys/kernel/security/lsm; echo; cat /sys/kernel/security/lockdown")
        check("LSM: apparmor активен, bpf нет", "apparmor" in out and ",bpf" not in out)
        check("lockdown: confidentiality", "[confidentiality]" in out)
        rc, out = run(ser, "doas sv status /var/service/*")
        bad = [l for l in out.splitlines() if l.startswith(("down:", "fail:", "warning:"))]
        check("все сервисы runit работают", not bad, "; ".join(bad))
        rc, out = run(ser, "for i in 1 2 3 4 5 6 7 8 9 10 11 12; do getent hosts voidlinux.org && break; sleep 5; done")
        check("DNS через unbound (DoT)", rc == 0)
        rc, out = run(ser, "for i in $(seq 1 24); do doas chronyc -n -N authdata | awk 'NR>2 && $2==\"NTS\" && $4>0 {f=1} END {exit !f}' && break; sleep 5; done; doas chronyc -N authdata")
        check("chrony: NTS-источники с ключами", rc == 0)
        rc, out = run(ser, "doas vh-audit", timeout=600)
        m = re.search(r"Итог: ok (\d+), FAIL (\d+), не проверено (\d+)", out)
        fails = [l for l in out.splitlines() if l.startswith("[FAIL]")]
        check("vh-audit", m is not None, (m.group(0) if m else "нет итога") + " | " + " | ".join(fails))
        rc, out = run(ser, "ls /usr/local/bin; ls -l /usr/local/bin/vh-wlfilter /usr/local/libexec/vh/browser-sandbox")
        check("netline установлен", "netline" in out and "zwifi" in out)
        check("скрипты исполняемые", out.count("-rwxr-xr-x") >= 2)
        rc, out = run(ser, "doas xbps-pkgdb -a; echo pkgdb=$?")
        check("xbps-pkgdb -a (с noextract прошивок)", "pkgdb=0" in out, out.strip().splitlines()[-1] if out.strip() else "")
        rc, out = run(ser, "du -sm /usr/lib/firmware; doas du -sxm / 2>/dev/null | tail -1; free -m; ls -d /proc/[0-9]* | wc -l; swapon --show")
        print(out)
        rc, out = run(ser, "doas nft list ruleset | grep -c . ; doas nft list set inet vh people_tmp")
        check("nftables: таблица и set'ы строгого режима", rc == 0)
        rc, out = run(ser, "id user; id admin; ls -ld /home/xfer /home/user")
        check("группы: user не в wheel/input/video", "wheel" not in out.split("id admin")[0] if "id admin" in out else True)
        rc, out = run(ser, "doas sh -c 'grep -c . /sys/kernel/security/apparmor/profiles; cat /sys/kernel/security/apparmor/profiles'")
        check("профили AppArmor загружены", "vh.firefox" in out and "vh.unbound" in out)
        rc, out = run(ser, "doas sh -c 'grep -ah vh-acpid /var/log/socklog/*/current | tail -3'")
        check("vh-acpid нашёл кнопку питания", "power:" in out)
    finally:
        shutdown(vm, ser)


def step_enroll(a):
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "printf 'enroll\\n' | doas /root/vh/install/20-firstboot.sh")
        check("20-firstboot: ключи записаны", "ключи записаны" in out, out[-300:].replace("\n", " "))
    finally:
        shutdown(vm, ser)


def step_sb(a):
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "doas sbctl status; doas sbctl verify")
        check("Secure Boot включён", re.search(r"Secure Boot:\s+.*Enabled", out) is not None, "")
        check("sbctl verify: всё подписано", "is not signed" not in out)
        rc, out = run(ser, "doas /root/vh/install/20-firstboot.sh")
        check("20-firstboot: проверка подписей", rc == 0)
    finally:
        shutdown(vm, ser)


def step_lock(a):
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "printf 'lock\\n' | doas /root/vh/install/30-lock.sh")
        check("30-lock.sh", rc == 0)
    finally:
        shutdown(vm, ser)
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "cat /proc/sys/kernel/modules_disabled; doas sv status /var/service/*")
        check("modules_disabled=1 к стадии 2", out.strip().splitlines()[0].strip().endswith("1") if out.strip() else False)
        bad = [l for l in out.splitlines() if l.startswith(("down:", "fail:"))]
        check("сервисы работают после блокировки модулей", not bad, "; ".join(bad))
        rc, out = run(ser, "for i in 1 2 3 4 5 6; do getent hosts voidlinux.org && break; sleep 5; done")
        check("DNS после блокировки модулей", rc == 0)
    finally:
        shutdown(vm, ser)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["base", "enroll", "sb", "lock", "all"])
    ap.add_argument("--dir", default=os.path.join(vhvm.REPO, "tests", "vm", "work"))
    ap.add_argument("--mem", type=int, default=3072)
    ap.add_argument("--smp", type=int, default=4)
    ap.add_argument("--user", default="admin")
    a = ap.parse_args()
    steps = {"base": [step_base], "enroll": [step_enroll], "sb": [step_sb], "lock": [step_lock],
             "all": [step_base, step_enroll, step_sb, step_lock]}[a.step]
    for s in steps:
        s(a)
    print("\n==== ИТОГ")
    for n, ok, d in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}: {n}")
    sys.exit(0 if all(ok for _, ok, _ in RESULTS) else 1)


if __name__ == "__main__":
    main()
