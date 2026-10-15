#!/usr/bin/env python3
"""Проверка установленной системы на стенде (после «vhvm.py install»).

  check.py base       — загрузка без Secure Boot: базовые проверки, vh-audit, сеть, DNS, NTS
  check.py enroll     — регистрация своих ключей (20-firstboot.sh в Setup Mode)
  check.py sb         — загрузка с включённым Secure Boot: подписи, cmdline только из UKI
  check.py lock       — этап 3 (30-lock.sh) и проверка modules_disabled после перезагрузки
  check.py desktop    — mango без экрана, фильтр Wayland, браузер в песочнице под AppArmor
  check.py strictnet  — optional/strict-net: сеть людей, временные разрешения
  check.py deadman    — optional/deadman: дамп RAM после выключения без модуля и с ним
  check.py totp       — optional/tpm2-totp на swtpm: генерация, код до пароля, PCR 14
  check.py all        — всё по порядку

Каждый шаг — отдельная загрузка VM. Итог: строки «PASS/FAIL …» в конце вывода.
"""
import argparse
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import vhvm  # noqa: E402

RESULTS = []
TOTP_PASS = "vh-test-totp-recovery"


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"\n{'PASS' if ok else 'FAIL'}: {name} {detail}", flush=True)


def run(ser, cmd, timeout=900):
    """Выполнить команду в root-шелле (doas -s), вернуть (код, вывод). «doas » в командах
    убирается: шелл уже root, а повторные запросы пароля по последовательной консоли
    теряют символы."""
    cmd = re.sub(r"\bdoas\s+", "", cmd)
    ser.log.write(f"\n### {cmd}\n")
    start = len(ser.alltext)
    rc = ser.sh(cmd, timeout=timeout, check=False)
    out = ser.alltext[start:]
    return rc, out


def pf(text):
    """printf '…' только из ASCII: не-ASCII байты — восьмеричными escape. По
    последовательной консоли в шелле без локали readline принимает байты UTF-8
    за Meta-клавиши и «съедает» строку."""
    out = "".join(c if c.isascii() and c.isprintable() and c not in "'\\%" else
                  "".join(f"\\{b:03o}" for b in c.encode()) for c in text)
    return f"printf '{out}'"


def as_user(user, cmd):
    """Команда от имени пользователя (из root-шелла): его UID, GID и группы."""
    return f"setpriv --reuid={user} --regid={user} --init-groups sh -c {shq(cmd)}"


def shq(s):
    return "'" + s.replace("'", "'\\''") + "'"


def root_shell(ser):
    ser.send("doas -s")
    ser.expect(r"doas \([^)]*\) password: ?", 60)
    time.sleep(1)
    ser.send(vhvm.USER_PASS)
    time.sleep(2)
    # без истории: набранные команды не должны оседать в ~/.bash_history (тест deadman ищет
    # маркеры в RAM — копии из файла истории дали бы ложный результат)
    ser.send("unset HISTFILE; export PS1='vh# ' TERM=dumb; stty -echo cols 250; "
             "rm -f /root/.bash_history /home/*/.bash_history")
    ser.expect(r"vh# ", 60)


def boot(a, extra=None):
    vm = vhvm.VM(a.dir, a.mem, a.smp)
    extra = list(extra or [])
    if getattr(a, "repo", False):
        # свежая копия репозитория — «сырым» tar на втором NVMe: после 30-lock.sh модуль
        # isofs не загрузить (modules_disabled), а драйвер NVMe встроен в ядро
        if not os.path.isfile(os.path.join(vhvm.REPO, "build", "vh-seccomp")):
            sys.exit("нет build/ — соберите инструменты на C: sh tests/c/build.sh")
        tar = os.path.join(vm.d, "repo.tar")
        flags = ["--no-xattrs"] + (["--no-fflags", "--no-mac-metadata"] if sys.platform == "darwin" else [])
        subprocess.run(["tar", *flags, "-cf", tar, "--exclude", ".git", "--exclude", "__pycache__",
                        "-C", os.path.dirname(vhvm.REPO), os.path.basename(vhvm.REPO)], check=True,
                       env=dict(os.environ, COPYFILE_DISABLE="1"))
        extra += ["-drive", f"file={tar},if=none,id=repo,format=raw,readonly=on",
                  "-device", "nvme,serial=VHREPO,drive=repo"]
    ser = vm.start(extra)
    ser.expect(r"[Pp]assword|[Pp]assphrase", 1800)
    time.sleep(2)
    ser.send(vhvm.LUKS_PASS)
    # initramfs с optional/tpm2-totp может спросить пароль восстановления (генерация по флагу)
    while True:
        m = ser.expect(r"login: ?$|Пароль восстановления[^:]*: |Ещё раз: |Нажмите Enter|Введите RESEAL: ", 1800)
        t = m.group(0)
        if t.startswith("login"):
            break
        time.sleep(1)
        ser.send("" if t.startswith("Нажмите") else ("RESEAL" if "RESEAL" in t else TOTP_PASS))
    ser.buf = "login: "
    vhvm.login(ser, "admin", vhvm.USER_PASS)
    root_shell(ser)
    if getattr(a, "repo", False):
        run(ser, "rm -rf /tmp/vhn && mkdir /tmp/vhn && "
                 "tar -xf $(readlink -f /dev/disk/by-id/nvme-*VHREPO* | head -1) -C /tmp/vhn && "
                 "cp -a /tmp/vhn/void-hardened/install /tmp/vhn/void-hardened/optional "
                 "/tmp/vhn/void-hardened/rootfs /tmp/vhn/void-hardened/tools /tmp/vhn/void-hardened/src /root/vh/ && "
                 "cd /tmp/vhn/void-hardened/rootfs/usr/local && find . -type f ! -name '*.in' | "
                 "while read f; do install -m $(stat -c %a \"$f\") \"$f\" \"/usr/local/$f\"; done; cd / && "
                 "bash /root/vh/install/build-tools.sh --prebuilt /tmp/vhn/void-hardened/build / >/dev/null && "
                 # система без python3 (docs/17): ignorepkg и удаление, если стоял с прошлой установки
                 "install -m 0644 /tmp/vhn/void-hardened/rootfs/etc/xbps.d/20-vh-ignorepkg.conf /etc/xbps.d/ && "
                 "{ xbps-remove -Fy python3 >/dev/null 2>&1; true; }")
    return vm, ser


def shutdown(vm, ser):
    ser.send("poweroff")
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
        rc, out = run(ser, "ok=1; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do getent hosts voidlinux.org && { ok=0; break; }; sleep 5; done; test $ok = 0")
        check("DNS через unbound (DoT)", rc == 0)
        rc, out = run(ser, "ok=1; for i in $(seq 1 24); do doas chronyc -n -N authdata | awk 'NR>2 && $2==\"NTS\" && $4>0 {f=1} END {exit !f}' && { ok=0; break; }; sleep 5; done; doas chronyc -N authdata; test $ok = 0")
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
        rc, out = run(ser, "id -nG user")
        check("группы: user не в wheel/input/video", not re.search(r"\b(wheel|input|video)\b", out.split("\n", 1)[-1]))
        rc, out = run(ser, "doas sh -c 'grep -c . /sys/kernel/security/apparmor/profiles; cat /sys/kernel/security/apparmor/profiles'")
        check("профили AppArmor загружены", "vh.firefox" in out and "vh.unbound" in out)
        rc, out = run(ser, "install -m 0755 /root/vh/tools/vh-bench /tmp/vh-bench && "
                           + as_user("admin", "cd /tmp && sh /tmp/vh-bench"), timeout=900)
        check("tools/vh-bench работает (dash)", "Отчёт:" in out and "zstd" in out, out[-500:].replace("\n", " | "))
        rc, out = run(ser, "doas sh -c 'grep -ah vh-acpid /var/log/socklog/*/current | tail -3'")
        check("vh-acpid нашёл кнопку питания", "power:" in out)
    finally:
        shutdown(vm, ser)


def step_ctools(a):
    """Инструменты на C в настоящей системе: ELF без python3, демоны, пересборка UKI
    через vh-limine-update и загрузка с новой UKI (docs/17)."""
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "command -v python3 perl || echo NO_INTERPRETERS; "
                           "for f in /usr/local/bin/vh-wlfilter /usr/local/sbin/vh-acpid /usr/local/sbin/vh-limine-update "
                           "/usr/local/sbin/vh-pkg /usr/local/libexec/vh/vh-seccomp; do "
                           "printf '%s ' $f; head -c 4 $f | od -An -c | tr -d ' \\n'; echo; done")
        check("нет python3 и perl", "NO_INTERPRETERS" in out, out[-200:])
        check("инструменты — ELF", out.count("177ELF") == 5, out[-400:].replace("\n", " | "))
        rc, out = run(ser, "/usr/local/libexec/vh/vh-seccomp --selftest")
        check("vh-seccomp --selftest (C)", rc == 0 and "selftest: OK" in out)
        rc, out = run(ser, "sv restart vh-acpid; sleep 3; sv status vh-acpid; "
                           "grep -ah vh-acpid /var/log/socklog/*/current | tail -6; grep VmRSS /proc/$(pgrep -x vh-acpid)/status")
        check("vh-acpid (C) работает и нашёл кнопку питания", "run: vh-acpid" in out and "power:" in out,
              out[-300:].replace("\n", " | "))
        rc, out = run(ser, "xbps-reconfigure -f $(. /etc/vh/vh.env; echo $VH_KERNEL) 2>&1 | tail -8", timeout=1800)
        check("xbps-reconfigure ядра → vh-limine-update (C)", "вписан в Limine" in out, out[-500:].replace("\n", " | "))
        rc, out = run(ser, "mount -o ro /boot/efi && sbctl verify; r=$?; grep -c '#' /boot/efi/EFI/BOOT/limine.conf; "
                           "umount /boot/efi; test $r = 0")
        check("после пересборки всё подписано", rc == 0 and "not signed" not in out, out[-300:].replace("\n", " | "))
        rc, out = run(ser, "doas vh-audit", timeout=600)
        m = re.search(r"Итог: ok (\d+), FAIL (\d+), не проверено (\d+)", out)
        fails = [l for l in out.splitlines() if l.startswith("[FAIL]")]
        check("vh-audit без FAIL (в том числе «нет интерпретаторов»)", m is not None and m.group(2) == "0",
              (m.group(0) if m else "нет итога") + " | " + " | ".join(fails))
    finally:
        shutdown(vm, ser)
    vm, ser = boot(a)                     # загрузка с UKI и Limine, записанными C-версией
    try:
        rc, out = run(ser, "cat /proc/cmdline; sv status vh-acpid")
        check("загрузка после пересборки UKI", "lockdown=confidentiality" in out and "run: vh-acpid" in out)
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
        rc, out = run(ser, "doas sbctl status")
        check("Secure Boot включён", re.search(r"Secure Boot:\s+.*Enabled", out) is not None, "")
        rc, out = run(ser, "doas mount -o ro /boot/efi && doas sbctl verify; r=$?; doas umount /boot/efi; test $r = 0")
        check("sbctl verify: всё подписано", rc == 0 and "not signed" not in out)
        rc, out = run(ser, "cat /proc/cmdline")
        check("cmdline под Secure Boot — только из UKI", "lockdown=confidentiality" in out)
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
        rc, out = run(ser, "ok=1; for i in 1 2 3 4 5 6; do getent hosts voidlinux.org && { ok=0; break; }; sleep 5; done; test $ok = 0")
        check("DNS после блокировки модулей", rc == 0)
    finally:
        shutdown(vm, ser)


def step_desktop(a):
    """mango без экрана (headless backend) → vh-wlfilter → vh-browse → doas → bwrap → Firefox."""
    vm, ser = boot(a)
    U = "setpriv --reuid=user --regid=user --init-groups env -i HOME=/home/user " \
        "XDG_RUNTIME_DIR=/run/user/$(id -u user) PATH=/usr/local/bin:/usr/bin LANG=C.UTF-8"
    try:
        # тестовый стенд: доступ к card0 вместо seatd (scenefx нужен EGL; в VM — kms_swrast)
        run(ser, "install -d -m 0700 -o user -g user /run/user/$(id -u user); setfacl -m u:user:rw /dev/dri/card0; "
                 "chmod 2750 /run/vh-sandbox; ls -ld /run/vh-sandbox")   # как 11-vh-runtime.sh: стенд мог быть старше
        rc, out = run(ser, f"{U} WLR_BACKENDS=headless WLR_HEADLESS_OUTPUTS=1 "
                           "sh -c 'mango >/tmp/vh-mango.log 2>&1 &'; sleep 25; doas ls -l /run/vh-sandbox; "
                           "pgrep -u user -l . | sort -k2 | uniq -f1")
        check("mango (headless) запустился, vh-wlfilter создал сокет", "wayland" in out and "mango" in out)
        check("сокеты песочницы: группа browser, 0660", re.search(r"srw-rw---- 1 user browser .* wayland", out) is not None)
        check("netline запущен", "netline" in out)
        rc, out = run(ser, f"{U} WAYLAND_DISPLAY=wayland-0 sh -c 'vh-browse untrusted >/tmp/vh-ff.log 2>&1 &'; "
                           "sleep 90; pgrep -u browser -l firefox | head; "
                           "for p in $(pgrep -u browser firefox | head -3); do doas cat /proc/$p/attr/current; echo; "
                           "doas grep -E 'Seccomp:|NoNewPrivs|CapEff' /proc/$p/status; done", timeout=600)
        check("Firefox работает от пользователя browser", "firefox" in out)
        check("Firefox под профилем vh.firefox (enforce)", "vh.firefox (enforce)" in out)
        check("Firefox: no_new_privs, без capability", "NoNewPrivs:\t1" in out and "CapEff:\t0000000000000000" in out)
        rc, out = run(ser, "doas sh -c 'cat /tmp/vh-ff.log; grep -a vh-wlfilter /tmp/vh-mango.log | tail -5'")
        check("vh-wlfilter без ошибок протокола", "клиент отключён" not in out, out[-400:].replace("\n", " | "))
        rc, out = run(ser, "doas sh -c 'grep -ah DENIED /var/log/socklog/kernel/current | grep -v chronyd | tail -15'")
        print(out)
        rc, out = run(ser, "p=$(pgrep -u browser firefox | head -1); ls /proc/$p/root/ /proc/$p/root/home/browser; "
                           "echo interrupts=$(nsenter -t $p -m cat /proc/interrupts | wc -c); "
                           "grep -E ' /tmp | /dev/shm ' /proc/$p/mountinfo; grep Seccomp: /proc/$p/status")
        check("песочница: /proc/interrupts пуст", "interrupts=0" in out)
        check("песочница: /tmp и /dev/shm с noexec", len(re.findall(r" /(tmp|dev/shm) .*noexec", out)) >= 2)
        check("песочница: seccomp-фильтр bwrap действует", "Seccomp:\t2" in out)
        run(ser, "doas pkill -u browser; doas pkill -u user; true")
    finally:
        shutdown(vm, ser)


def step_strictnet(a):
    """optional/strict-net: у людей нет сети и DNS, временные разрешения по таймауту."""
    vm, ser = boot(a)
    try:
        rc, out = run(ser, "doas /root/vh/optional/strict-net/enable")
        check("strict-net: включён", rc == 0, out[-200:].replace("\n", " "))
        rc, _ = run(ser, as_user("admin", "getent hosts voidlinux.org"))
        check("strict-net: у админа нет DNS", rc != 0)
        rc, _ = run(ser, "getent hosts voidlinux.org")
        check("strict-net: у root нет DNS без vh-net", rc != 0)
        rc, _ = run(ser, as_user("browser", "getent hosts voidlinux.org"))
        check("strict-net: браузеру DNS можно", rc == 0)
        rc, _ = run(ser, "vh-net allow admin 2 && " + as_user("admin", "getent hosts voidlinux.org"))
        check("strict-net: vh-net allow даёт сеть на время", rc == 0)
        rc, _ = run(ser, "vh-net revoke admin; " + as_user("admin", "getent hosts voidlinux.org"))
        check("strict-net: revoke отзывает", rc != 0)
        rc, out = run(ser, "doas vh-net xbps 5 && doas xbps-install -Sn 2>&1 | tail -2", timeout=300)
        check("strict-net: vh-net xbps открывает зеркала root", rc == 0)
        rc, out = run(ser, "doas vh-net status")
        print(out)
        rc, _ = run(ser, "/root/vh/optional/strict-net/disable && " + as_user("admin", "getent hosts voidlinux.org"))
        check("strict-net: disable возвращает базовый слой", rc == 0)
    finally:
        shutdown(vm, ser)


def find_in_dump(path, needles):
    """Поиск байтовых строк в дампе памяти VM (mmap, без загрузки в RAM)."""
    import mmap
    found = {}
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        for name, n in needles.items():
            found[name] = m.find(n) >= 0
    return found


# Искомые строки тоже собираются из частей: с --repo этот файл распаковывается
# в VM, и целая строка в исходнике нашлась бы в дампе как ложный маркер.
MARK_READ, MARK_PROC, MARK_DIRTY = (("VH" + "MARK" + s).encode() for s in ("_READ_7f3a", "_PROC_91c2", "_DIRTY_c40e"))


def dump_after_poweroff(a, tag, prepare_cmds):
    """Загрузить, выполнить команды, выключить; VM вместо перезагрузки/выключения
    встаёт на паузу — снять дамп RAM и искать ключ тома и маркеры."""
    vm, ser = boot(a, ["-action", "reboot=shutdown", "-action", "shutdown=pause"])
    try:
        rc, out = run(ser, "printf '%s' 'vh-test-luks' | doas cryptsetup luksDump --dump-volume-key --batch-mode "
                           "--key-file - /dev/nvme0n1p2 | sed -n 's/^MK dump:\\s*//p;/^\\s\\+[0-9a-f][0-9a-f] /p'")
        hexkey = "".join(re.findall(r"\b[0-9a-f]{2}\b", out.split("### ")[-1]))
        key = bytes.fromhex(hexkey[:128]) if len(hexkey) >= 128 else b""
        for c in prepare_cmds:
            run(ser, as_user("admin", c))
        ser.send("poweroff")
        # ждём паузы VM (выключение или перезагрузка → pause), затем дамп
        dump = os.path.join(vm.d, f"mem-{tag}.elf")
        if os.path.exists(dump):
            os.remove(dump)
        time.sleep(60)
        vm.monitor(f"dump-guest-memory -d {dump}")
        last = -1
        for _ in range(300):
            time.sleep(2)
            sz = os.path.getsize(dump) if os.path.exists(dump) else 0
            if sz > 0 and sz == last:
                break
            last = sz
        import mmap
        with open(dump, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            for needle in (MARK_READ, MARK_PROC, MARK_DIRTY):
                pos, n = m.find(needle), 0
                while pos >= 0 and n < 3:
                    ctx = m[max(0, pos - 120):pos + 40]
                    print(f"--- {needle.decode()} @{pos}:", repr(bytes(c if 32 <= c < 127 else 46 for c in ctx)))
                    pos, n = m.find(needle, pos + len(needle)), n + 1
        res = find_in_dump(dump, {
            "ключ тома (первые 32 байта)": key[:32] if key else b"\x00NOKEY\x00",
            "маркер прочитанного файла": MARK_READ,
            "маркер памяти процесса": MARK_PROC,
            "маркер записанного файла": MARK_DIRTY,
        })
        os.remove(dump)
        return bool(key), res
    finally:
        vm.monitor("quit")
        vm.stop()


# Маркер собирается внутри VM из частей: полная строка никогда не набирается по
# последовательной консоли (её эхо осталось бы в буфере UART, который ядро не освобождает,
# и тест находил бы маркер там, а не в данных)
MARKERS = [
    "a=VHMARK; printf \"${a}_READ_7f3a%.0s\" $(seq 1 2000) > /home/admin/read.txt; sync; cat /home/admin/read.txt >/dev/null",
    # маркер в куче процесса: строка живёт в памяти bash, пока он ждёт sleep
    "( a=VHMARK; m=$(printf \"${a}_PROC_91c2%.0s\" $(seq 1 4000)); sleep 9999; echo ${#m} ) &",
    "a=VHMARK; printf \"${a}_DIRTY_c40e%.0s\" $(seq 1 2000) > /home/admin/dirty.txt",
]


def step_deadman(a):
    """optional/deadman: дамп RAM после штатного выключения — без модуля и с ним."""
    ok_key, base = dump_after_poweroff(a, "base", MARKERS)
    check("стенд: ключ тома получен для поиска", ok_key)
    print("без deadman:", base)
    check("без deadman ключ ЕСТЬ в RAM после выключения (метод поиска работает)", base["ключ тома (первые 32 байта)"])
    vm, ser = boot(a)
    try:
        rc, out = run(ser, pf("нет\nn\n") + " | /root/vh/optional/deadman/enable", timeout=1800)
        check("deadman: включён", rc == 0, out[-300:].replace("\n", " "))
    finally:
        shutdown(vm, ser)
    ok_key, res = dump_after_poweroff(a, "deadman", MARKERS)
    print("с deadman:", res)
    for name, present in res.items():
        check(f"deadman: после выключения в RAM нет: {name}", not present)


def step_totp(a):
    """optional/tpm2-totp на swtpm: генерация в initramfs, код до пароля LUKS, PCR 14."""
    vm, ser = boot(a)
    try:
        rc, out = run(ser, pf("записал\n") + " | /root/vh/optional/tpm2-totp/enable", timeout=2400)
        check("tpm2-totp: включён (lockout, модуль dracut, UKI)", rc == 0, out[-300:].replace("\n", " "))
    finally:
        shutdown(vm, ser)
    # загрузка 1: после пароля LUKS initramfs генерирует секрет
    vm = vhvm.VM(a.dir, a.mem, a.smp)
    ser = vm.start([])
    try:
        ser.expect(r"[Pp]assphrase", 1800)
        time.sleep(2)
        ser.send(vhvm.LUKS_PASS)
        ser.expect(r"Пароль восстановления: ", 600)
        time.sleep(1)
        ser.send(TOTP_PASS)
        ser.expect(r"Ещё раз: ", 60)
        time.sleep(1)
        ser.send(TOTP_PASS)
        m = ser.expect(r"Нажмите Enter[^\n]*", 600)
        check("tpm2-totp: секрет сгенерирован в initramfs (QR показан)", "otpauth://" in ser.alltext or "█" in ser.alltext)
        ser.send("")
        vhvm.login(ser, "admin", vhvm.USER_PASS)
        root_shell(ser)
        rc, out = run(ser, "tpm2_pcrread sha256:14")
        check("tpm2-totp: PCR 14 расширен после показа", "0x0000000000000000000000000000000000000000000000000000000000000000" not in out)
        rc, out = run(ser, "tpm2-totp -p 0,2,4,7,14 calculate")
        check("tpm2-totp: работающая система код не вычисляет", rc != 0)
        rc, out = run(ser, "test ! -e /var/lib/vh/totp-generate")
        check("tpm2-totp: флаг генерации снят", rc == 0)
    finally:
        shutdown(vm, ser)
    # загрузка 2: код показывается до запроса пароля
    vm = vhvm.VM(a.dir, a.mem, a.smp)
    ser = vm.start([])
    try:
        ser.expect(r"сверьте код TOTP", 1800)
        m = ser.expect(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: (\d{6})", 300)
        check("tpm2-totp: код TOTP показан до пароля LUKS", True, m.group(1))
        ser.expect(r"[Pp]assphrase", 600)
        time.sleep(2)
        ser.send(vhvm.LUKS_PASS)
        m = ser.expect(r"login: ?$|Введите RESEAL: ", 900)
        check("tpm2-totp: после генерации перезапечатывание не требуется", m.group(0).startswith("login"))
        if not m.group(0).startswith("login"):
            ser.send("RESEAL")
            ser.expect(r"Пароль восстановления[^:]*: ", 60)
            time.sleep(1)
            ser.send(TOTP_PASS)
        else:
            ser.buf = "login: "
        vhvm.login(ser, "admin", vhvm.USER_PASS)
        root_shell(ser)
    finally:
        shutdown(vm, ser)


def step_modules(a):
    """Быстрые проверки модулей: dns-pin, viewers, home-lockdown, session-apparmor."""
    vm, ser = boot(a)
    try:
        # имена DoT-серверов в unbound.conf — как после установки (на случай прошлых прогонов)
        run(ser, "sed -i -e 's/^\\(\\s*forward-addr: 9.9.9.9@853#\\).*/\\1dns.quad9.net/' "
                 "-e 's/^\\(\\s*forward-addr: 149.112.112.112@853#\\).*/\\1dns.quad9.net/' "
                 "-e 's/^\\(\\s*forward-addr: 194.242.2.2@853#\\).*/\\1dns.mullvad.net/' /etc/unbound/unbound.conf; "
                 "sv restart unbound; sleep 3; grep forward-addr /etc/unbound/unbound.conf")
        rc, out = run(ser, "printf 'pin\\n' | /root/vh/optional/dns-pin/enable", timeout=600)
        check("dns-pin: пин записан, DNS работает", rc == 0 and "работает" in out, out[-300:].replace("\n", " "))
        rc, out = run(ser, "grep -c BEGIN /etc/unbound/ca-pin.pem /etc/chrony/nts-pin.pem")
        print(out)
        rc, out = run(ser, "cp -a /etc/unbound/unbound.conf /root/unbound.conf.test; "
                           "sed -i 's/@853#[a-z.]*/@853#example.com/' /etc/unbound/unbound.conf; "
                           "sv restart unbound; sleep 3; getent hosts kernel.org")
        check("dns-pin: чужое имя в forward-addr ломает резолв (отказ закрытый)", rc != 0)
        run(ser, "cp -a /root/unbound.conf.test /etc/unbound/unbound.conf; /root/vh/optional/dns-pin/disable; "
                 "sleep 3; getent hosts voidlinux.org")
        rc, out = run(ser, "/root/vh/optional/viewers/enable", timeout=1200)
        check("viewers: включён", rc == 0, out[-200:].replace("\n", " "))
        rc, out = run(ser, as_user("user", "printf 'VH-OPEN-OK\\n' > /home/xfer/t.txt; vh-open /home/xfer/t.txt < /dev/null | cat"))
        check("viewers: vh-open показывает текст в песочнице (bwrap + seccomp + fd)", "VH-OPEN-OK" in out, out[-300:].replace("\n", " "))
        rc, out = run(ser, as_user("user", "ln -sf /etc/passwd /home/xfer/evil.txt; vh-open /home/xfer/evil.txt < /dev/null | cat"))
        check("viewers: симлинк отвергнут", "не обычный файл" in out and "root:x:" not in out)
        rc, out = run(ser, "printf 'lock\\n' | /root/vh/optional/home-lockdown/enable")
        check("home-lockdown: включён", rc == 0, out[-200:].replace("\n", " "))
        rc, out = run(ser, as_user("user", "touch /home/user/.bash_login"))
        check("home-lockdown: ~/.bash_login создать нельзя", rc != 0)
        rc, out = run(ser, as_user("user", "touch /home/user/Documents/x && echo ok"))
        check("home-lockdown: ~/Documents записываем", rc == 0)
        run(ser, "/root/vh/optional/home-lockdown/disable")
        rc, out = run(ser, "sed 's/@VH_AA_MODE@/, complain/' /root/vh/optional/session-apparmor/vh.local.session "
                           "> /tmp/vh.session.aa && apparmor_parser -Q -K /tmp/vh.session.aa")
        check("session-apparmor: профиль компилируется", rc == 0, out[-300:].replace("\n", " "))
    finally:
        shutdown(vm, ser)


def step_deadmandump(a):
    """Только дамп RAM после выключения с уже включённым optional/deadman."""
    ok_key, res = dump_after_poweroff(a, "deadman", MARKERS)
    check("стенд: ключ тома получен для поиска", ok_key)
    print("с deadman:", res)
    for name, present in res.items():
        check(f"deadman: после выключения в RAM нет: {name}", not present)


def step_pkg(a):
    """vh-pkg: предупреждение о нежелательном пакете, обезвреживание SUID и udev."""
    vm, ser = boot(a)
    try:
        ser.buf = ""
        ser.send("vh-pkg add fuse3; echo __PKG__rc=$?")
        ser.expect(r"Ставить всё равно\? \[y/N\] ", 600)
        check("vh-pkg: fuse3 помечен как нежелательный", "!! fuse3" in ser.alltext)
        time.sleep(1)
        ser.send("y")
        m = ser.expect(r"__PKG__rc=(\d+)", 900)
        check("vh-pkg add: установка прошла", m.group(1) == "0", ser.alltext[-600:].replace("\n", " | "))
        rc, out = run(ser, "ls -l /usr/bin/fusermount3; ls /etc/udev/rules.d/; cat /etc/vh/suid-strip.list")
        check("vh-pkg: SUID у fusermount3 снят", "-rwsr" not in out and "fusermount3" in out)
        rc, out = run(ser, "chmod u+s /usr/bin/fusermount3 && vh-suid-strip --quiet; ls -l /usr/bin/fusermount3")
        check("vh-suid-strip: снимает вернувшийся SUID по списку vh-pkg", "-rwsr" not in out)
        rc, out = run(ser, "vh-pkg rm fuse3; xbps-query fuse3; echo q=$?")
        check("vh-pkg rm: пакет удалён", "q=2" in out or "q=1" in out)
    finally:
        shutdown(vm, ser)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["base", "ctools", "enroll", "sb", "lock", "desktop", "strictnet", "deadman", "deadmandump", "totp", "modules", "pkg", "all"])
    ap.add_argument("--dir", default=os.path.join(vhvm.REPO, "tests", "vm", "work"))
    ap.add_argument("--mem", type=int, default=3072)
    ap.add_argument("--smp", type=int, default=4)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--repo", action="store_true", help="обновить /root/vh в системе из рабочей копии")
    a = ap.parse_args()
    steps = {"base": [step_base], "ctools": [step_ctools], "enroll": [step_enroll], "sb": [step_sb], "lock": [step_lock],
             "desktop": [step_desktop], "strictnet": [step_strictnet], "deadman": [step_deadman],
             "totp": [step_totp], "modules": [step_modules], "pkg": [step_pkg], "deadmandump": [step_deadmandump],
             "all": [step_base, step_enroll, step_sb, step_lock, step_desktop]}[a.step]
    for s in steps:
        s(a)
    print("\n==== ИТОГ")
    for n, ok, d in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}: {n}")
    sys.exit(0 if all(ok for _, ok, _ in RESULTS) else 1)


if __name__ == "__main__":
    main()
