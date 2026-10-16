# 05. Система: runit, память, ядро, пользователи, PAM

> Модуль 5 промпта. Файлы: `/etc/runit/core-services/*-vh-*.sh`, `/etc/sysctl.d/*-vh-*.conf`,
> `/etc/modprobe.d/vh-*.conf`, `/etc/fstab`, `/etc/pam.d/{system-auth,system-login,doas,swaylock}`,
> `/etc/security/{access,faillock}.conf`, `/etc/doas.conf`, `/etc/udev/rules.d/99-vh-*.rules`,
> `/etc/profile.d/zz-vh.sh`, `/etc/bash/bashrc.d/vh.sh`.

## 1. runit: как стартует система

Void использует **runit** — init из трёх стадий:

1. **Стадия 1** (`/etc/runit/1`) — одноразовая инициализация. Последовательно выполняет
   (через `.`, в одном шелле) скрипты `/etc/runit/core-services/*.sh` по алфавиту:
   псевдо-ФС, udev, монтирование, sysctl… Здесь же наши шаги, которые **должны**
   произойти до запуска любых сервисов.
2. **Стадия 2** (`/etc/runit/2`) — `runsvdir` запускает все сервисы из
   `/etc/runit/runsvdir/default/` (он же `/var/service`) **параллельно** и следит за ними:
   упавший сервис перезапускается через секунду.
3. **Стадия 3** (`/etc/runit/3`) — выключение: остановка сервисов, `/etc/runit/shutdown.d/`,
   размонтирование.

Наши шаги стадии 1:

| Скрипт | Что делает | Почему в стадии 1 |
|---|---|---|
| `04-vh-mounts.sh` | опции `/proc`, `/dev`, `/dev/shm`, `/run` | runit монтирует их раньше fstab (раздел 2) |
| `05-vh-zram.sh` | swap в сжатой RAM | до того, как понадобится память |
| `07-vh-mm.sh` | THP `defrag=defer+madvise` ([11](11-performance.md)) | до запуска программ |
| `06-vh-nftables.sh` | правила файрвола; при ошибке — «запретить всё» | ни один сетевой сервис не стартует без правил |
| `11-vh-runtime.sh` | `/run/vh-sandbox`, профиль питания | каталог нужен сеансу, EPP — сразу |
| `12-vh-suid.sh` | снять вернувшиеся SUID и capabilities | до запуска программ пользователей |
| `99-zz-vh-modlock.sh` | предзагрузка модулей + `modules_disabled=1` (этап 3) | последним: после udev, до стадии 2 |

**Сервис runit** — каталог `/etc/sv/имя/` со скриптом `run`, который **не уходит в
фон** (`exec программа` в режиме переднего плана). Необязательные `conf` (читается
скриптом run) и `log/run` (журнал). Включить — ссылка в `/var/service/`:

```sh
ln -s /etc/sv/iwd /var/service/     # включить (и запустить)
sv status iwd                       # run: iwd: (pid 812) 3412s
sv restart iwd                      # перезапуск
sv down iwd                         # остановить (до перезагрузки)
rm /var/service/iwd                 # выключить совсем
```

Включено установщиком: `agetty-tty1`, `agetty-tty2` (только два входа), `udevd`, `dbus`,
`iwd`, `unbound`, `chronyd`, `seatd`, `socklog-unix`, `nanoklogd`, `vh-acpid`, `dhcpcd-eth0`
(VH_ETH=dhcp), `vh-fstrim` (VH_TRIM=yes). Нет: sshd, acpid, cron, wpa_supplicant.

> Свои `conf`-файлы: `/etc/sv/iwd/conf` (ждать шину D-Bus до 5 с и не стартовать без
> правил файрвола), `/etc/sv/dhcpcd-eth0/conf`. Пакет их не перезаписывает.

## 2. Монтирование и почему fstab не всё решает

```sh
findmnt -o TARGET,FSTYPE,OPTIONS      # что и с какими опциями смонтировано
```

| Точка | Опции | Зачем |
|---|---|---|
| `/proc` | `hidepid=invisible,gid=proc` | пользователь не видит чужие процессы и их аргументы (пароли в командной строке, пути). Админ — в группе `proc` |
| `/tmp`, `/var/tmp`, `/dev/shm` | tmpfs, `nosuid,nodev,noexec`, `size=` | общие каталоги без исполнения; размер ограничен, чтобы заполнение не вытесняло рабочие страницы |
| `/run` | `noexec,nosuid,nodev` | в /run только сокеты и состояние |
| `/dev` | `noexec,nosuid` | — |
| `/home` | `bind,nosuid,nodev,noexec` (`VH_HOME_NOEXEC`) | свои бинарники в $HOME не запускаются; каталог `VH_DEV_DIR` — исключение для разработки |
| `/home/xfer` | `…,noexec,nosymfollow` | каталог обмена с браузером: симлинки не разыменовываются вообще ([08](08-desktop.md)) |
| `/var/lib/vh-browser` | `nosuid,nodev,noexec` | профиль браузера |
| `/boot/efi` | `noauto,…,fmask=0177,dmask=0077` | ESP только на время обновления, только root |

**Ловушка Void.** `/proc`, `/dev`, `/dev/shm`, `/run` монтирует `00-pseudofs.sh` в стадии 1
**до** чтения fstab, а `mount -a` уже смонтированное пропускает. Строки для них в
fstab молча не действуют. Поэтому их опции ставит `04-vh-mounts.sh`
перемонтированием: `mount -o remount,…,hidepid=invisible,gid=… /proc`.

**noexec — не абсолютная защита.** `sh файл` выполнит команды шелла с noexec-раздела.
`/lib/ld-linux-x86-64.so.2 ./бинарник` — уже нет: ядро не отображает файл с такого раздела
с правом исполнения. Опаснее всего интерпретаторы с FFI (`python3` с `ctypes`, `perl`,
`luajit`): они выделяют исполняемую память и запускают в ней машинный код вообще без
файла. Поэтому таких интерпретаторов в системе нет: `ignorepkg=python3`, свои инструменты
написаны на Zig ([17](17-zig-tools.md)), `vh-audit` это проверяет. Бесфайловый запуск через
`memfd_create` закрыт `vm.memfd_noexec=2`. Браузер ещё и под AppArmor: право `m` и `x` —
только на файлы пакетов.

**Опции через bind.** `/home` — не отдельная ФС, поэтому опции вешаются bind-монтированием
на себя (`/home /home none bind,nosuid,nodev,noexec`): util-linux сам делает bind и
перемонтирование с флагами.

## 3. sysctl

Файлы `/etc/sysctl.d/30-vh-hardening.conf` (защита), `40-vh-network.conf` (сеть,
[06](06-network.md)), `50-vh-performance.conf` (память и планировщик, [11](11-performance.md)) — у
каждой строки комментарий. Применяются в стадии 1 (`08-sysctl.sh`); вручную —
`sysctl -p /etc/sysctl.d/30-vh-hardening.conf`; проверка — `sysctl -n имя` или `vh-audit`.

Ключевые (полный список — в файле):

| sysctl | Значение | Что закрывает |
|---|---|---|
| `kernel.kptr_restrict` | 2 | адреса ядра в `/proc/kallsyms` и др. — ломают KASLR |
| `kernel.dmesg_restrict` | 1 | журнал ядра (адреса, сведения о железе) — только root |
| `kernel.unprivileged_bpf_disabled` | 1 | eBPF без привилегий — источник множества LPE; 1 нельзя вернуть до перезагрузки |
| `kernel.yama.ptrace_scope` | 2 | ptrace только с `CAP_SYS_PTRACE`: процесс пользователя не прочитает память его же браузера или ssh-agent. 3 — запрет всем, включая root (ломает отладку и strace) |
| `kernel.io_uring_disabled` | 2 | io_uring — быстрый асинхронный ввод-вывод, но один из главных источников уязвимостей ядра |
| `vm.unprivileged_userfaultfd` | 0 | userfaultfd позволяет «остановить» ядро на page fault — основа эксплойтов гонок |
| `kernel.kexec_load_disabled` | 1 | загрузить другое ядро в обход Secure Boot |
| `kernel.sysrq` | 0 | клавиши SysRq (kill всех процессов, sync, reboot) с клавиатуры. `/proc/sysrq-trigger` для root работает всегда |
| `dev.tty.legacy_tiocsti` | 0 | вставка символов в чужой терминал (`ioctl TIOCSTI`) — класс атак «sudo в чужом терминале» |
| `net.mptcp.enabled` | 0 | MPTCP встроен в ядро и доступен без привилегий |
| `vm.memfd_noexec` | 2 | memfd без явного флага получает «неисполняемый навсегда», `MFD_EXEC` — отказ |
| `fs.protected_fifos`, `fs.protected_regular` | 2 | в общих каталогах со sticky-битом (`/tmp`) нельзя открыть чужой FIFO/файл с O_CREAT — атаки подмены |
| `fs.suid_dumpable`, `kernel.core_pattern` | 0, `\|/bin/false` | никаких дампов памяти (там ключи) |
| `kernel.panic`, `kernel.oops_limit` | 10, 100 | паника → перезагрузка; перебор через множество oops упирается в лимит |
| `kernel.softlockup_panic`, `kernel.hardlockup_panic` | 1, 1 | зависание без паники → паника → перезагрузка (раздел 11) |

`kernel.perf_event_paranoid=3` в промпте — патч Debian/Android, в upstream максимум 2.

## 4. Модули ядра

Модуль — код, который ядро загружает по требованию. **Любой** процесс может вызвать
автозагрузку: `socket(AF_RDS, …)` загрузит `rds`, правило nftables с редким
выражением — `nft_*`. Каждый такой модуль — редко используемый и слабо проверенный
код ядра, доступный атакующему без привилегий.

В ядре Void многое собрано модулями (`zcat /proc/config.gz | grep =m`): nf_tables, zram,
TCP BBR, а также **fuse** и **overlay** — монтирование, доступное без привилегий в своём
user namespace (класс уязвимостей CVE-2023-0386). Они в `module_blacklist`: flatpak,
AppImage и podman здесь не используются.

Три уровня защиты:

1. **`module_blacklist=` в cmdline** — ядро откажется загружать модуль вообще.
2. **`/etc/modprobe.d/vh-blacklist.conf`** — `install имя /bin/false`: дублирует первое
   (на случай, если список в cmdline разойдётся с файлом).
3. **`kernel.modules_disabled=1`** (этап 3) — после старта никакие модули не загружаются
   вовсе, даже root. Нужные позже (ФС флешек, `usb_storage`, модули AF_ALG для iwd,
   `tcp_bbr`…) предзагружаются из `/etc/vh/modules.preload` в конце стадии 1.

Этап 3 — после того как вы за одну загрузку воспользовались всем железом:

```sh
doas /root/vh/install/30-lock.sh     # снимок lsmod → modules.preload, флаг modlock.enabled
doas reboot
cat /proc/sys/kernel/modules_disabled   # 1
```

Цена: новое устройство другого типа заработает только после повторного `30-lock.sh` и
перезагрузки. Временно снять блокировку: `doas rm /etc/vh/modlock.enabled && doas reboot`.

> Следствие блокировки: предзагруженные модули AF_ALG (`algif_*`, нужны iwd для
> криптографии) доступны **любому** процессу через `socket(AF_ALG)`. Закрывают это
> профили AppArmor (`deny network alg`) — [08](08-desktop.md).

## 5. Пользователи и группы

| Учётная запись | Группы | Вход | Назначение |
|---|---|---|---|
| root | — | пароль заблокирован | только через `doas` от админа |
| `admin` | wheel, netdiag, proc, netdev | tty2, пароль | администрирование |
| `user` | _seatd, audio, render, netdev, backlight, netdiag, xfer | tty1 → сразу mango | повседневная работа |
| `browser` | render, xfer | нет (`nologin`, пароль заблокирован) | процессы браузера |
| `_unbound`, `chrony`, `_dhcpcd` | — | нет | сервисы (создаются пакетами) |

Принцип: повседневный пользователь **не в wheel** — его скомпрометированный процесс
не повысит права через doas (кроме узких правил без пароля, раздел 7). Группы с
прямым доступом к устройствам запрещены:

- `input` — чтение `/dev/input/*` = кейлоггер **всех** клавиатур, включая ввод админа на tty2;
- `video` — `/dev/dri/card0`: управление экраном мимо композитора.

Экран и ввод mango получает от **seatd** (группа `_seatd`): seatd выдаёт дескрипторы
устройств только активному сеансу на активном VT и отзывает их при переключении.

**pam_access** (`/etc/security/access.conf`): `user` входит только на tty1, `admin` —
только на tty2, остальные — нигде. Скомпрометированный сеанс пользователя не
попробует подобрать пароль админа через login на его TTY.

## 6. PAM

**PAM** — цепочка модулей, через которую `login`, `doas`, `swaylock` проверяют
пользователя. Четыре стека: `auth` (кто вы), `account` (можно ли вам сейчас),
`password` (смена пароля), `session` (что сделать при входе/выходе). Управляющие
флаги:

- `required` — неудача запоминается, стек продолжается (атакующий не узнаёт, какой
  модуль отказал);
- `requisite` — неудача сразу завершает стек;
- `sufficient` — успех сразу завершает стек успехом, *если до этого не было отказа
  required*;
- `[default=die]` — любой результат, кроме явно указанных, завершает отказом.

Изменения базового слоя:

```
# /etc/pam.d/system-auth — правки установщика (sed)
auth      required  pam_unix.so  try_first_pass              # убран nullok: пустой пароль не принимается
password  required  pam_unix.so  try_first_pass yescrypt rounds=7 shadow   # было: nullok sha512
```

**yescrypt** — memory-hard хэш паролей (как Argon2 для LUKS). `rounds=7` — в 4 раза
дороже умолчания (5): ~0,2–0,4 с на проверку пароля. shadow 4.8.1 в Void не знает
YESCRYPT в `login.defs` — поэтому пароли задаются только через `passwd` (PAM), не
через `chpasswd`. Проверка: `grep '^admin:\$y\$' /etc/shadow`.

**faillock** (`system-login` и `doas`): 5 ошибок за 15 минут → блокировка на 10 минут.
Не навсегда — иначе физический атакующий запер бы владельца. Стек `auth` в
`system-login` расписан явно:

```
auth  required       pam_faillock.so preauth      # заблокирован? — сразу отказ
auth  sufficient     pam_unix.so try_first_pass   # пароль верный — успех, дальше не идём
auth  [default=die]  pam_faillock.so authfail     # неверный — учесть и отказать
account required     pam_faillock.so              # при успешном входе — сбросить счётчик
```

С `include system-auth` вместо явного стека модуль `authfail` выполнялся бы и после
верного пароля (pam_unix в system-auth — `required`, а не `sufficient`).

**swaylock** работает от пользователя и проверяет пароль через SUID-помощник
`unix_chkpwd`. faillock там бесполезен: файл счётчика принадлежал бы пользователю, и
его процессы сбросили бы счётчик. Поэтому `/etc/pam.d/swaylock` — только
`pam_faildelay` (2 с после ошибки) + `pam_unix`.

**doas**: `umask=077` вместо `022` — файлы, созданные через doas, по умолчанию закрыты.

> **Правило при правке PAM:** держите открытым root-шелл (`doas -s` на tty2) и проверяйте
> вход на другом TTY, прежде чем закрыть его. Ошибка в PAM может закрыть вход всем.

## 7. doas

```
permit :wheel                                                              # админ: всё, с паролем каждый раз
permit nopass user as root cmd /usr/local/sbin/vh-browser args trusted     # ровно этот аргумент
permit nopass user as root cmd /usr/bin/poweroff args                      # без аргументов
```

- Нет `persist`: иначе после ввода пароля любой процесс админа 5 минут повышает права без пароля.
- `cmd` сравнивается буквально — вызывать с полным путём (`doas /usr/bin/poweroff`).
- `args` без значений — аргументы запрещены; со значениями — только эти.
- Нет `keepenv`: переменные пользователя (LD_PRELOAD, PATH) не попадают к root.
- Проверка синтаксиса: `doas -C /etc/doas.conf`; права файла — `0400 root:root`.

Что получает вредонос с правами `user` от этих правил: выключить или перезагрузить
машину, запустить браузер, включить Bluetooth. Не больше.

**Админ во время работы пользователя.** Ctrl+Alt+F2 → вход `admin`. Ввод на tty2 сеанс
пользователя не видит: seatd отбирает у mango клавиатуру при смене VT, а прямого
доступа к `/dev/input` у пользователя нет. Профиль админа: `TMOUT=600` (выход после
10 минут бездействия в приглашении) и `trap 'kill -KILL -1' EXIT` — после выхода не
остаётся ни одного процесса админа. Root-шелл `doas -s` — не login-шелл, поэтому
`TMOUT` для root задан в `/etc/bash/bashrc.d/vh.sh` (без trap — от root он убил бы всё).

## 8. SUID и capabilities

```sh
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f    # /usr/bin/doas /usr/bin/unix_chkpwd
getcap -r /usr                                            # пусто
doas vh-suid-strip --audit                                 # то же + снять вернувшееся
```

**File capabilities** — «кусочек root» для конкретного файла (например, `cap_net_raw`
для ping — сырые сокеты, через них можно подделывать пакеты). Ping работает и без
неё: ICMP-сокеты разрешены группе `netdiag` (`net.ipv4.ping_group_range`).

## 9. Права устройств (udev)

`/etc/udev/rules.d/99-vh-devices.rules` (номер 99 — после правил пакетов):

| Устройство | Было в Void | Стало | Почему |
|---|---|---|---|
| `/dev/dri/renderD*` | 0666 | 0660 root:render | драйвер i915 — только пользователю и браузеру |
| `/dev/rfkill` | 0664 | 0600 | снять блокировку радио — только root (iwd, bluetoothd) |
| `/dev/tpm0`, `/dev/tpmrm0` | группа tss | 0600 root | иерархии TPM — только root |
| `/dev/watchdog*` | — | 0600 root | открыть сторож без «поглаживания» = перезагрузка |
| `/dev/kvm` | 0666 | 0660 kvm | если KVM разрешён |
| `/sys/class/backlight/*/brightness` | root | группа backlight | яркость без SUID-утилит |

## 10. zram

zram — блочное устройство в RAM со сжатием (zstd ~ 3:1). Как swap: неиспользуемые
страницы сжимаются в памяти, а не пишутся на диск (где оказались бы ключи и
открытый текст). `05-vh-zram.sh`: `comp_algorithm=zstd`, размер 50 % RAM, приоритет 100.

- `vm.swappiness=180` — для zram выгоднее вытеснять анонимную память (сжатие в RAM
  быстрее, чем перечитывать файлы с NVMe).
- `vm.page-cluster=0` — читать по одной странице: упреждающее чтение не нужно для RAM.

Проверка: `zramctl`, `swapon --show`, `cat /sys/block/zram0/mm_stat`.

## 11. Крышка, кнопка питания, зависания: без acpid и без suspend

**Почему не acpid.** Его штатный обработчик (`/etc/acpi/handler.sh`) усыпляет машину по
крышке, а suspend запрещён: ключ LUKS лежал бы в RAM. Без acpid закрытие крышки и
нажатие кнопки питания не делают ничего — и работающий ноутбук в сумке греется и
садится. Поэтому `vh-acpid` (программа на Zig — [17](17-zig-tools.md), runit-сервис, `/etc/vh/acpi.conf`):

- слушает **только** два устройства ACPI — «Lid Switch» (`PNP0C0D`) и «Power Button»
  (`LNXPWRBN`/`PNP0C0C`) через `/dev/input/eventN`; USB- и виртуальные устройства его не
  касаются. Ожидание — блокирующий `poll()`: в простое ни одного пробуждения;
- крышка закрыта → `swaylock` в сеансе пользователя (`setpriv` с его UID, GID и группами,
  чистое окружение) — независимо от idle-inhibit браузера и от того, жив ли swayidle;
- закрыта дольше `LID_MIN` (10) минут → `poweroff`: стадия 3 runit (сервисы остановлены,
  данные сброшены, ФС отмонтированы). С внешним монитором крышка ничего не делает;
- кнопка питания → `poweroff` (`POWER_KEY=lock|ignore` — иначе); длинное нажатие
  (4 с) — аппаратное выключение мимо системы;
- сторож простоя (`IDLE_LOCK_MIN`, `IDLE_POWEROFF_MIN`, по умолчанию 0 — выключен;
  включает `optional/deadman`) — по времени без физического ввода со встроенных
  клавиатуры и тачпада.

Проверка: `doas svlogtail daemon | grep vh-acpid` — найденные устройства; закройте
крышку — экран заблокирован.

**Зависания.** `kernel.panic=10` превращает панику в перезагрузку через прошивку (с MOR
она стирает RAM). Но зависание **без** паники — soft lockup (ядро не отпускает CPU) или
hard lockup (CPU не отвечает даже на прерывания) — по умолчанию только пишется в журнал,
и машина остаётся под питанием с ключом в памяти. `kernel.softlockup_panic=1` и
`kernel.hardlockup_panic=1` (детектор hard lockup работает от NMI-сторожа:
`kernel.nmi_watchdog=1`) делают из них панику → перезагрузку. Ложные срабатывания
возможны только при зависании ядра дольше 20 с — это и есть сбой. `hung_task_panic` не
включаем: D-state бывает и при медленном вводе-выводе (флешка).

## 12. Журналы

`socklog-void`: `socklog-unix` принимает syslog программ, `nanoklogd` — журнал ядра.
Файлы — `/var/log/socklog/<категория>/current` (только root):

```sh
doas svlogtail                 # все журналы и затем новые строки (как tail -f)
doas svlogtail kernel          # отбрасывания файрвола (vh-in-drop / vh-out-drop), AppArmor
doas svlogtail secure          # входы, doas, faillock
doas cat /var/log/socklog/everything/current
```

Журналы сервисов, пишущих в stdout (unbound, chrony, dhcpcd), идут через `vlogger` в
тот же socklog.

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| Эскалации через редкие модули, BPF, io_uring, userfaultfd; подглядывания за процессами; подмены в /tmp; перебора паролей; лишних SUID; доступа к устройствам | Уязвимости в оставшемся коде ядра; интерпретаторы обходят noexec; root-доступ админа | ~0 (yescrypt — доли секунды на вход) | Админ — отдельный вход; пользователь не меняет свой пароль; новые типы устройств — после 30-lock.sh |
