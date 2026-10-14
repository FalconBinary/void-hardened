# 02. Bootstrap: пакеты и первичная настройка

> Модуль 2 промпта. Скрипты: `install/10-install.sh` (разделы «bootstrap», «ядро и
> загрузчик»), `install/packages.sh`, `install/chroot.sh`.

## 1. Как устроен xbps

**xbps** — пакетный менеджер Void. Важное для безопасности:

- **Репозиторий** — каталог на зеркале: пакеты `*.xbps` (tar + zstd) и индекс
  `x86_64-repodata` (список пакетов, версий, зависимостей, хэшей).
- **Индекс подписан** ключом RSA проекта, каждый пакет — тоже (`*.xbps.sig2`). Публичные
  ключи хранятся в `/var/db/xbps/keys/*.plist`.
- **Доверие при первом использовании.** Впервые встретив репозиторий, xbps спрашивает,
  импортировать ли его ключ. Поэтому ключи для новой системы мы **копируем из
  проверенной live-среды** (её образ мы проверили подписью, [00](00-prepare.md)), а не
  принимаем вслепую:
  ```sh
  mkdir -p /mnt/var/db/xbps/keys
  cp -a /var/db/xbps/keys/. /mnt/var/db/xbps/keys/
  ```
- **У подписи индекса нет срока годности.** Зеркало (или атакующий между вами и
  зеркалом) может отдавать старый, но валидно подписанный индекс — вы не увидите
  обновлений безопасности («атака заморозки»). Защита — HTTPS-зеркало и сверка версий
  с независимым источником перед важными обновлениями ([09](09-updates.md)).

Зеркала: `https://xmirror.voidlinux.org` (список) — выберите ближайшее с HTTPS и
укажите в `VH_MIRROR`.

## 2. Конфигурация xbps до установки

Файлы в `/mnt/etc/xbps.d/` кладутся **до** первого `xbps-install`: тогда их правила
действуют уже при начальной установке. `xbps-install -r /mnt` читает конфигурацию из
`/mnt/etc/xbps.d` (каталог относительно rootdir — `man xbps-install`, опция `-C`).

**Репозитории** (`00-repository-main.conf`, `10-repository-nonfree.conf`): имя файла
совпадает с файлом в `/usr/share/xbps.d/` — так наш перекрывает штатный.
nonfree нужен ради одного пакета — `intel-ucode` (закрытый микрокод CPU, без которого
не закрыты аппаратные уязвимости).

**ignorepkg** (`20-vh-ignorepkg.conf`): «зависимость считается удовлетворённой, пакет
не ставится». Используем для лишнего:

| Пакет | Кто тянет | Почему не нужен |
|---|---|---|
| python3-tkinter, -gobject, -dbus, -notify2, -psutil | apparmor | нужны только графическим утилитам (aa-notify); `apparmor_parser` и `aa-status` — на C |
| openresolv | iwd, wireguard-tools | `resolv.conf` статический (127.0.0.1), его никто не переписывает |
| sudo | — (страховка) | администрирование через opendoas: в нём на порядки меньше кода, чем в sudo |

**noextract** (`30-vh-noextract.conf`): файл не распаковывается ни при установке, ни
при обновлениях. Так убираем SUID-программы, не нужные никому. SUID-бит — это
«запуск с правами владельца файла» (root): каждая такая программа — точка, где
обычный пользователь передаёт данные коду с правами root.

| Файл | Пакет | Что делает |
|---|---|---|
| su, sg, newgrp | util-linux, shadow | смена пользователя/группы — у нас doas |
| chsh, chfn | util-linux | смена шелла и GECOS пользователем |
| expiry, gpasswd | shadow | срок пароля, пароли групп |
| newuidmap, newgidmap | shadow | отображение subuid в user namespace (podman и т. п.) |
| wall, write | util-linux | SGID tty: запись в чужие терминалы |
| utempter | libutempter (зависимость foot) | SGID utmp: запись «кто вошёл»; без неё foot просто не пишет utmp |
| xbps-uchroot | xbps | SUID: chroot для сборки пакетов (xbps-src) |
| dbus-daemon-launch-helper | dbus | SUID: запуск сервисов D-Bus по требованию — здесь их запускает runit |

**noextract для прошивок** (`40-vh-firmware.conf`, при `VH_FIRMWARE_TRIM=yes`):
`linux-firmware-network` — 440 МБ прошивок всех сетевых чипов подряд (Qualcomm,
Mediatek, Broadcom…). Этому ноутбуку нужны пять групп файлов, остальное не
распаковывается — ни при установке, ни при обновлениях:

```
noextract=/usr/lib/firmware/*            # всё...
noextract=!/usr/lib/firmware/intel-ucode/*  # ...кроме микрокода CPU
noextract=!/usr/lib/firmware/regulatory.db* # базы регуляторных доменов Wi-Fi
noextract=!/usr/lib/firmware/i915/kbl_*     # DMC для Comet Lake (и cml_* — GuC/HuC)
noextract=!/usr/lib/firmware/iwlwifi-Qu*    # AX201 CNVi
noextract=!/usr/lib/firmware/intel/ibt-*    # Bluetooth AX201
noextract=!/usr/lib/firmware/rtl_nic/*      # RTL8111/8168
```

Правило xbps: шаблоны проверяются по порядку, «!» возвращает совпавшее (`man xbps.d`).
Экономия — ~430 МБ на диске. Скачивать пакет при обновлении всё равно приходится
целиком. Новое железо (USB Wi-Fi и т. п.) — допишите шаблон в `VH_FIRMWARE_KEEP` или в
файл и `xbps-install -f linux-firmware-network`. Какую прошивку грузит Wi-Fi, покажет
проба: `dmesg | grep iwlwifi` (строка «loaded firmware version»).

Остальные SUID (passwd, chage, mount, umount) нужны root, но не пользователям: их
бит снимает `vh-suid-strip` — при каждой загрузке и после каждого обновления (xbps
возвращает права при обновлении пакета). Остаются только `doas` и `unix_chkpwd`
(без него `swaylock` не проверит пароль). `ping` получает `CAP_NET_RAW` через
`setcap` в скрипте пакета — capability тоже снимается, а ping работает через
ICMP-сокеты для группы `netdiag` ([05](05-system.md)).

> **Проверено на стенде** (`find / -xdev -perm -4000 -o -perm -2000` после установки):
> промпт прав насчёт `wall`, `write` и `dbus-daemon-launch-helper`, а ещё нашлись
> `xbps-uchroot` и `utempter`. `seatd-launch` в Void — без SUID. Остаются только `doas`
> и `unix_chkpwd`; единственная file capability — `cap_syslog` у `nanoklogd` (socklog
> читает журнал ядра без root).

## 3. Набор пакетов

Вместо метапакета `base-system` — явный список (`install/packages.sh`): `base-system`
тянет sudo, dhcpcd для всех интерфейсов, wpa_supplicant, openssh, утилиты btrfs/f2fs.

| Группа | Пакеты | Зачем |
|---|---|---|
| Основа | base-files xbps runit-void coreutils findutils diffutils dash bash grep gzip sed gawk less which tar util-linux shadow procps-ng iana-etc tzdata glibc-locales ncurses kbd kmod eudev iproute2 iputils libcap-progs ethtool iw pciutils usbutils | минимально работающая система, сеть, диагностика |
| Документация | mdocml man-pages nvi | `man` и редактор — сисадмину без них никак |
| Ядро | linux6.18 | серия ядра напрямую: метапакет `linux` тянет `linux-base` → прошивки AMD, NVIDIA, sof, alsa |
| Прошивки | linux-firmware-intel linux-firmware-network wireless-regdb intel-ucode | i915, iwlwifi/BT, rtl_nic; база регуляторных доменов; микрокод |
| Загрузка | dracut dracut-uefi systemd-boot-efistub zstd lz4 cryptsetup xfsprogs dosfstools efibootmgr limine sbctl tpm2-tools | UKI, LUKS, ФС, NVRAM, загрузчик, ключи Secure Boot, TPM |
| Защита | opendoas dumb_runtime_dir apparmor bubblewrap acl-progs | doas, `/run/user/UID`, MAC, песочницы, ACL каталога обмена |
| Сеть и время | dbus iwd nftables unbound chrony (+ dhcpcd при VH_ETH=dhcp) | Wi-Fi, файрвол, DNS, NTS |
| Журналы | socklog-void | syslog и журнал ядра в `/var/log/socklog` |
| Рабочий стол | seatd mangowc foot swaylock swayidle wl-clipboard mesa-dri intel-media-driver pipewire wireplumber alsa-utils firefox dejavu-fonts-ttf python3 | сеанс, графика, видео, звук, браузер; python3 — для своих инструментов |

`dracut-uefi` тянет `binutils` (`objcopy` собирает UKI). В нём есть ассемблер `as` и
компоновщик `ld` — правило «компиляторов нет» выполняется не полностью. Компилятора C
нет, `/home` смонтирован с noexec ([05](05-system.md)), так что практической пользы
вредоносу `as`/`ld` дают мало — это записано как остаточный риск.

**Не ставится никогда** (проверяет `vh-audit`): компиляторы, планировщики (cron,
snooze — точки закрепления), acpid (может усыплять по крышке), polkit, udisks2, gvfs,
avahi, cups, NetworkManager, демоны питания (tlp, thermald и т. п.). `usbguard` из
репозитория зависит от polkit — поэтому USB-авторизация сделана правилами udev
(`optional/usb-auth`).

## 4. Установка в /mnt

```sh
XBPS_ARCH=x86_64 xbps-install -Sy -r /mnt \
  -R https://repo-default.voidlinux.org/current \
  -R https://repo-default.voidlinux.org/current/nonfree \
  $(список пакетов без linux6.18)
```

- `-r /mnt` — корень установки; скрипты пакетов (INSTALL) xbps выполняет через
  `chroot /mnt`.
- `-S` — синхронизировать индекс; `-y` — не спрашивать.

**Ядро ставится последним**, после настройки. Почему: установка ядра запускает хуки
`/etc/kernel.d/post-install/*`. Если ядро поставить первым, хук dracut соберёт
обычный initramfs (провайдер `dracut-uefi` ещё не выбран), ключей Secure Boot и
нашего хука подписи ещё нет. Поставленное последним ядро сразу проходит всю цепочку:
dracut-uefi → UKI → подпись → limine.conf → Limine ([03](03-boot.md)).

## 5. chroot

`chroot` меняет корень для процесса: внутри `/mnt` выглядит как `/`. Ядро — то же, что
у live-среды, поэтому нужные псевдо-ФС монтируются снаружи:

```sh
mount -t proc proc /mnt/proc
mount -t sysfs sys /mnt/sys
mount -t efivarfs efivarfs /mnt/sys/firmware/efi/efivars   # efibootmgr, sbctl
mount --rbind /dev /mnt/dev && mount --make-rslave /mnt/dev
mount -t tmpfs -o mode=0755,nosuid,nodev run /mnt/run
mount -t securityfs securityfs /mnt/sys/kernel/security      # журнал измерений TPM
env -i PATH=/usr/bin HOME=/root TERM=linux chroot /mnt /bin/bash
```

`env -i` — чистое окружение: переменные live-среды не попадают в настройку.
`--make-rslave` — размонтирование `/mnt/dev` потом не утянет `/dev` live-среды.

## 6. Что делает chroot.sh — и как то же руками [CHROOT]

**Хост, время, локаль:**

```sh
echo void > /etc/hostname
ln -sf /usr/share/zoneinfo/Europe/Ljubljana /etc/localtime
sed -i 's/^#\(en_US.UTF-8 \)/\1/' /etc/default/libc-locales && xbps-reconfigure -f glibc-locales
echo LANG=en_US.UTF-8 > /etc/locale.conf
# /etc/rc.conf: KEYMAP="us", HARDWARECLOCK="UTC"
```

**PAM и пользователи** — [05](05-system.md). **Конфиги сети** — [06](06-network.md).
**Сервисы runit** — [05](05-system.md). **Ключи Secure Boot и UKI** — [03](03-boot.md).

**Порядок важен:** сначала PAM (yescrypt), потом `passwd` — иначе пароль будет
захэширован старым методом. Проверка: `grep '^admin:\$y\$' /etc/shadow`.

## Проверка

```sh
xbps-query -l | wc -l                    # число пакетов (ориентир — 500-600)
xbps-pkgdb -a                            # целостность: хэши файлов и зависимости
xbps-query -l | grep -E '^ii (sudo|dhcpcd|wpa_supplicant|openssh|polkit)-' # пусто (dhcpcd — только при VH_ETH=dhcp)
find / -xdev -perm -4000 -type f         # /usr/bin/doas /usr/bin/unix_chkpwd
getcap -r /usr                           # пусто
```

> `xbps-pkgdb -a` сообщит об отсутствующих файлах из noextract — это ожидаемо
> [ПРОВЕРИТЬ на стенде точную формулировку и код возврата].

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| Подмены пакетов (подпись + ключи из проверенной среды); лишних SUID и демонов | Атака заморозки индекса; `as`/`ld` в системе; доверие к upstream Void | нет; меньше пакетов — быстрее обновления | Нет sudo/su: только doas от админа; пользователь не меняет пароль сам (passwd без SUID) |
