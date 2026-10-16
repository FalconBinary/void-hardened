# 16. Справочник команд

Все команды проекта и стандартные команды Void, которые нужны в этой системе, — в одном
месте, по этапам и ролям. Здесь только «что набрать и что получится»; «почему так» —
в главе, на которую стоит ссылка.

Обозначения как в остальном руководстве: **[LIVE]** — с флешки, от root; **[ПОСЛЕ
ЗАГРУЗКИ]** — в установленной системе. Кто запускает:

- **user** — повседневный пользователь, сеанс на tty1. Прав администратора нет.
- **admin** — администратор, только на tty2 (`Ctrl+Alt+F2`), команды через `doas`.
  Несколько команд подряд — `doas -s` (root-шелл; закрывается сам через 10 минут простоя).
- **root** — [LIVE] или внутри `doas -s`.

## Содержание

1. [Установка с флешки](#1-установка-с-флешки)
2. [Первая загрузка](#2-первая-загрузка)
3. [Горячие клавиши](#3-горячие-клавиши)
4. [Команды пользователя](#4-команды-пользователя)
5. [Администрирование: команды проекта](#5-администрирование-команды-проекта)
6. [Пакеты: xbps](#6-пакеты-xbps)
7. [Сервисы: runit](#7-сервисы-runit)
8. [Сеть](#8-сеть)
9. [Загрузка, Secure Boot, шифрование, TPM](#9-загрузка-secure-boot-шифрование-tpm)
10. [Безопасность и диагностика](#10-безопасность-и-диагностика)
11. [Питание, память, накопитель](#11-питание-память-накопитель)
12. [Опциональные модули](#12-опциональные-модули)
13. [Восстановление с флешки](#13-восстановление-с-флешки)
14. [Где лежат настройки](#14-где-лежат-настройки)
15. [Замеры и VM-стенд](#15-замеры-и-vm-стенд)

---

## 1. Установка с флешки

Подробно — [00-prepare.md](00-prepare.md), [01-disk.md](01-disk.md), [02-bootstrap.md](02-bootstrap.md).

| Команда | Что делает |
|---|---|
| `loadkeys us` | раскладка консоли live-образа |
| `wpa_passphrase 'СЕТЬ' 'пароль' > /tmp/wpa.conf` | Wi-Fi в live (кабель работает сам, по DHCP) |
| `wpa_supplicant -B -i wlp0s20f3 -c /tmp/wpa.conf` | подключиться; имя интерфейса — из `ip link` |
| `xbps-install -Syu xbps` | обновить сам xbps в live (иначе следующая команда может отказать) |
| `xbps-install -Sy git` | git в live (в RAM) |
| `git clone https://github.com/FalconBinary/void-hardened.git && cd void-hardened` | получить проект |
| `./install/00-probe.sh` | проба железа без изменений: CPU, GPU, Wi-Fi, NVMe, TPM, Secure Boot, BIOS. Отчёт — `/tmp/vh-probe-*.txt` |
| `./install/00-probe.sh --install-tools` | то же, но сначала ставит в live `pciutils`, `usbutils`, `tpm2-tools` и т. п. — отчёт полнее |
| `cp vh.conf.example vh.conf` | копия настроек; обязательно задать `VH_DISK` (переменные — [раздел 14](#14-где-лежат-настройки)) |
| `./install/10-install.sh --dry-run` | показать план (диск, разделы, пакеты), ничего не трогая |
| `./install/10-install.sh` | установка: разметка, LUKS2, XFS, пакеты, конфиги, UKI, Limine, пароли. Диск стирается — запросит подтверждение |
| `./install/10-install.sh --config ДРУГОЙ.conf` | установка с другим файлом настроек |
| `./install/build-netline.sh /mnt` | собрать и поставить netline в смонтированную систему (установщик делает это сам при `VH_NETLINE=yes`) |

| `install/build-tools.sh /mnt` | собрать инструменты на Zig в RAM live-среды и поставить в систему ([17](17-zig-tools.md)); повторный запуск после `git pull` обновляет их |
| `install/build-thor.sh /mnt` | собрать thor (xbps + политика) в RAM live-среды, пакет — в `/mnt/var/lib/thor/repo` ([18](18-thor.md)); установщик делает это сам; затем в системе `doas xbps-install -Su thor` |

`install/chroot.sh` и `install/lib.sh` руками не запускаются — их вызывает `10-install.sh`.

Полезное в live при проблемах:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN      # какой диск ваш
nvme list                          # модель NVMe и размер сектора
ls /sys/firmware/efi                # есть — загрузились в режиме UEFI (нужно)
efibootmgr -v                      # записи загрузки прошивки
```

## 2. Первая загрузка

Подробно — [03-boot.md](03-boot.md), [05-system.md](05-system.md).

Порядок: Limine → UKI → пароль LUKS → tty1 (user, сеанс mango стартует сам). Админ —
`Ctrl+Alt+F2`, логин `admin`.

| Команда (admin) | Что делает |
|---|---|
| `doas /root/vh/install/20-firstboot.sh` | проверки после установки; если прошивка в Setup Mode — создаёт свои ключи Secure Boot, вносит их (подтверждение словом `enroll`), подписывает UKI и Limine, проверяет |
| `doas /root/vh/install/20-firstboot.sh --microsoft` | то же, но с сертификатами Microsoft в db. Нужно, только если без них не стартует Option ROM видеокарты/сетевой карты; по умолчанию не нужно — вместо этого в db вносятся хэши Option ROM из журнала TPM |
| `doas /root/vh/install/30-lock.sh` | после того как всё железо проверено: запрет загрузки модулей ядра до перезагрузки (`kernel.modules_disabled=1`). Подтверждение словом `lock` |
| `doas rm /etc/vh/modlock.enabled` | отключить запрет модулей (с ближайшей перезагрузки) |
| `doas vh-audit` | чек-лист: каждая строка `[ ok ]`/`[FAIL]`/`[ ?? ]` с объяснением |

## 3. Горячие клавиши

Подробно — [12-daily.md](12-daily.md). Системные привязки — `/etc/vh/mango-vh.conf`
(принадлежит root), свои — `~/.config/mango/config.conf`.

| Клавиши | Действие |
|---|---|
| `Super+Return` | терминал foot |
| `Super+D` | zrun — запуск программ |
| `Super+Shift+D` | zrun в режиме команды |
| `Super+B` | браузер, доверенный профиль |
| `Super+Shift+B` | браузер, одноразовый профиль (без JIT, WebGL, GPU; ничего не помнит) |
| `Super+W` | zwifi — сети Wi-Fi |
| `Super+Shift+W` | zbt — Bluetooth |
| `Super+P` | zwall — обои |
| `Super+C` | zcal — календарь |
| `Super+Escape` | zpower — выключение/перезагрузка/выход |
| `Super+L` | заблокировать экран (swaylock) |
| `Super+F` | окно на весь экран |
| `Super+U` / `Super+Shift+U` | флешка: подключить / безопасно извлечь (модуль usb-auth) |
| `Ctrl+1…9` | перейти на тег (рабочий стол) |
| `Alt+1…9` | перенести окно на тег |
| `Alt+Q` | закрыть окно |
| Fn-клавиши яркости, громкости, микрофона | `vh-backlight` и `wpctl` |
| `Ctrl+Alt+F2` / `Ctrl+Alt+F1` | консоль админа / обратно в сеанс |
| `Правый Ctrl+Правый Alt+End` | тревожное выключение (только с модулем deadman и если включено) |

Экран блокируется сам через 5 минут простоя и при закрытии крышки. Окна браузера
открываются на теге 9 без фокуса — `Ctrl+9`, чтобы перейти.

## 4. Команды пользователя

| Команда | Что делает |
|---|---|
| `vh-browse` | браузер (доверенный профиль) в песочнице от пользователя `browser` |
| `vh-browse untrusted` | одноразовый профиль |
| `vh-backlight +5` / `-5` / `50` | яркость: прибавить, убавить, задать в процентах |
| `wpctl status` | устройства звука PipeWire |
| `wpctl set-volume @DEFAULT_AUDIO_SINK@ 50%` | громкость |
| `wpctl set-default ID` | выбрать выход по номеру из `wpctl status` |
| `vh-open ФАЙЛ` | открыть PDF/картинку/видео/текст в песочнице (модуль viewers) |
| `vh-open --gpu ФАЙЛ` | видео с аппаратным декодированием — только для своих файлов |
| `zwifi`, `zbt`, `zwall`, `zbg`, `zpower`, `zcal`, `zrun` | утилиты netline, то же, что клавиши выше |
| `ls ~/Downloads` | загрузки браузера (общий каталог `/home/xfer`, без исполнения) |

`vh-session` и `vh-wlfilter` запускаются сами при входе на tty1, руками не нужны.

Внести свой IP в разрешения браузера для локальной сети или открыть локальный порт —
это делает админ (см. [раздел 8](#8-сеть)).

## 5. Администрирование: команды проекта

### Обновление — [09-updates.md](09-updates.md)

| Команда | Что делает |
|---|---|
| `doas vh-update` | всё обновление: синхронизация, список, подтверждение, установка, пересборка и подпись UKI при обновлении микрокода/прошивок/dracut/limine, разбор новых файлов пакетов, снятие SUID, сертификаты unbound, процессы со старыми библиотеками |
| `doas xbps-reconfigure -f linux6.18` | пересобрать и подписать UKI вручную (после правки cmdline, dracut.conf.d, модулей) |
| `doas vh-limine-update --dry-run` | показать, что будет записано в `limine.conf`, ничего не меняя |
| `doas vh-limine-update` | переписать `limine.conf` по UKI на ESP (с хэшами), подписать и заменить Limine |
| `doas vh-limine-update --new 6.18.57_1` | то же, явно указав только что собранную версию ядра (так вызывает хук ядра) |
| `doas vkpurge list` / `doas vkpurge rm 6.18.55_1` | старые ядра: список / удалить (все сразу — `vh-deep-clean --only kernels`) |

### Установка программ — [12-daily.md](12-daily.md#10-установка-программ-thor-и-vh-pkg), [18-thor.md](18-thor.md)

| Команда | Что делает |
|---|---|
| `doas thor install ПАКЕТ… [-y] [-j N]` | установить: синхронизация, план, параллельная загрузка (N воркеров, по умолчанию 4), установка с политикой (SUID, хуки, udev, чёрный список); принимает ключи `xbps-install` |
| `doas thor update [-y]` | обновить всё (= `xbps-install -Su`, загрузка параллельно) |
| `doas thor fetch [-u] [ПАКЕТ…]` | только скачать в кэш и проверить подписи |
| `doas thor remove ПАКЕТ…` | = `xbps-remove` |
| `thor search СЛОВО` | = `xbps-query -Rs` |
| `doas thor mirror [--write]` | замер зеркал (задержка, скорость); `--write` — лучшее в `/etc/xbps.d`, запасные в `/etc/thor/thor.conf` |
| `doas thor allow ПАКЕТ…` | разрешить пакет из чёрного списка (покажет причину, спросит) — `/etc/thor/allow.conf` |
| `doas thor keep ПУТЬ…` | исключение политики для файла или каталога модуля dracut — `/etc/thor/keep.conf` |
| `doas thor baseline` | базовый список хуков и правил из установленных пакетов (перевод старой установки на thor) |
| `thor policy` | режим политики, число записей в списках, разрешённые SUID и capabilities |
| `doas vh-pkg add ПАКЕТ… [-y]` | = `thor install` + уборка осиротевших зависимостей |
| `doas vh-pkg add ПАКЕТ --ignore ЗАВИСИМОСТЬ` | не ставить зависимость (xbps `ignorepkg`); навсегда, пока не убрать строку из `/etc/xbps.d/51-vh-pkg-ignore.conf` |
| `doas vh-pkg add ПАКЕТ --keep ПУТЬ` | = `thor keep ПУТЬ` перед установкой |
| `doas vh-pkg scan ПАКЕТ…` | снять SUID и capabilities, вернувшиеся мимо xbps (`vh-suid-strip`); разбор файлов делает thor при установке |
| `doas vh-pkg rm ПАКЕТ…` | удалить пакет с зависимостями и сиротами; изменённые конфиги — в журнал для `vh-deep-clean` |

### Очистка — [12-daily.md](12-daily.md#11-очистка-vh-deep-clean)

| Команда | Что делает |
|---|---|
| `doas vh-deep-clean` | план: что удалится по группам и сколько места освободится; ничего не меняет |
| `doas vh-deep-clean --apply` | убрать ненужное; по каждой группе — вопрос; до и после — `vh-audit` и `xbps-pkgdb -a` |
| `doas vh-deep-clean --apply -y` | без вопросов (ядра с ключами на носителе так не удаляются) |
| `doas vh-deep-clean --apply --user` | плюс `~/.cache`, кэш Firefox, корзина |
| `doas vh-deep-clean --only orphans,conf,services,kernels,cache,user` | только перечисленные группы (с `--apply` или без) |
| `doas vh-deep-clean restore` | вернуть конфиги и ссылки сервисов из резерва последней очистки |

### Права и аудит — [05-system.md](05-system.md), [10-audit.md](10-audit.md)

| Команда | Что делает |
|---|---|
| `doas vh-audit` | полный чек-лист системы |
| `doas vh-suid-strip` | снять SUID/SGID и capabilities, вернувшиеся с обновлением |
| `doas vh-suid-strip --audit` | только показать, ничего не меняя |
| `doas vh-suid-strip --quiet` | молча (для скриптов) |

### Оборудование — [06-network.md](06-network.md), [11-performance.md](11-performance.md)

| Команда | Что делает |
|---|---|
| `doas vh-bluetooth on` / `off` | Bluetooth по требованию: снять rfkill и запустить bluetoothd / остановить и заблокировать радио. Пароль не нужен — правило doas пропускает только эти два слова |
| `doas sv restart vh-acpid` | применить изменения `/etc/vh/acpi.conf` (крышка, кнопка питания, простой) |
| `doas vh-power` | применить профиль питания по текущему источнику (вызывает udev сам) |
| `doas passwd user` | сменить пароль пользователю |
| `doas passwd` | сменить пароль root |
| `passwd` | сменить свой пароль |

Настройки `/etc/vh/acpi.conf`:

```sh
LID_MIN=10              # крышка закрыта дольше N минут → штатное выключение
POWER_KEY=poweroff      # кнопка питания: poweroff | lock | ignore
IDLE_LOCK_MIN=0         # блокировка по простою физического ввода (0 — выкл.)
IDLE_POWEROFF_MIN=0     # выключение по простою (0 — выкл.)
INTERNAL_INPUT=""       # свои имена встроенных устройств ввода, если не распознались
```

## 6. Пакеты: xbps

Подробно — [02-bootstrap.md](02-bootstrap.md), [09-updates.md](09-updates.md). Для установки
программ используйте `vh-pkg`; голый `xbps-install` не разбирает файлы пакета.

| Команда | Что делает |
|---|---|
| `xbps-query -Rs СЛОВО` | поиск в репозитории |
| `xbps-query -R ПАКЕТ` | описание пакета из репозитория |
| `xbps-query -Rx ПАКЕТ` | зависимости пакета |
| `xbps-query -l` | установленные пакеты |
| `xbps-query -m` | установленные явно (не зависимостями) |
| `xbps-query -f ПАКЕТ` | файлы установленного пакета |
| `xbps-query -o /путь/к/файлу` | какому пакету принадлежит файл |
| `xbps-query -X ПАКЕТ` | кто зависит от пакета |
| `doas xbps-install -S` | синхронизировать индексы |
| `doas xbps-install -un` | что обновится (без установки) |
| `doas xbps-install -Sn ПАКЕТ` | что поставится вместе с пакетом (без установки) |
| `doas xbps-remove -R ПАКЕТ` | удалить с ненужными зависимостями |
| `doas xbps-remove -o` | удалить осиротевшие зависимости |
| `doas xbps-remove -O` | убрать из кэша устаревшие версии пакетов (весь кэш — `vh-deep-clean --only cache`) |
| `doas xbps-pkgdb -a` | проверить целостность всех файлов пакетов (хэши) |
| `doas xbps-pkgdb -m manual ПАКЕТ` / `-m auto` | пометить пакет как явный / как зависимость |
| `doas xbps-reconfigure -f ПАКЕТ` | заново выполнить хуки пакета |
| `doas xbps-alternatives -l` | альтернативы (какой бинарник за каким именем) |

Своё: `/etc/xbps.d/20-vh-ignorepkg.conf` (не ставить никогда), `30-vh-noextract.conf`
(не распаковывать файлы: прошивки, SUID-бинарники), `50-vh-pkg.conf`, `51-vh-pkg-ignore.conf`
(добавляет `vh-pkg`). В строгом режиме сети перед ручным `xbps-install` — `doas vh-net xbps`.

## 7. Сервисы: runit

Подробно — [05-system.md](05-system.md). Активные сервисы — ссылки в `/var/service/`.

| Команда | Что делает |
|---|---|
| `doas sv status /var/service/*` | состояние всех сервисов |
| `doas sv status iwd` | один сервис: `run` — работает, время с запуска |
| `doas sv restart unbound` | перезапустить |
| `doas sv down X` / `doas sv up X` | остановить / запустить до перезагрузки |
| `doas ln -s /etc/sv/X /var/service/` | включить навсегда (стартует через ~5 с) |
| `doas rm /var/service/X` | выключить навсегда |
| `doas touch /etc/sv/X/down` | не запускать при загрузке, но оставить управляемым |
| `ls /etc/sv` | все установленные сервисы |
| `cat /etc/sv/X/run` | как сервис запускается |
| `doas svlogtail` | все журналы в реальном времени |
| `doas svlogtail kernel` / `daemon` / `secure` / `auth` | только ядро / демоны / безопасность / входы |
| `doas less /var/log/socklog/kernel/current` | журнал ядра целиком |
| `dmesg` | сообщения ядра (только admin: `kernel.dmesg_restrict=1`) |
| `doas poweroff` / `doas reboot` | штатные выключение / перезагрузка |

Включённые по умолчанию: `agetty-tty1`, `agetty-tty2`, `udevd`, `dbus`, `iwd`, `unbound`,
`chronyd`, `seatd`, `socklog-unix`, `nanoklogd`, `vh-acpid`, `dhcpcd-eth0` (или
`vh-eth-static`), `vh-fstrim`. Suspend и гибернации нет намеренно ([05-system.md](05-system.md)).

## 8. Сеть

Подробно — [06-network.md](06-network.md), [07-network-speed.md](07-network-speed.md).

### Wi-Fi: iwd

| Команда | Что делает |
|---|---|
| `iwctl` | интерактивная оболочка (дальше команды без `iwctl`) |
| `iwctl station wlan0 scan` + `iwctl station wlan0 get-networks` | найти сети |
| `iwctl station wlan0 connect "СЕТЬ"` | подключиться (пароль спросит) |
| `iwctl station wlan0 show` | состояние, сигнал, скорость |
| `iwctl station wlan0 disconnect` | отключиться |
| `iwctl known-networks list` | сохранённые сети |
| `iwctl known-networks "СЕТЬ" forget` | забыть сеть |
| `iw dev wlan0 link` | частота, битрейт, MCS |
| `iw dev wlan0 get power_save` | энергосбережение Wi-Fi (должно быть `off`) |
| `iw reg get` | регуляторный домен (страна) |
| `rfkill list` | блокировки радио |

Профили сетей — `/var/lib/iwd/*.psk` (только root).

### Межсетевой экран: nftables

| Команда | Что делает |
|---|---|
| `doas nft list ruleset` | все правила |
| `doas nft list set inet vh browser_lan` | текущие разрешения браузеру в локальной сети |
| `doas nft add element inet vh browser_lan '{ 192.168.1.10 . 443 timeout 30m }'` | пустить браузер к адресу:порту в LAN на 30 минут (роутер, NAS) |
| `doas nft add element inet vh browser_lo_ports '{ 8000 timeout 2h }'` | пустить браузер к своему локальному серверу на `127.0.0.1:8000` |
| `doas nft delete element inet vh browser_lan '{ 192.168.1.10 . 443 }'` | убрать разрешение досрочно |
| `doas nft -c -f /etc/nftables.conf` | проверить файл правил без применения |
| `doas nft -f /etc/nftables.conf` | применить правила после правки (файл начинается с `flush ruleset`) |
| `doas nft monitor trace` | трассировка пакетов (если правило с `meta nftrace set 1`) |
| `doas svlogtail kernel \| grep -E 'vh-(in\|out)-drop'` | что отбросил экран (входящее / исходящее) |

### DNS и время

| Команда | Что делает |
|---|---|
| `getent hosts example.org` | разрешение имени через системный резолвер (unbound) |
| `getent hosts dnssec-failed.org` | должно **не** разрешиться (SERVFAIL) — DNSSEC работает |
| `doas unbound-checkconf` | проверить `/etc/unbound/unbound.conf` |
| `doas sv restart unbound` | применить конфиг и сбросить кэш DNS |
| `chronyc -N sources` | источники времени |
| `doas chronyc -N authdata` | NTS: столбец `Mode` = `NTS`, `KeyID` растут |
| `chronyc tracking` | смещение часов |
| `date` | текущее время |

### Проводная сеть и адреса

| Команда | Что делает |
|---|---|
| `ip -br a` | адреса интерфейсов |
| `ip r` | маршруты |
| `ss -tunap` | открытые сокеты (от root — с процессами) |
| `doas sv restart dhcpcd-eth0` | переполучить адрес по кабелю |
| `ethtool eth0` | скорость и дуплекс кабеля |

## 9. Загрузка, Secure Boot, шифрование, TPM

Подробно — [03-boot.md](03-boot.md), [01-disk.md](01-disk.md).

ESP монтируется только на время работы (`noauto`): `doas mount /boot/efi` и
`doas umount /boot/efi`. UKI — `/boot/efi/EFI/void/linux-ВЕРСИЯ.efi`, Limine —
`/boot/efi/EFI/BOOT/BOOTX64.EFI`, его конфиг — `/boot/efi/EFI/BOOT/limine.conf`
(пишет только `vh-limine-update`: в конфиге хэши файлов, а сам конфиг вшит в подписанный
Limine — правка руками сломает загрузку).

| Команда | Что делает |
|---|---|
| `cat /proc/cmdline` | с какой командной строкой загружено ядро |
| `doas sbctl status` | Secure Boot включён, свои ключи, Setup Mode |
| `doas sbctl verify` | все ли EFI-файлы на ESP подписаны (ESP должна быть смонтирована) |
| `doas sbctl list-files` | что sbctl подписывает при обновлении |
| `doas efibootmgr -v` | записи загрузки прошивки |
| `doas efibootmgr -o 0001,0000` | порядок загрузки |
| `cat /sys/kernel/security/lockdown` | режим lockdown (`[confidentiality]`) |
| `doas cryptsetup luksDump /dev/nvme0n1p2` | заголовок LUKS: слоты ключей, PBKDF, шифр |
| `doas cryptsetup luksAddKey /dev/nvme0n1p2` | добавить пароль (запасной) |
| `doas cryptsetup luksChangeKey /dev/nvme0n1p2` | сменить пароль |
| `doas cryptsetup luksKillSlot /dev/nvme0n1p2 N` | удалить слот N |
| `doas cryptsetup luksHeaderBackup /dev/nvme0n1p2 --header-backup-file /media/user/luks-header.img` | резервная копия заголовка — на флешку, хранить отдельно |
| `doas cryptsetup status cryptroot` | открытый том: шифр, размер ключа, флаги |
| `doas tpm2_pcrread sha256:0,2,4,7,8,9` | измерения загрузки в TPM |
| `doas tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements` | журнал измерений прошивки |

Изменить командную строку ядра: `KERNEL_CMDLINE` в `/etc/default/dracut-uefi-hook`, затем
`doas xbps-reconfigure -f linux6.18`. Меню Limine — `/etc/vh/boot.conf` (`TIMEOUT` — секунды,
`KEEP` — сколько ядер оставлять в меню), затем `doas vh-limine-update`. BIOS обновляется
с флешки средствами MSI ([00-prepare.md](00-prepare.md)), `fwupd` не установлен.

## 10. Безопасность и диагностика

Подробно — [05-system.md](05-system.md), [08-desktop.md](08-desktop.md), [10-audit.md](10-audit.md).

| Команда | Что делает |
|---|---|
| `doas vh-audit` | весь чек-лист |
| `doas aa-status` | профили AppArmor и режимы (enforce/complain) |
| `doas apparmor_parser -r /etc/apparmor.d/vh.firefox` | перезагрузить профиль после правки |
| `doas svlogtail kernel \| grep 'apparmor="DENIED"'` | отказы AppArmor |
| `cat /sys/kernel/security/lsm` | активные LSM (`landlock,lockdown,yama,apparmor…`) |
| `cat /proc/sys/kernel/modules_disabled` | `1` — модули заперты (после `30-lock.sh`) |
| `lsmod` | загруженные модули |
| `doas sysctl -a 2>/dev/null \| grep ИМЯ` | текущее значение параметра ядра |
| `doas sysctl --system` | применить `/etc/sysctl.d` без перезагрузки |
| `find / -xdev -perm /6000 -type f 2>/dev/null` | все SUID/SGID-файлы (должны быть только `doas` и `unix_chkpwd`) |
| `doas getcap -r /usr 2>/dev/null` | файлы с capabilities |
| `grep -E 'Seccomp\|NoNewPrivs\|CapEff' /proc/PID/status` | ограничения процесса (браузер: `2`, `1`, `0`) |
| `ps -eo user,pid,comm` | процессы и владельцы |
| `doas /usr/local/libexec/vh/vh-seccomp --selftest` | самопроверка фильтров seccomp (48 случаев) |
| `doas udevadm info /dev/X` | атрибуты устройства для правил udev |
| `doas udevadm control --reload && doas udevadm trigger` | применить правила udev |
| `doas svlogtail auth` | входы и неудачные попытки |
| `doas -s` | root-шелл (TMOUT 600, история не пишется) |
| `doas apparmor_parser -r -C /etc/apparmor.d/ПРОФИЛЬ` | перевести профиль в complain (вместо `aa-complain`: Python-утилит AppArmor в системе нет) |

Правка `doas.conf`: `doas doas -C /etc/doas.conf` проверяет синтаксис до выхода из
редактора — без этого можно остаться без `doas` (тогда — [раздел 13](#13-восстановление-с-флешки)).

## 11. Питание, память, накопитель

Подробно — [11-performance.md](11-performance.md), [15-cachyos.md](15-cachyos.md).

| Команда | Что делает |
|---|---|
| `cat /sys/class/power_supply/BAT*/capacity` | заряд, % |
| `cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference` | профиль EPP (`balance_performance` от сети, `balance_power` от батареи) |
| `grep MHz /proc/cpuinfo` | частоты ядер |
| `cat /sys/class/thermal/thermal_zone*/temp` | температуры (миллиградусы) |
| `cat /sys/bus/pci/devices/0000:01:00.0/power/runtime_status` | dGPU NVIDIA: `suspended` — спит |
| `doas powertop` | потребление (если поставить `doas vh-pkg add powertop`) |
| `free -h` | память |
| `zramctl` | zram: алгоритм, сжатие |
| `swapon --show` | подкачка (только zram) |
| `findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS` | точки монтирования и опции (`nosuid`, `noexec`, `nodev`) |
| `df -h` / `du -sh /usr` | место |
| `doas xfs_info /` | параметры XFS |
| `doas fstrim -v /` | TRIM вручную (раз в неделю это делает `vh-fstrim`) |
| `cat /sys/class/nvme/nvme0/model` | модель NVMe (здоровье — `doas vh-pkg add nvme-cli`, затем `doas nvme smart-log /dev/nvme0`) |

## 12. Опциональные модули

Подробно — [13-optional.md](13-optional.md). У каждого модуля есть `enable` и `disable`:

```sh
doas /root/vh/optional/status                  # что включено
doas /root/vh/optional/МОДУЛЬ/enable
doas /root/vh/optional/МОДУЛЬ/disable
```

Включение модулей, которым нужны модули ядра (usb-auth, fido2, deadman), — до `30-lock.sh`
или с перезагрузкой после `doas rm /etc/vh/modlock.enabled`.

### strict-net — сеть по разрешению

| Команда | Что делает |
|---|---|
| `doas vh-net status` | действующие временные разрешения |
| `doas vh-net xbps [МИН]` | root: DNS и HTTPS к зеркалам из `/etc/xbps.d` (по умолчанию 30 минут; `vh-update` и `vh-pkg` вызывают сами) |
| `doas vh-net allow user [МИН]` | сеть и DNS пользователю (по умолчанию 10 минут) |
| `doas vh-net revoke user` | отозвать досрочно |

### dns-pin — пиннинг сертификатов DoT/NTS

`enable` спрашивает подтверждение словом `pin`. При смене УЦ у провайдера DNS —
[09-updates.md](09-updates.md), раздел 6. `pin-fetch АДРЕС ПОРТ ИМЯ [ALPN]` — вспомогательный,
выводит корень цепочки сервера.

### usb-auth — флешки без BadUSB

| Команда | Что делает |
|---|---|
| `doas vh-usb attach` (`Super+U`) | последнее вставленное устройство: авторизовать только интерфейсы накопителя и смонтировать в `/media/user` (`nodev,nosuid,noexec,nosymfollow`) |
| `doas vh-usb detach` (`Super+Shift+U`) | sync, отмонтировать, деавторизовать — можно вынимать |
| `doas vh-usb list` | внешние устройства и их состояние |
| `doas vh-usb-allow-key` | разрешить свой FIDO2-ключ в конкретном порту (вставить напрямую, без хаба) |

`enable` спрашивает подтверждение словом `usb`.

### fido2 — вход по ключу

`enable` регистрирует по два ключа на пользователя (основной и запасной). На YubiKey
заранее выключите клавиатурный интерфейс: `ykman config usb --disable OTP`.

### sb-offline-keys — ключи Secure Boot на отдельном носителе

| Команда | Что делает |
|---|---|
| `doas /root/vh/optional/sb-offline-keys/enable /dev/sdX` | перенести ключи на носитель (стирается; подтверждение — имя устройства) |
| `doas vh-keys mount` | выключить сеть, открыть носитель, подключить ключи |
| `doas vh-keys umount` | отключить ключи, закрыть носитель, вернуть сеть |
| `doas vh-keys status` | подключён ли носитель |
| `doas vh-uki-verify --init [UKI]` | записать эталоны (после чистой установки) |
| `doas vh-uki-verify UKI ВЕРСИЯ` | проверить новую UKI перед подписью (вызывает `vh-limine-update`) |

`vh-update` сам скачивает пакеты с сетью и просит вставить носитель перед установкой.

### tpm2-totp — проверка, что загрузка не подменена

`enable` защищает TPM от перебора и показывает lockout-пароль TPM — запишите его офлайн
(вместе с ключами PK/KEK) и подтвердите словом `записал`. Дальше:

1. перезагрузка; после пароля LUKS initramfs спросит пароль восстановления tpm2-totp (свой,
   diceware из 5 слов) и покажет QR-код — добавьте его в приложение TOTP (Aegis, FreeOTP);
2. на каждой загрузке **до** ввода пароля LUKS сверяйте 6 цифр на экране с телефоном;
   не совпало без обновления — пароль не вводить ([13-optional.md](13-optional.md));
3. после обновления ядра, микрокода или BIOS код один раз не совпадёт: сверьте версию ядра
   на экране с записанной, введите `RESEAL` и пароль восстановления.

### deadman — стирание ключа LUKS

| Команда | Что делает |
|---|---|
| `doas /root/vh/optional/deadman/enable` | спросит метку (USB-устройство на шнурке) и комбинацию клавиш |
| `doas vh-deadman test` | что будет стёрто, вставлена ли метка — ничего не делает |
| `cat /run/vh/deadman` | состояние демона |
| `doas sv status vh-deadman` | демон работает |

Настройки — `/etc/vh/deadman.conf` (`TAG`, `COMBO`, `WATCHDOG`), после правки
`doas sv restart vh-deadman`. `vh-deadman daemon` и `vh-deadman final` вызывают runit
и стадия выключения, руками не запускаются.

### session-netns — сеанс пользователя без сети

Сеанс на tty1 запускается в пустом сетевом пространстве имён (только `lo`): у mango,
терминалов и программ пользователя нет сети на уровне ядра. Wayland, звук и D-Bus работают
(сокеты в ФС), zwifi управляет iwd как обычно, браузер выходит в сеть через root-лаунчер.
Команд нет: `enable` / `disable`, действует со следующего входа.

### session-apparmor — профиль на весь сеанс пользователя

| Команда | Что делает |
|---|---|
| `doas /root/vh/optional/session-apparmor/enable` | режим complain: только журнал отказов |
| `doas /root/vh/optional/session-apparmor/enable --enforce` | запрещать (после недели в complain) |
| `doas svlogtail kernel \| grep vh.session` | отказы профиля сеанса |

Свои разрешения — `/etc/apparmor.d/local/vh.session`.

### viewers — просмотрщики в песочнице

`vh-open ФАЙЛ`, `vh-open --gpu ФАЙЛ` ([раздел 4](#4-команды-пользователя)).

### home-lockdown — конфиги пользователя только для чтения

| Команда | Что делает |
|---|---|
| `doas /root/vh/optional/home-lockdown/enable` | подтверждение словом `lock` |
| `doas vh-apply-config [user]` | применить черновики из `~/config-drafts/` (показывает diff и строки, запускающие программы; подтверждение по каждому файлу). Запускать после выхода пользователя из сеанса |

Пользователь правит копию: `~/config-drafts/.config/foot/foot.ini` вместо
`~/.config/foot/foot.ini`.

## 13. Восстановление с флешки

Подробно — [03-boot.md](03-boot.md) (восстановление), [09-updates.md](09-updates.md) (откат).

```sh
# [LIVE] открыть и смонтировать систему
cryptsetup open /dev/nvme0n1p2 cryptroot
mount /dev/mapper/cryptroot /mnt
mount /dev/nvme0n1p1 /mnt/boot/efi
for d in dev proc sys sys/firmware/efi/efivars run; do mount --rbind /$d /mnt/$d; done
chroot /mnt /bin/bash

# внутри: починить что нужно, например
xbps-reconfigure -f linux6.18          # пересобрать и подписать UKI
vh-limine-update                       # переписать limine.conf
passwd admin                           # забытый пароль
doas -C /etc/doas.conf                 # проверить doas.conf

# выход
exit
umount -R /mnt
cryptsetup close cryptroot
```

Обновить netline из live: после `cryptsetup open` и `mount` (без chroot) —
`./install/build-netline.sh /mnt`. Так же обновляются инструменты на Zig и thor (компилятора
в системе нет): `./install/build-tools.sh /mnt`, `./install/build-thor.sh /mnt`.

Если сломан заголовок LUKS — `cryptsetup luksHeaderRestore /dev/nvme0n1p2
--header-backup-file luks-header.img` из резервной копии ([01-disk.md](01-disk.md)).

Если Secure Boot не пускает (UKI не подписана) — в BIOS временно выключить Secure Boot,
загрузиться, `doas xbps-reconfigure -f linux6.18`, `doas sbctl verify`, включить обратно.

## 14. Где лежат настройки

### Переменные установки — `vh.conf`

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `VH_DISK` | — | диск для установки, например `/dev/nvme0n1` (обязательно) |
| `VH_ESP_SIZE` | `1G` | размер ESP |
| `VH_TRIM` | `yes` | TRIM через LUKS (быстрее, видно занятые блоки) |
| `VH_LUKS_ITER_MS`, `VH_LUKS_MEM_KIB` | `3000`, `1048576` | стоимость Argon2id: время и память |
| `VH_HOSTNAME`, `VH_TIMEZONE`, `VH_LOCALE`, `VH_KEYMAP` | `void`, `Europe/Ljubljana`, `en_US.UTF-8`, `us` | имя, часовой пояс, язык, раскладка |
| `VH_REGDOM` | `SI` | страна для Wi-Fi |
| `VH_MIRROR` | `repo-default.voidlinux.org` | зеркало |
| `VH_KERNEL` | `linux6.18` | серия ядра |
| `VH_ADMIN`, `VH_USER`, `VH_BROWSER_USER` | `admin`, `user`, `browser` | имена пользователей |
| `VH_INITRD_COMPRESS` | `zstd` | сжатие initramfs |
| `VH_LIMINE_TIMEOUT` | `1` | секунды меню Limine |
| `VH_EXTRA_CMDLINE` | — | дополнительные параметры ядра |
| `VH_GPU` | `igpu` | `igpu` — только Intel, GTX 1650 обесточена; `nouveau` — и NVIDIA (`DRI_PRIME=1`) |
| `VH_BLUETOOTH` | `optional` | `off` / `optional` (по требованию, `vh-bluetooth on`) / `on` |
| `VH_CAMERA`, `VH_CARDREADER` | `no` | веб-камера, кардридер |
| `VH_FIRMWARE_TRIM`, `VH_FIRMWARE_KEEP` | `yes`, — | оставить только прошивки вашего железа; что сохранить дополнительно |
| `VH_VIRT` | `no` | KVM для виртуальных машин |
| `VH_ETH`, `VH_ETH_ADDR`, `VH_ETH_GW` | `dhcp` | проводная сеть: `dhcp` / `static` / `off` |
| `VH_DNS_UPSTREAMS` | Quad9… | серверы DoT `адрес@853#имя` |
| `VH_NTS_SERVERS` | Cloudflare, Netnod, PTB… | серверы NTS |
| `VH_ZRAM_ALGO`, `VH_ZRAM_PERCENT` | `zstd`, `50` | zram |
| `VH_HOME_NOEXEC` | `yes` | `/home` без исполнения |
| `VH_DEV_DIR` | — | каталог в домашнем, где исполнение разрешено (для разработки) |
| `VH_NETLINE`, `VH_NETLINE_REPO`, `VH_NETLINE_REF` | `yes`, …, `lite` | бар netline; собирается тем же Zig, что свои инструменты и thor (`zig/ZIG_VERSION`, сейчас 0.17.0) |
| `VH_TEST_SERIAL` | `no` | консоль на последовательном порту (только VM-стенд) |

После установки значения сохранены в `/etc/vh/vh.env`.

### Файлы системы

| Файл | Что настраивает |
|---|---|
| `/etc/default/dracut-uefi-hook` | `KERNEL_CMDLINE` — командная строка ядра внутри UKI |
| `/etc/dracut.conf.d/` | состав initramfs |
| `/etc/vh/boot.conf` | Limine: таймаут, офлайн-ключи |
| `/etc/nftables.conf` | межсетевой экран |
| `/etc/vh/nft/*.nft` | динамические части экрана (strict-net) |
| `/etc/iwd/main.conf` | iwd: MAC-рандомизация, роуминг |
| `/etc/unbound/unbound.conf` | DNS: DoT-серверы, DNSSEC, защита от rebinding |
| `/etc/chrony.conf` | время: серверы NTS |
| `/etc/doas.conf` | кто и что может через doas |
| `/etc/sysctl.d/` | параметры ядра |
| `/etc/modprobe.d/` | запрещённые модули, параметры модулей |
| `/etc/udev/rules.d/` | права устройств, питание |
| `/etc/apparmor.d/` | профили AppArmor (`local/` — свои дополнения) |
| `/etc/xbps.d/` | репозитории, ignorepkg, noextract |
| `/etc/vh/acpi.conf` | крышка, кнопка питания, простой |
| `/etc/vh/deadman.conf` | dead man's switch |
| `/etc/vh/mango-vh.conf` | системные клавиши и автозапуск сеанса |
| `/etc/vh/firefox/` | Firefox: политики и настройки для доверенного и одноразового профилей (`policies-*.json`, `vh-*.cfg`) |
| `/etc/vh/suid-strip.list` | файлы, у которых `vh-pkg` снял SUID (`vh-suid-strip` снимает снова) |
| `/etc/vh/optional/` | флаги включённых модулей |
| `~/.config/mango/config.conf` | свои настройки mango (теги, вид, раскладка) |
| `~/.config/foot/foot.ini` | терминал |

## 15. Замеры и VM-стенд

Подробно — [15-cachyos.md](15-cachyos.md), [00-prepare.md](00-prepare.md) (стенд).

| Команда | Что делает |
|---|---|
| `sh tools/vh-bench` | замеры CPU, памяти, простоя, загрузки — одинаково здесь и в CachyOS |
| `sh tools/vh-bench --fio` | плюс накопитель (нужен `fio`, 2 ГБ временный файл) |
| `python3 tests/vm/vhvm.py install --iso VOID.iso [--netline] [--conf 'VH_X="y"']` | установить систему в qemu (OVMF с Secure Boot, swtpm, NVMe) |
| `python3 tests/vm/vhvm.py boot` | загрузить установленную VM |
| `python3 tests/vm/vhvm.py shell --run 'КОМАНДА'` | загрузить и выполнить команды через последовательную консоль |
| `sh tests/zig/run.sh` | инструменты на Zig: юнит-тесты, дифференциальные тесты против C-эталона из истории git, фаззинг прокси (нужен docker) |
| `sh tests/thor/run.sh` | thor: политика на тестовых пакетах, параллельная загрузка и запасное зеркало, замена xbps на системе Void, vh-pkg |
| `sh tests/zig/build.sh` | собрать x86_64-инструменты и пакет thor в `build/` для `check.py --repo` |
| `python3 tests/vm/check.py ШАГ [--repo]` | проверка: `thor`, `base`, `ctools`, `enroll`, `sb`, `lock`, `desktop`, `strictnet`, `deadman`, `deadmandump`, `totp`, `modules`, `pkg`, `clean`. `--repo` — сначала обновить скрипты в VM из рабочей копии |

Общие ключи стенда: `--dir КАТАЛОГ` (по умолчанию `tests/vm/work`), `--mem`, `--smp`.
`vh-hashpw` (`zig/tools/vh-hashpw.zig`) — хэш пароля для автоматической установки на стенде, на настоящем
железе не нужен.
