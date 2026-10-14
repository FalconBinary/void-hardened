# 10. Аудит, журналы, целостность, резервные копии

> Модуль 10 промпта. Инструменты: `doas vh-audit`, socklog, `xbps-pkgdb`.

## 1. vh-audit — чек-лист с ожидаемыми значениями

```sh
doas vh-audit
```

Каждая строка — `[ ok ]`, `[FAIL]` (не совпало с ожидаемым) или `[ ?? ]` (не удалось
проверить: нет сети, не выполнен этап). Что проверяется:

| Раздел | Проверки |
|---|---|
| Загрузка и ядро | параметры cmdline из UKI; lockdown = confidentiality; список LSM (AppArmor есть, BPF нет); `kernel.panic=10`; Secure Boot включён; `modules_disabled=1` (после этапа 3); fuse и overlay не загружены; профили AppArmor загружены |
| sysctl | каждое значение из `/etc/sysctl.d/*vh*.conf` совпадает с текущим |
| Монтирование | hidepid у /proc; noexec/nosuid/nodev у /tmp, /var/tmp, /dev/shm, /run; nosymfollow у /home/xfer; ESP не смонтирован |
| SUID и устройства | SUID только у doas и unix_chkpwd; file capabilities нет; права render node, rfkill, TPM, watchdog; нет компиляторов и лишних демонов |
| Пользователи | пароли yescrypt; root заблокирован; пользователь не в wheel, input, video, kvm; `doas -C` |
| Сервисы | работают dbus, iwd, unbound, chronyd, seatd, socklog, vh-acpid; не включены sshd, acpid, cron, wpa_supplicant; список включённых параноидальных модулей |
| Сеть | таблица nftables; слушает только unbound на 127.0.0.1:53; resolv.conf; redirects = 0 на all/default/eth0/wlan0; Wi-Fi без энергосбережения; DNS отвечает; chrony с NTS |
| Производительность | распакованы только нужные прошивки; THP `defer+madvise`; zram; планировщик NVMe `none`; EPP по профилю питания; dGPU в D3cold (VH_GPU=igpu) |

Запускайте после установки, после каждого `vh-update` и при любом подозрении.

## 2. Ручной чек-лист (то, что скрипт не проверит сам)

**Загрузка:**
- `sbctl status` — Secure Boot enabled, setup mode disabled; `sbctl verify` — всё подписано.
- Передать `init=/bin/sh` из меню Limine невозможно: редактор отключён. Проверка
  систему не меняет: `cat /proc/cmdline` совпадает с `/etc/default/dracut-uefi-hook`.
- `dmesg | grep -i DMAR` — IOMMU включён; `cat /sys/devices/system/cpu/vulnerabilities/*`.

**Сеть (с другого устройства в той же сети):**
- `nmap -sS -p- <адрес ноутбука>` — все порты filtered (входящих нет).
- Тест DNS rebinding: имя, указывающее на `192.168.x.x` (например, сервис типа
  nip.io: `192.168.1.1.nip.io`), не резолвится — unbound вырезает частные адреса.
- `getent hosts dnssec-failed.org` — отказ (DNSSEC работает).

**Изоляция браузера** (в одноразовом профиле откройте `about:support`):
- раздел «Песочница»: уровень песочницы контента 4 (или выше), user namespaces — нет;
- `about:policies` — ваша политика активна;
- в профиле нет каталогов `gmp-*` после просмотра видео.

**Сеанс:**
- `setsid sleep 9999 &` в терминале, выйти из mango, войти снова на tty2 админом:
  `ps -u user` пуст.
- `ls -ld ~/Downloads/` → ссылка на `/home/xfer`; симлинк, созданный в /home/xfer,
  не открывается (`ELOOP`).

## 3. Журналы

`socklog-void` пишет в `/var/log/socklog/<категория>/current` (ротация — svlogd):

| Где | Что |
|---|---|
| `kernel/` | отбрасывания файрвола (`vh-in-drop`, `vh-out-drop`), отказы AppArmor (`apparmor="DENIED"`), ошибки драйверов |
| `daemon/` | unbound, chronyd, iwd, dhcpcd |
| `secure/` | входы, ошибки паролей, faillock, doas |
| `everything/` | всё подряд |

```sh
doas svlogtail secure                     # входы и doas (svlogtail без аргументов — всё, с ожиданием новых строк)
doas grep -h 'vh-out-drop' /var/log/socklog/kernel/current | tail   # кто пытался в сеть
doas grep -h 'apparmor="DENIED"' /var/log/socklog/kernel/current | tail
```

Читает журналы только root — пользователь не видит, какие попытки замечены.

## 4. Целостность

**Изнутри** (быстро, но root-руткит может обмануть):

```sh
doas xbps-pkgdb -a                   # хэши файлов всех пакетов и зависимости
doas sbctl verify                    # подписи EFI-файлов на ESP
doas vh-suid-strip --audit           # SUID/SGID и capabilities
```

`xbps-pkgdb` сверяет файлы с хэшами в `/var/db/xbps` — на том же диске. Руткит
перепишет и файл, и хэш. Поэтому —

**Снаружи** (надёжно): загрузитесь с проверенной live-флешки, откройте LUKS,
смонтируйте в /mnt и сверьте с **внешним снимком** (на отдельном зашифрованном
носителе):

```sh
xbps-pkgdb -r /mnt -a
# снимок для сравнения создаётся заранее, после чистой установки и после каждого обновления:
tar -C /mnt -cf - var/db/xbps | sha256sum > /media/backup/xbps-db.sha256
find /mnt/etc /mnt/usr/local /mnt/boot/efi -type f -exec sha256sum {} + > /media/backup/files.sha256
sha256sum -c /media/backup/files.sha256 --quiet
```

Только офлайн-сверка обнаружит и **откат секторов XTS** (глава 01): подменённый
старый шифртекст расшифровывается в старую версию файла — хэш не совпадёт.
Периодичность — раз в месяц и после любой подозрительной ситуации (ноутбук без
присмотра в чужих руках).

## 5. Резервные копии

| Что | Как | Где хранить |
|---|---|---|
| Данные (`/home/user`) | `restic` или `borg` (оба в репозитории) с шифрованием, `age` для отдельных файлов | внешний диск, второй — в другом месте |
| Заголовок LUKS | `cryptsetup luksHeaderBackup` (глава 01) — при каждой смене пароля новый, старые уничтожить | зашифрованный внешний носитель |
| Ключи Secure Boot | `/var/lib/sbctl/keys` — копия на офлайн-носитель (или план перевыпуска: Setup Mode → `create-keys` → `enroll-keys`) | там же, где заголовок |
| Снимок целостности | раздел 4 | там же |

```sh
doas xbps-install -S restic
restic -r /media/backup/restic init
restic -r /media/backup/restic backup ~/Documents ~/projects
restic -r /media/backup/restic check --read-data-subset=10%    # восстановимость
```

**Проверяйте восстановление**, а не только создание: раз в квартал восстановите
несколько файлов в `/tmp` и сравните.

## 6. Меры с измеримой ценой — не включены по умолчанию

| Мера | Что закрывает | Как включить | Как замерить цену |
|---|---|---|---|
| `pti=on` | утечка адресов ядра через prefetch (EntryBleed) | `VH_EXTRA_CMDLINE` | системные вызовы: `perf bench syscall` недоступен из-за lockdown — `time` сборки/распаковки |
| `nosmt` | атаки через соседний поток ядра | `VH_EXTRA_CMDLINE` | −30–40 % многопоточной производительности: `zstd -T0 -b` |
| `spec_store_bypass_disable=seccomp spectre_v2_user=seccomp` | Spectre для процессов под seccomp (браузер) | `VH_EXTRA_CMDLINE` | Speedometer 3 до/после |
| `--integrity` (dm-integrity) | откат и подмена секторов | только при `luksFormat` | `fio` запись: −30–50 % |
| `vm.dirty_expire_centisecs` ↓ | меньше грязных страниц с открытым текстом в RAM | sysctl | `fio`/`iostat` под записью |
| `kernel.yama.ptrace_scope=3` | ptrace даже для root | sysctl | ломает strace/gdb |

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| Незамеченных изменений конфигурации; незаметного закрепления (офлайн-сверка); потери данных | Руткит, обманывающий проверки изнутри (до офлайн-сверки); копии вне вашего контроля | нет | Офлайн-сверка и проверка бэкапов — ручная дисциплина |
