# 14. Разбор исходного промпта

Основа проекта — промпт «Void Linux — chroot-bootstrap, hardening и сеть» (в заголовке
v2, внутри v5; 95 страниц, модули 0–12). Ниже — что в нём не сходится с реальностью
(проверено по пакетам и исходникам на октябрь 2026), что противоречит выбранному стеку
**seatd + Limine + mango + netline** и как это решено здесь.

Метод проверки: индекс репозиториев Void x86_64 (current + nonfree), содержимое
пакетов `.xbps` (файлы, права, скрипты INSTALL, conf_files), исходники mango 0.17.5 и
iwd 3.12, документация Limine 12.9.3, WirePlumber 0.5.18, политик Firefox, man-страницы
unbound 1.26, chrony 4.8, dhcpcd 10.3, foot 1.28, конфиг ядра Void 6.18
(`srcpkgs/linux6.18/files/x86_64-dotconfig`), настройки CachyOS (cachyos-settings) и прогон
установщика на стенде qemu + OVMF + swtpm.

## 1. Несовпадения со стеком

| Промпт | Реальность | Решение |
|---|---|---|
| Весь сеанс построен на **sway**: swaylock, swayidle, swaybar + status_command, IPC sway, `/etc/sway/config`, критерии `sandbox_engine`, `no_focus`, `shortcuts_inhibitor`, `primary_selection` | Выбран **mango** (mangowc 0.17.5 есть в репозитории Void — собирать не нужно) | swaylock и swayidle работают с mango (ext-session-lock, idle-notify есть). Аналоги: `focus_on_activate=0`, `allow_shortcuts_inhibit=0`, правила окон `isopensilent`, `tags`, `ignore_maximize`. Панель — netline |
| **security-context-v1** обязателен для браузера и просмотрщиков | В mango 0.17.5 его **нет** (main.c: screencopy, data-control, virtual-keyboard, input-method, layer-shell, session-lock, foreign-toplevel, gamma, output-management, drm-lease, shortcuts-inhibit создаются для всех клиентов, фильтра глобалов нет) | `vh-wlfilter` — прокси на python3 stdlib с **белым** списком глобалов; плюс пометка app_id/заголовка и запрет полноэкранного режима. Строже security-context (там — чёрный список) |
| IPC sway закрывается дочерним профилем AppArmor | IPC mango — `$XDG_RUNTIME_DIR/mango-<pid>.sock`, принимает `dispatch spawn` (запуск команд) | Песочницы его не видят (другой UID, свой XDG_RUNTIME_DIR). От процессов самого пользователя — `optional/session-apparmor` |
| Сеть — только iwd, без NetworkManager; нет BlueZ; нет elogind/polkit | netline: zwifi на NetworkManager, zbt на BlueZ, zpower на logind + polkit | netline доработан: zwifi умеет iwd (свой агент паролей), zpower без logind — `doas reboot/poweroff`, zbt запускает Bluetooth по требованию |
| Bluetooth вырезан полностью | Вы подключаете наушники через zbt | `VH_BLUETOOTH=optional` (по умолчанию): bluez стоит, сервис выключен, радио заблокировано; включение на время — doas без пароля |
| Сеанс в пустом netns | netline видит сеть через sysfs/netlink — в пустом netns только `lo`, иконка Wi-Fi «умирает» | netns сеанса — параноидальный слой, с этой ценой |
| «Нет компиляторов, никаких сборок» | netline нужен Zig 0.16, в репозитории — 0.13 | [ВНЕ ОГРАНИЧЕНИЙ]: сборка в RAM live-среды, компилятор проверяется подписью и хэшем и в систему не попадает |

## 2. Фактические ошибки и пробелы

| # | Утверждение промпта | Как на самом деле | Что сделано |
|---|---|---|---|
| 1 | «Проверить, что PCR 8 нулевой в initramfs» | Limine 12 при Secure Boot с вписанным хэшем конфига **принудительно** включает measured boot: PCR 8 ← cmdline и пути, PCR 9 ← байты limine.conf и файлы | Схема tpm2-totp пересчитана ([13](13-optional.md)) |
| 2 | Не выключает ли `enroll-config` редактор Limine? | Выключает принудительно при SB + enrolled config (USAGE.md) | `editor_enabled: no` всё равно задан явно |
| 3 | «Ядро — пакет linux» | `linux` → `linux-base` → прошивки AMD, NVIDIA, sof, alsa (против минимализма и правила «nvidia-firmware только с nouveau») | ставится `linux6.18` напрямую |
| 4 | apparmor — «официальный пакет» без оговорок | тянет python3-tkinter, -gobject, -dbus, -psutil, -notify2 (для GUI-утилит) | `ignorepkg` |
| 5 | Стандартная загрузка профилей AppArmor | `09-apparmor.sh` из runit-void-apparmor компилирует все ~150 профилей пакета при каждой загрузке **без кэша**; штатный профиль `firefox` (unconfined + userns) прикрепляется к тому же пути, что и ограничивающий | свой `09-vh-apparmor.sh`: 5 профилей, из кэша; штатный скрипт — noextract |
| 6 | «Оценить usbguard» | usbguard в Void зависит от **polkit**, который промпт запрещает | USB-авторизация правилами udev (`optional/usb-auth`) |
| 7 | `xbps-query -Rs vlock` | vlock в репозитории нет | не нужен: админ входит отдельно, VT сеанса не видит ввод tty2 |
| 8 | Нет компиляторов | `dracut-uefi` тянет `binutils` (`as`, `ld`) | остаточный риск, записан (C-компилятора нет, /home noexec) |
| 9 | seatd-launch, dbus-daemon-launch-helper, wall/write — SUID/SGID | Проверено `find -perm` на стенде: `seatd-launch` без SUID; `dbus-daemon-launch-helper` — SUID, `wall`/`write` — SGID tty, а ещё SUID у `xbps-uchroot` и SGID у помощника `utempter` (зависимость foot) | все пятеро — в `noextract`; `vh-suid-strip` снимает биты, если файл всё же появился |
| 10 | fstab: hidepid для /proc, noexec для /dev/shm, /run, /dev | runit монтирует их в `00-pseudofs.sh` **до** fstab; `mount -a` уже смонтированное пропускает — опции из fstab молча не применяются | перемонтирование в `04-vh-mounts.sh` |
| 11 | «dGPU обесточен» | Без драйвера GTX 1650 остаётся в D0 (~5–8 Вт); механизм не описан | правило udev: runtime PM + удаление HDMI-аудио функции → корневой порт в D3cold |
| 12 | Вариант A (только iGPU) без оговорок | На многих ноутбуках с GTX 1650 HDMI разведён на dGPU — внешний монитор перестанет работать | проба показывает, к какому GPU подключён порт; `VH_GPU=nouveau` |
| 13 | swaylock + PAM «как есть» | `/etc/pam.d/swaylock` в Void включает стек `login` — faillock туда попал бы и сломался в процессе без root | свой стек swaylock: `pam_faildelay` + `pam_unix` |
| 14 | Модуль 7: `max-reuse-tcp-queue` для unbound | в unbound 1.26 опция называется `max-reuse-tcp-queries` | исправлено, все опции сверены с man-страницей |
| 15 | Политики Firefox на всё | `Preferences` не принимает `javascript.options.*` и `app.normandy.*` | autoconfig (`lockPref`), подмонтированный в песочницу |
| 16 | `pam_rundir` или `dumb_runtime_dir` — сравнить | В `system-login` Void уже есть `-session optional pam_dumb_runtime_dir.so` | достаточно поставить пакет; каталог чистит `vh-session` |
| 17 | `kernel.perf_event_paranoid=3` | в upstream максимум 2 (промпт сам это отмечает) | 2 |
| 18 | Сравнить «ExtensionSettings», WirePlumber для restricted-клиентов | WirePlumber 0.5 по умолчанию даёт restricted-клиентам `rx` **на всё, включая микрофон** | свой permission manager: Audio/Source, Video/Source — невидимы |
| 19 | Заголовок «v2» | содержание — v5 | — |
| 20 | `preempt=full` **или `preempt=lazy`** — выбрать по замеру | ядро Void собрано с `PREEMPT_VOLUNTARY` + `PREEMPT_DYNAMIC`, `CONFIG_PREEMPT_LAZY` не задан — режима `lazy` нет | `preempt=full` |
| 21 | «sched_ext — не использовать [ПРОВЕРИТЬ]» | `CONFIG_SCHED_CLASS_EXT` не задан — его и нельзя включить | — |
| 22 | fuse и overlay — «если модули, в module_blacklist» | в ядре Void — модули (`=m`) | добавлены в `module_blacklist` |
| 23 | `efi_pstore.pstore_disable=1` | `CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE=y`: в ядре Void он и так выключен | параметр оставлен — явное лучше неявного, цена нулевая |
| 24 | `kernel.softlockup_panic`, `hardlockup_panic`, `nmi_watchdog` | прошлая версия установщика их не ставила | добавлены в `30-vh-hardening.conf`; детектор hard lockup в ядре Void — `HARDLOCKUP_DETECTOR_PERF` |
| 25 | Крышку и кнопку питания обрабатывает «root-сторож» — только в связке со сторожем простоя | без acpid и без suspend в базовом слое крышка не делала бы **ничего**: ноутбук в сумке греется | `vh-acpid` в базовом слое: крышка → блокировка, > 10 мин → штатное выключение, кнопка → выключение; сторож простоя — опция |
| 26 | PCR 8 расширять после показа TOTP | Limine 12 при SB с вписанным хэшем сам пишет в PCR 8 и 9 | расширяется свободный PCR 14, на него запечатан секрет ([13](13-optional.md)) |
| 27 | штатный модуль dracut `70tpm2-totp` | его `check()` вызывает `tpm2-totp calculate` при сборке: при PCR, расширенном после показа, модуль не попал бы в образ; он же не умеет reseal по флагу | свой модуль `90vhtotp` |
| 28 | `vm.memfd_noexec=2` | в ядрах 6.3–6.5 значение 2 отклоняло `memfd_create()` без флагов; с 6.6 такие вызовы получают `MFD_NOEXEC_SEAL`, отказ — только `MFD_EXEC` | оставлено (ядро 6.18) |
| 29 | «linux-firmware-network» как есть | 440 МБ прошивок всех сетевых чипов | `noextract` с исключениями: распаковываются только iwlwifi-Qu*, ibt, rtl_nic, i915/kbl, микрокод (−430 МБ) |
| 30 | андервольт не упоминается | `intel-undervolt` есть в репозитории, но пишет в MSR — lockdown это запрещает | в списке запрещённых ускорений ([15](15-cachyos.md)) |
| 31 | `msi-ec` для режимов вентилятора | в ядре 6.18 модель MS-16R5 (GF63 Thin 10-го поколения) не поддерживается — только `16R6…` (11-е поколение) | проба проверяет прошивку EC; режимы MSI — только в Windows |
| 32 | флаг немедленного выключения после MOR — «своя NV-переменная под своим GUID» | efivarfs создаёт переменные с незнакомыми GUID неудаляемыми (`chattr +i`): initramfs без `chattr` не снял бы флаг — каждая загрузка заканчивалась бы выключением | переменная под GUID `LINUX_EFI_CRASH_GUID` (такие efivarfs создаёт удаляемыми); initramfs выключает машину, только если флаг удалился |

## 3. Внутренние противоречия промпта

- **«Минимум своих скриптов» vs ~25 своих root-скриптов и демонов** (dead man's switch
  с ioctl DM, сторож простоя на evdev, генератор seccomp, лаунчеры с передачей fd,
  проверка UKI, PE-парсер…). Каждый — доверенная база, которую надо поддерживать.
  Решение: защита **слоями**. Базовый слой — то, что даёт много при малой цене;
  самое тяжёлое — опционально, с явной ценой.
- **«Максимальная производительность» vs меры с ценой:** нет suspend, одноразовый
  браузер без JIT и GPU, `init_on_free`, `iommu.strict`, core scheduling. Здесь —
  осознанно: включено то, что стоит единицы процентов, а дорогое либо ограничено
  одноразовым профилем, либо вынесено в таблицу мер с ценой ([10](10-audit.md)).
- **«Пользователь без сети» vs разработка** (git, ssh, сборка netline): в базовом слое у
  пользователя сеть есть; строгий режим — `optional/strict-net`.
- **Сотни проверок [VM-ТЕСТ]**: часть (Wi-Fi, FIDO2, датчик крышки, iTCO) на стенде без
  реального железа не проверить — такие места помечены, профиль iwd поставляется в
  режиме complain.

## 4. Что в промпте сильное и сохранено

Модель угроз и требование «для каждой меры — от чего защищает, остаточный риск,
цена» (таблица в конце каждой главы); UKI со встроенной cmdline; свои ключи Secure
Boot без Microsoft и учёт Option ROM; lockdown, `modules_disabled`, запрет редких
модулей; отдельный пользователь браузера в bwrap без user namespace; DNS только через
unbound с DoT и DNSSEC; NTS; nftables с allowlist по skuid и fail-closed загрузкой;
iwd с WPA3/PMF/случайным MAC; `kill -KILL -1` после сеанса; запрещённые «ускорения»
с объяснением.

## 5. Что найдено прогоном на стенде

Установщик прогоняется целиком в qemu + OVMF + swtpm (`tests/vm/vhvm.py`). Ошибки, которые
статический разбор не поймал:

- в live-образе Void нет `xz` — архив Zig не распаковывался, установка обрывалась;
- проверка формата пароля `grep "^admin:\$y\$"` в двойных кавычках: последний `$` grep
  понимает как конец строки — правильный yescrypt-хэш «не находился»; та же ошибка была
  в `vh-audit`;
- у `vh-wlfilter` и `browser-sandbox` не было бита исполнения: фильтр Wayland не
  запустился бы, браузер не открылся бы;
- **unbound падал по кругу**: версия 1.26 при старте перечисляет интерфейсы
  (`getifaddrs` через netlink), а профиль AppArmor запрещал netlink целиком —
  «could not open ports». Профиль разрешает `netlink raw`;
- комментарии в конце строк `/etc/sysctl.d/*.conf`: `sysctl -p` из procps их не
  понимает и пишет в ядро «значение # текст» — у числовых параметров ядро отбрасывает
  хвост по случайности. Комментарии перенесены на отдельные строки;
- функция `msg` стадии 1 runit передаёт текст в `printf` как формат: «50%» в
  сообщении ломало вывод;
- правило udev `99-vh-devices.rules` не перекрывало `tpm-udev.rules` пакета tpm2-tss:
  порядок файлов лексический, «tpm-…» идёт после «99-…». Теперь присваивания
  окончательные (`MODE:=`);
- SUID/SGID у `wall`, `write`, `dbus-daemon-launch-helper`, `xbps-uchroot`, `utempter`
  (см. п. 9) — в `noextract`;
- unbound отдавал записи AAAA при выключенном IPv6 — теперь `private-address: ::/0`
  (при `VH_IPV6=no`);
- `sbctl verify` без смонтированного ESP («failed to find EFI system partition»):
  ESP в fstab — `noauto`, `20-firstboot.sh` и `vh-audit` монтируют его на чтение и на
  время проверки;
- браузер не подключался к Wayland: сокет фильтра создаётся от пользователя и получал
  его группу, а браузер — другой UID. Каталог `/run/vh-sandbox` теперь setgid
  (`2750 user:browser`) — сокеты наследуют группу браузера;
- профиль `vh.firefox` не давал fontconfig создавать файлы блокировки (`link`).

Промпт требовал seccomp-фильтр на bwrap браузера — в прошлой версии его не было.
Добавлен: `vh-seccomp browser` (генератор с метками и самопроверкой на 48 вызовах);
на стенде Firefox работает под ним (`Seccomp: 2`), профилем `vh.firefox (enforce)`,
без capability и с `no_new_privs`.

Что подтвердил стенд: загрузка Limine → UKI → LUKS2 → runit; регистрация своих ключей
Secure Boot с хэшем Option ROM из журнала TPM (iPXE сетевой карты) вместо сертификатов
Microsoft и загрузка с включённым Secure Boot; `modules_disabled=1` к стадии 2 (после
него даже CD с ISO9660 не смонтировать — модуль не загрузится); cmdline только из UKI;
lockdown=confidentiality; LSM `lockdown,capability,landlock,yama,apparmor`; DoT через
unbound; DNSSEC отвергает `dnssec-failed.org`; защита от DNS rebinding
(`192.168.1.1.nip.io` не резолвится); chrony — 4 источника по NTS; `xbps-pkgdb -a`
чист при обрезанных прошивках; `vh-acpid` находит кнопку питания.

## 6. Чего нельзя проверить без вашего ноутбука

Модель (для пунктов BIOS), какие порты USB «hardwired», подключение клавиатуры,
наличие MOR и Option ROM, блокировка NO_REBOOT у iTCO, разводка HDMI, поведение AX201
с LAR и энергосбережением. Всё это собирает `install/00-probe.sh` — запустите его с
live-флешки до установки.
