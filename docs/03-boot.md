# 03. Загрузка: UKI, Secure Boot, Limine, TPM

> Модуль 3 промпта. Файлы: `/etc/default/dracut-uefi-hook` (командная строка ядра),
> `/etc/dracut.conf.d/10-vh.conf`, хуки `/etc/kernel.d/*/…-vh-*`,
> `/usr/local/sbin/vh-limine-update`, этап 2 — `install/20-firstboot.sh`.

## 1. Цепочка загрузки целиком

```
кнопка питания
 └─ прошивка UEFI (SEC → PEI → DXE)           измеряет себя и настройки в PCR 0–7
     └─ запись NVRAM «Void Linux (Limine)»     \EFI\BOOT\BOOTX64.EFI
         └─ Limine                              Secure Boot: подпись проверяет прошивка
             ├─ сверяет limine.conf с хэшем, вписанным в сам BOOTX64.EFI
             └─ запускает UKI (protocol: efi)   подпись UKI проверяет прошивка (db/dbx)
                 └─ systemd-stub                 измеряет секции UKI в PCR 11
                     └─ ядро (EFI stub)          измеряет initrd в PCR 9
                         └─ initramfs (dracut)   спрашивает пароль LUKS
                             └─ switch_root → /sbin/init (runit, стадия 1)
```

Каждое звено проверяет следующее **до** передачи управления. Подмена любого файла
на ESP даёт либо ошибку подписи (прошивка не запустит), либо ошибку хэша (Limine
остановится) — но не загрузку чужого кода.

## 2. UKI — ядро, initramfs и cmdline в одном подписанном файле

**UKI** (Unified Kernel Image) — PE-файл (как `.exe`), который прошивка запускает
напрямую. Внутри секции:

| Секция | Содержимое |
|---|---|
| `.linux` | ядро |
| `.initrd` | initramfs (+ микрокод CPU в начале) |
| `.cmdline` | командная строка ядра |
| `.osrel`, `.uname` | /etc/os-release и версия ядра |

Код «склейки» — **systemd-stub** (`linuxx64.efi.stub` из пакета
`systemd-boot-efistub`; сам systemd не нужен). Подпись UKI покрывает **все секции
сразу**: нельзя подменить initramfs или дописать `init=/bin/sh` в cmdline.

> **Почему это важно.** В классической схеме (GRUB + отдельные `vmlinuz` и
> `initramfs.img` на открытом `/boot`) подписано только ядро. Initramfs — архив,
> который спрашивает ваш пароль LUKS, — не подписан никем: evil maid подменяет его на
> версию, которая сохраняет пароль.

Поведение systemd-stub, о котором надо знать:
- **При включённом Secure Boot внешняя cmdline игнорируется** — действует только
  встроенная. Проверка: передать `init=/bin/sh` из меню Limine — `/proc/cmdline` не
  изменится.
- С ESP он подхватывает *addons* (только подписанные), *credentials* и *sysext*
  (без подписи; передаются в `/.extra` и измеряются в PCR 12/13). Наш initramfs —
  dracut без systemd — `/.extra` не читает, но подброшенный файл меняет PCR 12/13:
  это ловит tpm2-totp, если эти PCR в политике ([13](13-optional.md)).

### Сборка: dracut-uefi

Пакет `dracut-uefi` — альтернатива провайдера initramfs: вместо
`/boot/initramfs-*.img` его хук `20-initramfs` вызывает `dracut --uefi`:

```sh
xbps-alternatives -s dracut-uefi          # выбрать провайдер (один раз)
xbps-reconfigure -f linux6.18             # пересобрать UKI для установленного ядра
ls -l /boot/efi/EFI/void/                 # linux-6.18.56_1.efi
```

Настройки (`/etc/dracut.conf.d/10-vh.conf`):

| Параметр | Значение | Зачем |
|---|---|---|
| `hostonly="yes"` | только модули для этого железа | initramfs в разы меньше, быстрее грузится, меньше кода |
| `hostonly_cmdline="no"` | не дописывать параметры | cmdline — только наша, из одного места |
| `compress` | `zstd` или `lz4` | lz4 распаковывается быстрее, zstd меньше читать с ESP — [замер](11-performance.md) |
| `early_microcode="yes"` | микрокод в начале initramfs | ядро обновляет микрокод до всего остального |
| `reproducible="yes"` | без меток времени | одни входные данные → один хэш (проверка сборки, [13](13-optional.md)) |
| `add_drivers` | xhci_pci usbhid hid_generic atkbd i8042 | клавиатура для пароля LUKS (встроенная или USB) |
| `omit_dracutmodules` | plymouth, сеть, LVM, RAID, btrfs, systemd… | не нужны — меньше кода в initramfs |

> Хук dracut-uefi пишет UKI в `boot/efi/EFI/void/` **относительно корня**. Если ESP не
> смонтирован, файл ляжет на корневую ФС, а загружаться будет старое ядро. Поэтому
> хук `05-vh-esp` монтирует ESP до сборки и падает с ошибкой, если не вышло.

## 3. Командная строка ядра

Задаётся в `/etc/default/dracut-uefi-hook` (`KERNEL_CMDLINE=`), встраивается в UKI.
Изменить — отредактировать файл и пересобрать: `doas xbps-reconfigure -f linux6.18`.

| Параметр | Что делает | Цена |
|---|---|---|
| `rd.luks.uuid=…` | открыть только свой том LUKS | — |
| `root=UUID=… rootfstype=xfs rootflags=noatime,logbsize=256k ro` | корень; опции XFS, которые нельзя сменить при remount | — |
| `rd.lvm=0 rd.md=0 rd.dm=0` | не искать другие тома: флешка с подложным томом не активируется | — |
| `rd.shell=0 rd.emergency=poweroff` | при сбое initramfs — выключение, не root-шелл. `halt` оставил бы RAM (и ключ) под питанием | нет аварийного шелла — чинить с live-флешки |
| `quiet loglevel=3` | только ошибки на экране | — |
| `net.ifnames=0` | имена `eth0`/`wlan0` вместо `enp3s0` — проще конфиги | — |
| `panic=10` | после паники — перезагрузка через 10 с (с MOR прошивка сотрёт RAM), а не зависание с ключом в памяти. В cmdline — чтобы действовало до sysctl | — |
| `lockdown=confidentiality` | даже root не читает и не пишет память ядра (`/dev/mem`, kprobes, `/proc/kcore`), не грузит неподписанное, нет гибернации | нет гибернации, нет части инструментов отладки ядра |
| `module.sig_enforce=1` | только подписанные модули (подразумевается lockdown, задано явно) | DKMS-модули невозможны |
| `lsm=landlock,lockdown,yama,apparmor` | включить LSM. AppArmor в ядре Void собран, но без этого не активен. `bpf` нет намеренно: BPF LSM — инструмент для руткита. `capability` включён всегда | — |
| `intel_iommu=on iommu.strict=1 iommu.passthrough=0` | IOMMU для всех устройств; строгий режим сбрасывает IOTLB при каждом освобождении буфера — устройство не дочитает чужую память | заметно на NVMe с высоким IOPS — [замер fio](11-performance.md) |
| `efi=disable_early_pci_dma` | запрет DMA (bus master) PCI до включения IOMMU | — |
| `init_on_alloc=1 init_on_free=1` | обнулять память при выделении и **освобождении**: открытый текст не остаётся в свободной памяти | единицы процентов при интенсивной работе с памятью |
| `slab_nomerge page_alloc.shuffle=1` | не сливать кэши slab разных типов, перемешивать свободные страницы — сложнее эксплуатировать переполнения | ~0 |
| `debugfs=off` | нет `/sys/kernel/debug` — большая поверхность ядра | — |
| `ia32_emulation=0` | нет 32-битных системных вызовов: меньше кода ядра, доступного процессам | 32-битные программы (Steam, wine) не работают |
| `bdev_allow_write_mounted=0` | нельзя писать в блочное устройство со смонтированной ФС (повреждение XFS «из-под» ядра) | — |
| `efi_pstore.pstore_disable=1` | текст oops не пишется открытым текстом в NVRAM EFI | — |
| `proc_mem.force_override=never` | запись в чужую read-only память через `/proc/PID/mem` запрещена | ломает часть отладчиков |
| `cfg80211.ieee80211_regdom=SI` | регуляторный домен Wi-Fi с первой секунды: все разрешённые каналы, активное сканирование | — |
| `preempt=full` | полное вытеснение в ядре: интерфейс отзывчив под нагрузкой | ~0–1 % пропускной способности |
| `module_blacklist=…` | ядро не загрузит перечисленные модули ни по запросу, ни явно | — |
| `ipv6.disable=1` (VH_IPV6=no) | без IPv6: нет ожидания RA/DAD, нет утечек мимо VPN, меньше кода | нет IPv6-only сетей |

Список `module_blacklist` (функция `vh_module_blacklist` в `install/lib.sh`):
редкие сетевые протоколы, доступные без привилегий через `socket()` (sctp, rds, tipc,
can, atm, ax25, netrom, rose, x25, appletalk, ieee802154, nfc), порты с DMA (firewire,
thunderbolt), неиспользуемые ФС (cramfs, hfs, hfsplus, udf, cifs, nfs, ksmbd, 9p,
jffs2, freevxfs), `binfmt_misc`, `uhid`, интерфейс к ME (`mei*`), а по настройкам —
Bluetooth, камера, картридер, KVM, nouveau.

`mitigations=auto` (по умолчанию) не трогаем: смягчения уязвимостей CPU работают,
SMT (гиперпоточность) включена.

## 4. Secure Boot со своими ключами

### Как устроен

В NVRAM прошивки четыре базы:

- **PK** (Platform Key) — владелец платформы. Кто владеет PK, тот меняет KEK.
- **KEK** (Key Exchange Key) — кто может менять db и dbx.
- **db** — сертификаты и хэши, которым **разрешено** загружаться.
- **dbx** — отозванные: запрещено, даже если подписано разрешённым ключом.

С завода там ключи производителя и Microsoft. Пока установлен чужой PK, Secure Boot
защищает от *чужого* кода, но разрешает всё, что подписал Microsoft:

- **Microsoft UEFI CA 2011** подписывает shim — загрузчики всех дистрибутивов, включая
  старые версии с известными уязвимостями, которые загружают что угодно;
- **Microsoft Windows Production PCA 2011** подписывает загрузчики Windows, включая
  старые `bootmgr.efi` с обходом Secure Boot (BlackLotus, CVE-2022-21894, CVE-2023-24932).

Поэтому — **свои ключи** (sbctl) и **без сертификатов Microsoft**. Тогда загружается
только то, что подписали вы.

### Option ROM — главная ловушка

Прошивка исполняет код из ПЗУ устройств (Option ROM): GOP видеокарты, PXE сетевой
карты. Они подписаны Microsoft UEFI CA. Без сертификатов Microsoft в db прошивка их не
запустит — на части машин это **чёрный экран без возможности войти в BIOS**.

Выход без доверия всем подписям Microsoft — внести в db **хэши именно ваших Option
ROM**. Их берёт sbctl из журнала измерений TPM (`--tpm-eventlog`): каждая
загруженная прошивкой Option ROM записана туда как событие
`EV_EFI_BOOT_SERVICES_DRIVER`. На ноутбуке с iGPU, у которой GOP встроен в прошивку,
событий может не быть вовсе — тогда хэши не нужны. Проба
([00](00-prepare.md)) показывает их число.

> Обновление прошивки или видеокарты меняет хэш Option ROM. Перед прошивкой BIOS
> выключите Secure Boot, после — заново внесите хэши (`sbctl enroll-keys --tpm-eventlog
> --append`) [ПРОВЕРИТЬ sbctl enroll-keys --help].

### Этап 2: регистрация ключей

Ключи создаются при установке: `sbctl create-keys` → `/var/lib/sbctl/keys/{PK,KEK,db}/`.
Каждая UKI и Limine подписываются ключом db автоматически (хук `90-vh-uki`).

1. **[BIOS]** Задайте пароль администратора (supervisor). Без него любой выключит
   Secure Boot одной кнопкой.
2. **[BIOS]** Secure Boot → «Reset to Setup Mode» / «Delete all keys» / «Clear keys».
3. **[ПОСЛЕ ЗАГРУЗКИ]** `doas /root/vh/install/20-firstboot.sh` — проверит базовый слой,
   увидит Setup Mode, посчитает Option ROM в журнале TPM и выполнит:
   ```sh
   sbctl enroll-keys                   # Option ROM нет
   sbctl enroll-keys --tpm-eventlog    # есть Option ROM
   ```
4. **[BIOS]** Включите Secure Boot. Выключите загрузку с USB и сети, меню загрузки,
   UEFI Shell; Limine — первым в порядке загрузки.
5. **[ПОСЛЕ ЗАГРУЗКИ]** Снова `20-firstboot.sh`: `sbctl status` должен показать
   «Secure Boot: Enabled», `sbctl verify` — все файлы подписаны.

**PKfail.** На части прошивок в качестве PK записан тестовый ключ производителя с
известным приватным ключом. После `enroll-keys` PK — ваш; проверка:
`sbctl list-enrolled-keys` [ПРОВЕРИТЬ наличие подкоманды в sbctl 0.18].

### Где лежит ключ подписи — главный остаточный риск базового слоя

`/var/lib/sbctl/keys/db/db.key` на корневой ФС, читать может только root. Root-руткит
подпишет им свою UKI — Secure Boot её пропустит. Закрытие — хранить db.key на
отдельном зашифрованном носителе, подключаемом только для подписи, и проверять
входные данные сборки UKI (`optional/sb-offline-keys`, [13](13-optional.md)).

## 5. Limine

Limine 12 (в репозитории Void) — загрузчик с меню. Его роль здесь: меню
«текущее / предыдущее ядро» и **привязка точных версий UKI по хэшу**.

`vh-limine-update` (вызывается хуком ядра) делает:

1. оставляет на ESP две последние UKI (и UKI работающего ядра), остальные удаляет;
2. подписывает UKI (`sbctl sign`);
3. пишет `/boot/efi/EFI/BOOT/limine.conf`:
   ```
   timeout: 1
   editor_enabled: no
   hash_mismatch_panic: yes
   /Void Linux 6.18.56_1
       protocol: efi
       path: boot():/EFI/void/linux-6.18.56_1.efi#<BLAKE2B-512>
   /Void Linux 6.18.55_1 (предыдущее ядро)
       ...
   ```
4. копирует чистый `/usr/share/limine/BOOTX64.EFI`, вписывает в него хэш конфига
   (`limine enroll-config BOOTX64.EFI <BLAKE2B>`), подписывает и кладёт на ESP.

Что даёт вписанный хэш при включённом Secure Boot (Limine 12, `USAGE.md`):
- конфиг сверяется с хэшем при каждой загрузке — правка = остановка;
- **редактор меню отключён принудительно** (`editor_enabled` можно не задавать);
- у всех путей обязательны хэши; для `protocol: efi` подпись проверяет ещё и прошивка;
- **measured boot включается принудительно**: Limine записывает в **PCR 8**
  командную строку и пути, а в **PCR 9** — байты limine.conf и загруженный файл.
  Следствие для tpm2-totp: PCR 8 в initramfs **не нулевой**, а PCR 9 меняется при
  каждой правке limine.conf (то есть при каждом обновлении ядра) — [13](13-optional.md).

> Почему Limine, а не две записи NVRAM прямо на UKI (`efibootmgr`)? Записи NVRAM —
> меньше компонентов, но меню выбора ядра тогда — меню прошивки (его лучше
> выключить), а хэш-привязки версии нет. Limine выбран вами; при равной защите
> промпт предлагает вариант с меньшим числом компонентов — это честная альтернатива.

Запись NVRAM создаёт установщик:

```sh
efibootmgr -c -d /dev/nvme0n1 -p 1 -L "Void Linux (Limine)" -l '\EFI\BOOT\BOOTX64.EFI'
efibootmgr -v
```

`\EFI\BOOT\BOOTX64.EFI` — ещё и путь «по умолчанию»: прошивка найдёт Limine, даже
если NVRAM сброшен.

## 6. TPM и PCR — коротко

**TPM** — отдельный (здесь — встроенный в ME) криптопроцессор. **PCR** (Platform
Configuration Register) — регистр, который нельзя записать, только «расширить»:
`PCR = SHA256(PCR || хэш_события)`. После загрузки значения PCR — отпечаток всего,
что загрузилось, по порядку. Подделать значение нельзя без подделки самих событий.

| PCR | Что измеряется |
|---|---|
| 0 | код прошивки |
| 1 | настройки прошивки, ACPI-таблицы, переменные Boot#### |
| 2 | Option ROM устройств |
| 4 | загруженные EFI-приложения (Limine, UKI) — **ловит подмену UKI** |
| 5 | таблица GPT, переменные загрузки |
| 7 | состояние Secure Boot и ключи (PK/KEK/db/dbx) |
| 8 | (Limine) cmdline и пути |
| 9 | (Limine) limine.conf и файлы; (ядро) initrd |
| 11 | секции UKI (systemd-stub) |
| 12, 13 | credentials и sysext с ESP |

Базовый слой TPM не использует для разблокировки: автоматическая расшифровка по TPM
без PIN (clevis) отдала бы ключ любому, кто включит украденный ноутбук. TPM здесь —
для **проверки целостности до ввода пароля** (tpm2-totp, [13](13-optional.md)) и журнала
Option ROM.

### MOR: очистка RAM при перезагрузке

Ядро ставит переменную `MemoryOverwriteRequestControl=1`: при следующей перезагрузке
**через прошивку** она обязана стереть RAM до загрузки чего-либо. Значит, паника
(`panic=10`) или перезагрузка не оставляют ключ LUKS в памяти для следующей
загруженной системы. Не помогает: при выключении питания (DRAM остывает секунды),
при длинном нажатии кнопки питания, при переносе модулей памяти. Проба показывает,
поддерживает ли прошивка MOR.

## 7. Восстановление

**Limine пишет о несовпадении хэша** — limine.conf или BOOTX64.EFI на ESP изменены
(или запись прервалась между ними). **Нет загрузки после регистрации ключей** —
не подписан файл или нужен хэш Option ROM.

1. **[BIOS]** Выключите Secure Boot (пароль BIOS).
2. Загрузитесь с live-флешки Void, **[LIVE]**:
   ```sh
   cryptsetup open /dev/nvme0n1p2 cryptroot
   mount -o noatime /dev/mapper/cryptroot /mnt
   mount /dev/nvme0n1p1 /mnt/boot/efi
   for d in proc sys dev run; do mount --rbind /$d /mnt/$d; done
   mount -t efivarfs efivarfs /mnt/sys/firmware/efi/efivars
   chroot /mnt /bin/bash
   xbps-reconfigure -f linux6.18          # пересобрать UKI, подписать, обновить Limine
   sbctl verify
   exit; umount -R /mnt; reboot
   ```
3. **[BIOS]** Включите Secure Boot.

Если прошивка не показывает изображение после регистрации ключей (Option ROM) — в
большинстве ноутбуков помогает сброс настроек BIOS кнопкой/перемычкой, после чего
ключи заводские; повторите регистрацию с `--tpm-eventlog`.

## Итог главы

| Защищает от | Остаточный риск | Цена в скорости | Цена в удобстве |
|---|---|---|---|
| Подмены загрузчика, ядра, initramfs, cmdline; загрузки старых shim/bootmgr (без ключей Microsoft); DMA до IOMMU | db.key на диске (root-руткит подпишет своё); прошивка без пароля BIOS; откат на старую подписанную UKI (до tpm2-totp); ME | `iommu.strict`, `init_on_free`: единицы процентов; Limine: +1 с меню | Изменения cmdline — только пересборкой UKI; обновление BIOS — с выключением Secure Boot |
