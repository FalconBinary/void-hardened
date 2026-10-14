# void-hardened

Защищённый, быстрый и минималистичный **Void Linux** для ноутбука — установщик и
подробное руководство для ручной установки.

*A hardened, fast and minimal Void Linux setup for a laptop: LUKS2 + signed UKI + own
Secure Boot keys + Limine, runit, seatd + MangoWM + the netline bar, a sandboxed browser,
DoT DNS and NTS time. An installer script plus a step-by-step guide (in Russian).*

```
Limine (подписан, хэш конфига вписан) → UKI (ядро + initramfs + cmdline, подписана своим ключом)
  → пароль LUKS2 (Argon2id) → runit → seatd → mango + netline → браузер в песочнице
```

## Что получается

| Область | Что сделано |
|---|---|
| Загрузка | UKI через dracut-uefi, **свои ключи Secure Boot без сертификатов Microsoft** (sbctl, с учётом Option ROM), Limine с BLAKE2B-хэшами UKI и вписанным хэшем конфига, cmdline только из подписанной UKI |
| Диск | GPT: ESP + LUKS2 (aes-xts 512, Argon2id 1 ГиБ / 3 с, сектор 4K, без workqueue) + XFS; swap только в zram |
| Ядро | штатное `linux6.18`: lockdown=confidentiality, AppArmor + Landlock + Yama, IOMMU strict, init_on_free, запрет редких модулей, после старта — `modules_disabled=1`, sysctl с комментарием к каждой строке |
| Сеть | nftables «запрещено всё, кроме разрешённого» по UID программы, iwd (WPA3, PMF, случайный MAC на сеть), unbound (DNSSEC, только DoT, защита от DNS rebinding), chrony только с NTS, IPv6 выключен |
| Рабочий стол | seatd (без elogind и polkit) + **mango** + **netline** (панель на Zig, 0 пробуждений в простое), swaylock/swayidle, PipeWire |
| Браузер | Firefox от отдельного пользователя в bwrap без user namespace, Wayland только через фильтрующий прокси (в mango нет security-context), звук без микрофона, AppArmor, политики, одноразовый профиль без JIT для недоверенных сайтов |
| Удобство | крышка → блокировка, кнопка питания → штатное выключение, яркость и звук без root, Bluetooth по требованию, обновление одной командой `doas vh-update`, проверка всего — `doas vh-audit` |
| Минимализм | ~13 сервисов, нет systemd, polkit, sudo, ssh-сервера, cron, компиляторов; прошивки — только нужные этому ноутбуку |

Параноидальные слои (включаются отдельно): строгая сеть, пиннинг УЦ для DNS/NTS, защита
от BadUSB, FIDO2, ключи Secure Boot на отдельной флешке с проверкой сборки UKI,
tpm2-totp (проверка загрузки до пароля), dead man's switch (стирание ключа LUKS из RAM),
сеанс в пустом netns, AppArmor на весь сеанс, просмотрщики в песочнице, закрытый $HOME —
[docs/13-optional.md](docs/13-optional.md).

## Для какого железа

Написано и проверено на стенде для **MSI GF63 Thin 10SCXR/10SCSR (MS-16R5)**:
Intel Core i5-10500H, UHD 630 + GTX 1650 Max-Q, Intel AX201 (Wi-Fi 6 + BT),
Realtek RTL8111, NVMe, UEFI с TPM 2.0 (PTT). Подойдёт для похожих ноутбуков на Intel с
UEFI — различия задаются в `vh.conf`, а `install/00-probe.sh` перед установкой покажет,
что нужно поменять.

GTX 1650 по умолчанию **обесточена**: проприетарный драйвер NVIDIA в Void собирается
через DKMS, а неподписанный модуль lockdown не загрузит. Нужна dGPU (внешний монитор на
HDMI, разведённом на NVIDIA) — `VH_GPU=nouveau` (глава [04](docs/04-gpu.md)).

## Быстрый старт: автоматическая установка

**Перед началом:** обновите BIOS, сохраните данные — диск будет стёрт целиком. Прочтите
хотя бы [главу 00](docs/00-prepare.md): модель угроз, настройки BIOS, проверка образа.

1. **Образ.** Скачайте `void-live-x86_64-<дата>-base.iso` с
   `https://repo-default.voidlinux.org/live/current/`, **проверьте подпись** (minisign,
   ключ — по двум каналам: [00, раздел 4](docs/00-prepare.md#4-скачивание-и-проверка-образа)),
   запишите на флешку.
2. **BIOS.** UEFI без CSM, Secure Boot **выключен** на время установки, PTT включён,
   VT-d включён ([таблица для MSI GF63](docs/00-prepare.md#msi-gf63-thin-10scxr--10scsr-ms-16r5--где-что-лежит)).
3. **Live-среда.** Загрузитесь с флешки, войдите `root` / `voidlinux`, подключите сеть
   (кабель — сам; Wi-Fi — `wpa_supplicant`, [00, раздел 5](docs/00-prepare.md#5-загрузка-live-среды)):
   ```sh
   xbps-install -Syu xbps && xbps-install -Sy git
   git clone https://github.com/FalconBinary/void-hardened.git && cd void-hardened
   ./install/00-probe.sh --install-tools      # проба железа: ничего не пишет, даёт рекомендации
   cp vh.conf.example vh.conf && vi vh.conf   # минимум: VH_DISK="/dev/nvme0n1"
   ./install/10-install.sh --dry-run          # план без изменений
   ./install/10-install.sh                    # установка (~15–30 мин)
   ```
   Установщик спросит пароль LUKS (diceware от 7 слов) и пароли админа и пользователя —
   все разные.
4. **Первая загрузка.** Выньте флешку. Limine → пароль LUKS → на **tty2** войдите как
   `admin` и запустите `doas /root/vh/install/20-firstboot.sh` — проверка базового слоя.
5. **Secure Boot.** В BIOS: пароль администратора, «Delete All Secure Boot Variables»
   (Setup Mode). Загрузитесь, снова `20-firstboot.sh` — он запишет ваши ключи. В BIOS
   включите Secure Boot, выключите загрузку с USB. Ещё раз `20-firstboot.sh` — проверка
   подписей ([03](docs/03-boot.md)).
6. **Блокировка модулей.** За одну загрузку воспользуйтесь всем железом (Wi-Fi, флешка,
   наушники, внешний монитор…), затем `doas /root/vh/install/30-lock.sh` и перезагрузка
   ([05](docs/05-system.md#4-модули-ядра)).
7. **Работа.** На **tty1** входит пользователь — сразу mango. Клавиши — [12](docs/12-daily.md).
   Проверка всего: `doas vh-audit`. Обновления: `doas vh-update`.

## Ручная установка — учебник

[docs/README.md](docs/README.md) — руководство в порядке установки. Каждый шаг
установщика разобран: зачем он нужен, как сделать то же руками, как проверить и чем
приходится платить. Цель — после прочтения понимать систему настолько, чтобы собрать
её без скрипта, найти поломку и осознанно менять решения.

| Глава | О чём |
|---|---|
| [00](docs/00-prepare.md) | модель угроз, железо, BIOS (MSI GF63), проверка образа, проба, VM-стенд |
| [01](docs/01-disk.md) | GPT, LUKS2 изнутри, Argon2id и энтропия, TRIM, XFS, бэкап заголовка |
| [02](docs/02-bootstrap.md) | xbps, ключи, ignorepkg/noextract, минимальный набор пакетов, chroot |
| [03](docs/03-boot.md) | UKI, cmdline, Secure Boot со своими ключами, Option ROM, Limine, PCR, MOR |
| [04](docs/04-gpu.md) | iGPU/dGPU, обесточивание GTX 1650, nouveau/NVK |
| [05](docs/05-system.md) | runit, монтирование, sysctl, модули ядра, пользователи, PAM, doas, SUID |
| [06](docs/06-network.md) | nftables, iwd, unbound (DoT, DNSSEC), chrony (NTS), DHCP, Bluetooth |
| [07](docs/07-network-speed.md) | BBR, буферы, сканирование и роуминг Wi-Fi, замеры |
| [08](docs/08-desktop.md) | seatd, mango, безопасность Wayland, фильтр, песочница браузера, netline |
| [09](docs/09-updates.md) | обновления, хуки ядра, подпись, откат, атака заморозки |
| [10](docs/10-audit.md) | чек-лист, журналы, целостность, бэкапы |
| [11](docs/11-performance.md) | профили питания, CPU, память, накопитель, загрузка, запрещённые ускорения |
| [12](docs/12-daily.md) | повседневная работа без админа |
| [13](docs/13-optional.md) | параноидальные слои |
| [14](docs/14-prompt-review.md) | разбор исходного промпта: недочёты и решения |
| [15](docs/15-cachyos.md) | производительность против CachyOS: честное сравнение и `tools/vh-bench` |

## Структура репозитория

```
install/        00-probe.sh (проба) · 10-install.sh (установка) · chroot.sh · 20-firstboot.sh
                (Secure Boot) · 30-lock.sh (modules_disabled) · build-netline.sh · lib.sh · packages.sh
rootfs/         файлы, которые ложатся в систему (*.in — шаблоны с @VH_*@ из vh.conf)
optional/       параноидальные модули: <модуль>/enable, disable; status
tools/          vh-bench (сравнение скорости), vh-hashpw (только для тестов)
tests/vm/       стенд qemu + OVMF (Secure Boot) + swtpm: автоматическая установка и проверка
docs/           руководство
vh.conf.example все настройки установщика с объяснениями
```

## Честные оговорки

- **Проверено на стенде, не на всех ноутбуках.** Установка, загрузка через Limine → UKI →
  LUKS и базовые проверки прогоняются в VM (`tests/vm`). Wi-Fi, датчик крышки, iTCO, MOR,
  Option ROM, разводку HDMI проверяет только ваше железо — смотрите отчёт пробы и
  `vh-audit`.
- **Netline собирается компилятором Zig 0.16**, которого нет в репозитории Void (там 0.13):
  компилятор скачивается с ziglang.org в RAM live-среды, проверяется подписью minisign и
  хэшем и в систему не попадает ([ВНЕ ОГРАНИЧЕНИЙ], [08](docs/08-desktop.md)).
  `VH_NETLINE=no` — без панели.
- **Против CachyOS** в синтетике CPU эта система медленнее на единицы процентов (у них
  пакеты под x86-64-v3 и ядро с BORE/LTO; здесь включены меры защиты с ценой); в загрузке,
  памяти, отклике и батарее — не хуже. Подробно и с замером — [15](docs/15-cachyos.md).
- **Нет suspend** (ключ LUKS в RAM): крышка блокирует экран, а закрытая дольше 10 минут —
  штатно выключает ноутбук.
- Абсолютной безопасности не существует: остаточные риски названы в конце каждой главы.

## Лицензия

[GPL-3.0](LICENSE). Пакеты Void, ядро Linux, Firefox и прочее — под своими лицензиями.
