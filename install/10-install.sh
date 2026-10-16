#!/bin/bash
# Этап 1: установка с live-флешки Void (glibc, x86_64), от root.
#
#   cp vh.conf.example vh.conf && vi vh.conf      — минимум: VH_DISK
#   ./install/10-install.sh --dry-run             — показать план, ничего не меняя
#   ./install/10-install.sh                       — установить
#
# Что делает (руками то же самое — docs/01…docs/03):
#   1. размечает диск GPT: ESP (FAT32) + LUKS2 (XFS внутри), без swap-раздела;
#   2. собирает thor (xbps + политика безопасности, docs/18) в RAM live-среды и ставит
#      через него пакеты в /mnt с HTTPS-зеркала — параллельно, ключи xbps — из live-среды;
#   3. собирает netline компилятором Zig в RAM live-среды (в систему он не попадает);
#   4. в chroot настраивает систему (install/chroot.sh): пользователи, PAM, сеть,
#      sysctl, AppArmor, UKI, ключи Secure Boot, Limine, запись в NVRAM.
#
# Secure Boot во время установки должен быть ВЫКЛЮЧЕН (live-образ Void не подписан).
# Регистрация своих ключей — этап 2 (install/20-firstboot.sh) после первой загрузки.

. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/packages.sh"

CFG=$VH_ROOT/vh.conf
while [ $# -gt 0 ]; do
	case $1 in
		--dry-run) DRY_RUN=1 ;;
		--config) CFG=$2; shift ;;
		-h|--help) sed -n '2,20p' "$0"; exit 0 ;;
		*) die "неизвестный аргумент: $1" ;;
	esac
	shift
done

need_root
load_config "$CFG"
MNT=/mnt
REPO=$VH_MIRROR/current
NONFREE=$VH_MIRROR/current/nonfree

# ---------------------------------------------------------------- проверки
say "проверки"
[ -d /sys/firmware/efi/efivars ] || die "загрузка не в режиме UEFI"
[ "$(uname -m)" = x86_64 ] || die "нужен x86_64"
[ -n "$VH_DISK" ] || die "в vh.conf не задан VH_DISK"
[ -b "$VH_DISK" ] || die "$VH_DISK — не блочное устройство"
case $(lsblk -dno TYPE "$VH_DISK") in disk) ;; *) die "$VH_DISK — не целый диск" ;; esac
if lsblk -no MOUNTPOINTS "$VH_DISK" 2>/dev/null | grep -q .; then
	die "на $VH_DISK есть смонтированные разделы (это не live-флешка?)"
fi
size_gib=$(( $(blockdev --getsize64 "$VH_DISK") / 1073741824 ))
[ "$size_gib" -ge 20 ] || die "диск меньше 20 ГиБ"
sb=$(od -An -t u1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | tr -d ' ')
[ "${sb:-0}" = 0 ] || warn "Secure Boot включён — live-образ не мог так загрузиться; проверьте прошивку"
ESP_PART=$(part "$VH_DISK" 1)
LUKS_PART=$(part "$VH_DISK" 2)
ok "диск $VH_DISK, $size_gib ГиБ: $ESP_PART (ESP $VH_ESP_SIZE) + $LUKS_PART (LUKS2)"

cat <<EOF

План установки:
  диск            $VH_DISK ($(lsblk -dno MODEL "$VH_DISK"))  — ВСЁ БУДЕТ СТЁРТО
  хост            $VH_HOSTNAME, $VH_TIMEZONE, $VH_LOCALE, раскладка $VH_KEYMAP, домен Wi-Fi $VH_REGDOM
  пользователи    $VH_ADMIN (админ, tty2), $VH_USER (tty1), $VH_BROWSER_USER (браузер)
  ядро            $VH_KERNEL, initramfs $VH_INITRD_COMPRESS, Limine timeout $VH_LIMINE_TIMEOUT
  GPU             $VH_GPU   Bluetooth $VH_BLUETOOTH   Ethernet $VH_ETH   IPv6 $VH_IPV6
  TRIM            $VH_TRIM  zram $VH_ZRAM_ALGO ${VH_ZRAM_PERCENT}%
  netline         $VH_NETLINE ($VH_NETLINE_REF)
  зеркало         $VH_MIRROR
EOF
[ "$DRY_RUN" = 1 ] || confirm_exact "$VH_DISK" "Данные на $VH_DISK будут уничтожены безвозвратно."

# ---------------------------------------------------------------- live-среда
say "утилиты live-среды (ставятся в RAM)"
run xbps-install -Syu xbps
run xbps-install -Sy cryptsetup xfsprogs dosfstools
run xbps-install -Sy minisign xz
[ "$VH_NETLINE" = yes ] && run xbps-install -Sy git

# ---------------------------------------------------------------- разметка
say "разметка $VH_DISK (GPT: ESP + LUKS2)"
run wipefs -af "$VH_DISK"
if [ "$VH_TRIM" = yes ]; then
	# Сообщить SSD, что все блоки свободны: старые данные недоступны через интерфейс
	# диска и не мешают выравниванию износа. Это не гарантированное стирание (docs/01).
	run blkdiscard -f "$VH_DISK" || warn "blkdiscard не поддерживается — пропущено"
fi
if [ "$DRY_RUN" = 1 ]; then
	echo "   + sfdisk $VH_DISK (ESP $VH_ESP_SIZE, остальное — LUKS)"
else
	sfdisk --wipe always --wipe-partitions always "$VH_DISK" <<EOF
label: gpt
size=$VH_ESP_SIZE, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="ESP"
type=CA7D7CCB-63ED-4C53-861C-1742536059CC, name="cryptroot"
EOF
	udevadm settle
	for _ in 1 2 3 4 5; do [ -b "$LUKS_PART" ] && break; sleep 1; done
	[ -b "$LUKS_PART" ] || die "раздел $LUKS_PART не появился"
fi

# ---------------------------------------------------------------- LUKS2
say "LUKS2: aes-xts-plain64, 512 бит, сектор 4096, Argon2id (${VH_LUKS_ITER_MS} мс, $((VH_LUKS_MEM_KIB/1024)) МиБ)"
LUKS_ARGS=(--type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512
	--pbkdf argon2id --pbkdf-memory "$VH_LUKS_MEM_KIB" --pbkdf-parallel 4
	--iter-time "$VH_LUKS_ITER_MS" --sector-size 4096 --label cryptroot)
OPEN_ARGS=(--perf-no_read_workqueue --perf-no_write_workqueue --persistent)
[ "$VH_TRIM" = yes ] && OPEN_ARGS+=(--allow-discards)
if [ -n "${VH_TEST_PASSPHRASE:-}" ]; then
	# Только для автоматических тестов в VM (tests/vm). На реальной машине — вручную.
	run_key() { printf '%s' "$VH_TEST_PASSPHRASE" | "$@" --key-file=-; }
	[ "$DRY_RUN" = 1 ] || run_key cryptsetup luksFormat -q "${LUKS_ARGS[@]}" "$LUKS_PART"
	[ "$DRY_RUN" = 1 ] || run_key cryptsetup open "${OPEN_ARGS[@]}" "$LUKS_PART" cryptroot
else
	echo "Пароль LUKS: diceware от 7 слов (docs/01). Вводится только в initramfs при загрузке."
	run cryptsetup luksFormat "${LUKS_ARGS[@]}" "$LUKS_PART"
	run cryptsetup open "${OPEN_ARGS[@]}" "$LUKS_PART" cryptroot
fi

# ---------------------------------------------------------------- файловые системы
say "файловые системы"
run mkfs.vfat -F 32 -n ESP "$ESP_PART"
run mkfs.xfs -f -L voidroot -s size=4096 /dev/mapper/cryptroot
run mount -o noatime,logbsize=256k /dev/mapper/cryptroot "$MNT"
run mkdir -p "$MNT/boot/efi"
run mount -o nosuid,nodev,noexec,fmask=0177,dmask=0077 "$ESP_PART" "$MNT/boot/efi"

if [ "$DRY_RUN" = 1 ]; then
	VH_LUKS_UUID=DRYRUN-LUKS VH_ROOT_UUID=DRYRUN-ROOT VH_ESP_UUID=DRYRUN-ESP
else
	VH_LUKS_UUID=$(cryptsetup luksUUID "$LUKS_PART")
	VH_ROOT_UUID=$(blkid -s UUID -o value /dev/mapper/cryptroot)
	VH_ESP_UUID=$(blkid -s UUID -o value "$ESP_PART")
fi
export VH_LUKS_UUID VH_ROOT_UUID VH_ESP_UUID
VH_CMDLINE=$(vh_cmdline)
# Значения для шаблонов rootfs/*.in, вычисляемые из vh.conf
for u in $VH_DNS_UPSTREAMS; do
	[[ $u =~ ^[0-9.]+@853#[A-Za-z0-9.-]+$ ]] || die "VH_DNS_UPSTREAMS: «$u» — нужен формат IP@853#имя"
done
VH_DOT_IPS=$(for u in $VH_DNS_UPSTREAMS; do echo "${u%%@*}"; done | sort -u | paste -sd, - | sed 's/,/, /g')
VH_UNBOUND_FORWARDS=$(for u in $VH_DNS_UPSTREAMS; do printf '\tforward-addr: %s\n' "$u"; done)
VH_CHRONY_SERVERS=$(for s in $VH_NTS_SERVERS; do printf 'server %s iburst nts\n' "$s"; done)
VH_SHM_SIZE="25%"
if [ "$VH_IPV6" = no ]; then
	# IPv6 выключен в ядре: адреса AAAA из ответов вырезаются (как «частные») — программы
	# не тратят время на попытки IPv6, которые не могут удаться
	VH_UNBOUND_AAAA=$'\t# IPv6 выключен (VH_IPV6=no): записи AAAA не отдаются\n\tprivate-address: ::/0'
else
	VH_UNBOUND_AAAA=""
fi
export VH_CMDLINE VH_DOT_IPS VH_UNBOUND_FORWARDS VH_CHRONY_SERVERS VH_SHM_SIZE VH_UNBOUND_AAAA
ok "LUKS $VH_LUKS_UUID, корень $VH_ROOT_UUID, ESP $VH_ESP_UUID"

# ---------------------------------------------------------------- bootstrap
say "xbps: ключи репозитория из проверенной live-среды и конфиги xbps.d"
run mkdir -p "$MNT/var/db/xbps/keys" "$MNT/etc/xbps.d"
run cp -a /var/db/xbps/keys/. "$MNT/var/db/xbps/keys/"
# xbps.d кладём ДО установки: ignorepkg и noextract действуют уже на bootstrap.
for f in "$VH_ROOT"/rootfs/etc/xbps.d/*; do
	b=$(basename "$f")
	if [ "$DRY_RUN" = 1 ]; then echo "   + render /etc/xbps.d/${b%.in}"; continue; fi
	case $b in
		*.in) render "$f" "$MNT/etc/xbps.d/${b%.in}" ;;
		*) install -m 0644 "$f" "$MNT/etc/xbps.d/$b" ;;
	esac
done
if [ "$VH_FIRMWARE_TRIM" = yes ]; then
	if [ "$DRY_RUN" = 1 ]; then echo "   + /etc/xbps.d/40-vh-firmware.conf (только нужные прошивки)"
	else vh_firmware_noextract > "$MNT/etc/xbps.d/40-vh-firmware.conf"; fi
fi

say "thor: сборка в RAM live-среды (docs/18)"
run bash "$VH_ROOT/install/build-thor.sh" "$MNT"
THOR=/tmp/vh-thor/dest/usr/bin/thor
# Политика thor на время установки — в режиме learn: хуки ядра, модули dracut, sysctl.d
# и правила udev пакетов базовой системы записываются в /etc/thor/baseline, а не
# обезвреживаются. SUID/SGID, capabilities и чёрный список действуют уже сейчас.
if [ "$DRY_RUN" = 1 ]; then echo "   + /etc/thor/policy.conf: mode=learn"
else printf '# thor (docs/18): enforce — политика действует; learn — только при установке системы\nmode=learn\n' > "$MNT/etc/thor/policy.conf"; fi
thor_install() {
	# libxbps с политикой программы берут из своего дерева (rpath $ORIGIN/../lib)
	run env XBPS_ARCH=x86_64 "$THOR" install -y -r "$MNT" -R "$REPO" -R "$NONFREE" "$@"
}

say "установка пакетов ($(vh_packages | wc -l) шт. + зависимости), без ядра — thor, параллельно"
# Ядро ставится последним, уже после настройки (ниже): тогда его хуки сразу соберут
# UKI нужным dracut-uefi, подпишут её готовыми ключами и пропишут в Limine.
mapfile -t PKGS < <(vh_packages | grep -vx "$VH_KERNEL")
thor_install "${PKGS[@]}"

# ---------------------------------------------------------------- netline
if [ "$VH_NETLINE" = yes ]; then
	say "netline: сборка в RAM live-среды"
	run bash "$VH_ROOT/install/build-netline.sh" "$MNT"
fi

# ---------------------------------------------------------------- файлы конфигурации
say "файлы конфигурации (rootfs/)"
install_tree "$VH_ROOT/rootfs" "$MNT"
run install -d -m 0700 "$MNT/root/vh"
run cp -a "$VH_ROOT/install" "$VH_ROOT/tools" "$VH_ROOT/rootfs" "$VH_ROOT/optional" \
	"$VH_ROOT/src" "$VH_ROOT/zig" "$VH_ROOT/thor" "$VH_ROOT/vh.conf.example" "$MNT/root/vh/"
# инструменты на C: компилятор — только в RAM live-среды, в систему — готовые программы
run bash "$VH_ROOT/install/build-tools.sh" "$MNT"
[ -f "$CFG" ] && run install -m 0600 "$CFG" "$MNT/root/vh/vh.conf"
if [ "$DRY_RUN" != 1 ]; then
	printf 'VH_LUKS_UUID=%s\nVH_ROOT_UUID=%s\nVH_ESP_UUID=%s\nVH_DISK=%s\n' \
		"$VH_LUKS_UUID" "$VH_ROOT_UUID" "$VH_ESP_UUID" "$VH_DISK" > "$MNT/root/vh/ids"
fi

# ---------------------------------------------------------------- chroot
say "настройка в chroot"
chroot_mounts() {
	run mount -t proc proc "$MNT/proc"
	run mount -t sysfs sys "$MNT/sys"
	run mount -t efivarfs efivarfs "$MNT/sys/firmware/efi/efivars"
	run mount --rbind /dev "$MNT/dev"
	run mount --make-rslave "$MNT/dev"
	run mount -t tmpfs -o mode=0755,nosuid,nodev run "$MNT/run"
	if [ -e /sys/kernel/security/tpm0 ]; then
		run mount -t securityfs securityfs "$MNT/sys/kernel/security"
	fi
}
chroot_mounts
run env -i PATH=/usr/bin:/usr/sbin HOME=/root TERM="${TERM:-linux}" \
	VH_TEST_PASSWORD="${VH_TEST_PASSWORD:-}" VH_YES="${VH_YES:-0}" \
	chroot "$MNT" /bin/bash /root/vh/install/chroot.sh

# ---------------------------------------------------------------- ядро и загрузчик
say "ядро $VH_KERNEL: dracut-uefi → UKI → подпись → limine.conf → Limine"
thor_install "$VH_KERNEL"
if [ "$DRY_RUN" != 1 ]; then
	ls "$MNT"/boot/efi/EFI/void/linux-*.efi >/dev/null 2>&1 || die "UKI не создана (см. вывод dracut выше)"
	[ -s "$MNT/boot/efi/EFI/BOOT/BOOTX64.EFI" ] && [ -s "$MNT/boot/efi/EFI/BOOT/limine.conf" ] \
		|| die "Limine не установлен на ESP (vh-limine-update)"
	ok "$(ls "$MNT"/boot/efi/EFI/void/)"
fi

say "запись загрузки в NVRAM"
# Старые записи с тем же именем удаляются, чтобы не копились при переустановке.
if [ "$DRY_RUN" != 1 ]; then
	chroot "$MNT" efibootmgr | sed -n 's/^Boot\([0-9A-F]\{4\}\)\*\? Void Linux (Limine).*/\1/p' \
		| while read -r n; do chroot "$MNT" efibootmgr -q -b "$n" -B; done
fi
run chroot "$MNT" efibootmgr -q -c -d "$VH_DISK" -p 1 -L "Void Linux (Limine)" -l '\EFI\BOOT\BOOTX64.EFI'

# Кэш пакетов (~1,5 ГБ) на целевой системе не нужен.
run rm -rf "$MNT/var/cache/xbps"

say "политика thor: enforce (базовый список — $(grep -vc '^#' "$MNT/etc/thor/baseline" 2>/dev/null || echo 0) записей)"
if [ "$DRY_RUN" = 1 ]; then echo "   + /etc/thor/policy.conf: mode=enforce"
else printf '# thor (docs/18): enforce — политика действует; learn — только при установке системы\nmode=enforce\n' > "$MNT/etc/thor/policy.conf"; fi

# ---------------------------------------------------------------- итог
say "готово"
cat <<EOF

Установка завершена. Дальше:
  1. Сохраните заголовок LUKS на внешний носитель (docs/01):
       cryptsetup luksHeaderBackup $LUKS_PART --header-backup-file /путь/на/флешке/luks-header.img
  2. Отмонтируйте и перезагрузитесь:
       umount -R $MNT && cryptsetup close cryptroot && reboot
  3. Выньте флешку. Загрузка: Limine → UKI → пароль LUKS → вход.
  4. Войдите на tty2 как $VH_ADMIN и запустите этап 2:
       doas /root/vh/install/20-firstboot.sh     (подробно — docs/03)
EOF
