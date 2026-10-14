#!/bin/bash
# Этап 1, часть внутри chroot. Запускается из 10-install.sh — вручную не нужен.
# Каждому шагу соответствует раздел руководства (docs/…), где он разобран по командам.

. /root/vh/install/lib.sh
load_config /root/vh/vh.conf
set -a
# shellcheck source=/dev/null
. /root/vh/ids
set +a

# ---------------------------------------------------------------- хост (docs/02)
say "имя хоста, часовой пояс, локаль, раскладка"
echo "$VH_HOSTNAME" > /etc/hostname
cat > /etc/hosts <<EOF
127.0.0.1	localhost
127.0.1.1	$VH_HOSTNAME
EOF
ln -sf "/usr/share/zoneinfo/$VH_TIMEZONE" /etc/localtime
sed -i "s/^#\s*\($VH_LOCALE \)/\1/" /etc/default/libc-locales
xbps-reconfigure -f glibc-locales >/dev/null
echo "LANG=$VH_LOCALE" > /etc/locale.conf
sed -i -e "s/^#\?KEYMAP=.*/KEYMAP=\"$VH_KEYMAP\"/" -e 's/^#\?HARDWARECLOCK=.*/HARDWARECLOCK="UTC"/' /etc/rc.conf

# ---------------------------------------------------------------- PAM (docs/05)
say "PAM: yescrypt, без nullok; login.defs: umask 077"
# system-auth из pam-base: пустой пароль не принимается, хэш — yescrypt (cost 7).
sed -i -e 's/\s*nullok//' -e 's/\bsha512\b/yescrypt rounds=7/' /etc/pam.d/system-auth
grep -q 'yescrypt' /etc/pam.d/system-auth || die "system-auth: не удалось включить yescrypt"
sed -i -e 's/^UMASK.*/UMASK		077/' /etc/login.defs
grep -q '^HOME_MODE' /etc/login.defs || echo 'HOME_MODE	0700' >> /etc/login.defs

# ---------------------------------------------------------------- группы и пользователи (docs/05)
say "группы и пользователи"
for g in render netdev netdiag backlight proc xfer; do
	getent group "$g" >/dev/null || groupadd -r "$g"
done
getent group _seatd >/dev/null || die "нет группы _seatd (пакет seatd?)"
if ! id "$VH_ADMIN" >/dev/null 2>&1; then
	useradd -m -s /bin/bash -G wheel,netdiag,proc,netdev "$VH_ADMIN"
fi
if ! id "$VH_USER" >/dev/null 2>&1; then
	useradd -m -s /bin/bash -G _seatd,audio,render,netdev,backlight,netdiag,xfer "$VH_USER"
fi
if ! id "$VH_BROWSER_USER" >/dev/null 2>&1; then
	useradd -r -m -d /var/lib/vh-browser -s /usr/bin/nologin -G render,xfer "$VH_BROWSER_USER"
fi
chmod 0700 /var/lib/vh-browser "/home/$VH_ADMIN" "/home/$VH_USER"
passwd -l "$VH_BROWSER_USER" >/dev/null
# root заблокирован: администрирование — только через doas от $VH_ADMIN
passwd -l root >/dev/null

# ---------------------------------------------------------------- сгенерированные конфиги
say "sysctl (GID netdiag), blacklist модулей, fstab"
VH_NETDIAG_GID=$(getent group netdiag | cut -d: -f3)
export VH_NETDIAG_GID
render /root/vh/rootfs/etc/sysctl.d/40-vh-network.conf.cin /etc/sysctl.d/40-vh-network.conf

{
	echo "# void-hardened: дублирует module_blacklist= из cmdline (docs/03, docs/05)."
	echo "# install … /bin/false запрещает и явный «modprobe имя», а не только автозагрузку."
	vh_module_blacklist | sed 's|.*|install & /bin/false|'
} > /etc/modprobe.d/vh-blacklist.conf

[ "$VH_GPU" = igpu ] || rm -f /etc/udev/rules.d/99-vh-dgpu-off.rules

ESP_DEV="UUID=$VH_ESP_UUID"
HOME_OPTS="bind,nosuid,nodev"
[ "$VH_HOME_NOEXEC" = yes ] && HOME_OPTS="$HOME_OPTS,noexec"
cat > /etc/fstab <<EOF
# void-hardened: файловые системы (docs/01, docs/05).
# /proc, /dev, /dev/shm и /run монтирует runit до fstab — их опции задаёт
# /etc/runit/core-services/04-vh-mounts.sh.
#
# корень: XFS в LUKS2. logbsize задаётся в cmdline (rootflags=): при remount он не меняется
UUID=$VH_ROOT_UUID	/		xfs	rw,noatime	0 0
# ESP монтируется только на время обновления ядра (хуки /etc/kernel.d)
$ESP_DEV	/boot/efi	vfat	noauto,nosuid,nodev,noexec,fmask=0177,dmask=0077	0 0
# временные каталоги в RAM: без исполнения, с ограничением размера
tmpfs		/tmp		tmpfs	nosuid,nodev,noexec,mode=1777,size=25%	0 0
tmpfs		/var/tmp	tmpfs	nosuid,nodev,noexec,mode=1777,size=10%	0 0
# опции через bind-mount (это не отдельные ФС)
/home		/home		none	$HOME_OPTS	0 0
/home/xfer	/home/xfer	none	bind,nosuid,nodev,noexec,nosymfollow	0 0
/var/lib/vh-browser	/var/lib/vh-browser	none	bind,nosuid,nodev,noexec	0 0
EOF
if [ -n "$VH_DEV_DIR" ]; then
	install -d -m 0700 -o "$VH_USER" -g "$VH_USER" "/home/$VH_USER/$VH_DEV_DIR"
	printf '%s\t%s\tnone\tbind,nosuid,nodev\t0 0\n' "/home/$VH_USER/$VH_DEV_DIR" "/home/$VH_USER/$VH_DEV_DIR" >> /etc/fstab
fi

# ---------------------------------------------------------------- сеть (docs/06, docs/07)
say "unbound, chrony, iwd, resolv.conf"
install -d -m 0750 -o _unbound -g _unbound /etc/unbound/var
anchor=""
for f in /etc/dns/root.key /usr/share/dnssec-anchors/root.key /etc/unbound/root.key; do
	[ -s "$f" ] && { anchor=$f; break; }
done
[ -n "$anchor" ] || die "нет корневого ключа DNSSEC (пакет dnssec-anchors)"
install -m 0640 -o _unbound -g _unbound "$anchor" /etc/unbound/var/root.key
install -m 0644 /etc/ssl/certs/ca-certificates.crt /etc/unbound/ca-bundle.pem
unbound-checkconf /etc/unbound/unbound.conf >/dev/null || die "unbound.conf с ошибкой"
install -d -m 0750 -o chrony -g chrony /var/lib/chrony
install -d -m 0700 /var/lib/iwd
nft -c -f /etc/nftables.conf || die "nftables.conf с ошибкой"

# ---------------------------------------------------------------- сервисы runit (docs/05)
say "сервисы runit"
SVDIR=/etc/runit/runsvdir/default
for t in 3 4 5 6; do rm -f "$SVDIR/agetty-tty$t"; done
enable_sv() { [ -d "/etc/sv/$1" ] || die "нет сервиса $1"; ln -sfn "/etc/sv/$1" "$SVDIR/$1"; }
for s in agetty-tty1 agetty-tty2 udevd dbus iwd unbound chronyd seatd socklog-unix nanoklogd vh-acpid; do
	enable_sv "$s"
done
case $VH_ETH in
	dhcp) enable_sv dhcpcd-eth0 ;;
	static) enable_sv vh-eth-static ;;
esac
[ "$VH_TRIM" = yes ] && enable_sv vh-fstrim
if [ "${VH_TEST_SERIAL:-no}" = yes ]; then
	# стенд tests/vm: вход админа на ttyS0 (на железе не включать)
	enable_sv agetty-ttyS0
	sed -i "/^- : ALL : ALL/i + : $VH_ADMIN : ttyS0" /etc/security/access.conf
fi
[ "$VH_BLUETOOTH" = on ] && enable_sv bluetoothd
for s in sshd dhcpcd wpa_supplicant acpid; do rm -f "$SVDIR/$s"; done

# ---------------------------------------------------------------- рабочий стол (docs/08)
say "PipeWire, домашние каталоги, общий каталог загрузок"
install -d /etc/pipewire/pipewire.conf.d
ln -sf /usr/share/examples/wireplumber/10-wireplumber.conf /etc/pipewire/pipewire.conf.d/
ln -sf /usr/share/examples/pipewire/20-pipewire-pulse.conf /etc/pipewire/pipewire.conf.d/

# Каталог обмена с браузером: группа xfer (пользователь и браузер), setgid,
# ACL по умолчанию — чтобы файл, скачанный с umask 077, был доступен обоим.
install -d -m 2770 -o "$VH_BROWSER_USER" -g xfer /home/xfer
setfacl -m "d:u:$VH_USER:rwX,d:u:$VH_BROWSER_USER:rwX,d:g:xfer:rwX,d:m::rwX" /home/xfer

uh=/home/$VH_USER
install -d -m 0700 -o "$VH_USER" -g "$VH_USER" "$uh/.config" "$uh/.config/mango" \
	"$uh/.config/foot" "$uh/.config/netline" "$uh/Pictures" "$uh/Pictures/wallpapers"
install -m 0600 -o "$VH_USER" -g "$VH_USER" /etc/vh/skel/mango-config.conf "$uh/.config/mango/config.conf"
install -m 0600 -o "$VH_USER" -g "$VH_USER" /etc/vh/skel/foot.ini "$uh/.config/foot/foot.ini"
ln -sfn /home/xfer "$uh/Downloads"
chown -h "$VH_USER:$VH_USER" "$uh/Downloads"

# ---------------------------------------------------------------- загрузка (docs/03)
say "dracut-uefi как провайдер initramfs; ключи Secure Boot"
xbps-alternatives -s dracut-uefi >/dev/null
install -d -m 0700 /var/cache/apparmor
if [ ! -e /var/lib/sbctl/keys/db/db.key ]; then
	sbctl create-keys
fi
chmod -R go-rwx /var/lib/sbctl

# ---------------------------------------------------------------- SUID (docs/05)
say "SUID и capabilities"
/usr/local/sbin/vh-suid-strip

# ---------------------------------------------------------------- пароли (docs/01, docs/05)
say "пароли"
if [ -n "${VH_TEST_PASSWORD:-}" ]; then
	# автотесты в VM: один и тот же пароль у обоих
	h=$(printf '%s' "$VH_TEST_PASSWORD" | python3 -I /root/vh/tools/vh-hashpw 7)
	usermod -p "$h" "$VH_ADMIN"
	usermod -p "$h" "$VH_USER"
else
	echo "Пароли админа и пользователя — разные и не совпадают с паролем LUKS (docs/01)."
	until passwd "$VH_ADMIN"; do echo "ещё раз"; done
	until passwd "$VH_USER"; do echo "ещё раз"; done
fi
for u in "$VH_ADMIN" "$VH_USER"; do
	case $(getent shadow "$u" | cut -d: -f2) in
		'$y$'*) ;;
		*) die "пароль $u не в формате yescrypt" ;;
	esac
done

ok "chroot: настройка завершена"
