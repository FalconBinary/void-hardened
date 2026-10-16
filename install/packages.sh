# shellcheck shell=bash
# Список пакетов целевой системы. Вместо base-system — явный минимальный набор:
# base-system тянет sudo, dhcpcd, wpa_supplicant, openssh, btrfs/f2fs-progs и т. п.
# Обоснование каждого пакета — docs/02-bootstrap.md.
# thor — xbps с политикой void-hardened (docs/18); собирается install/build-thor.sh и
# ставится из локального репозитория /var/lib/thor/repo, заменяя xbps и libxbps.

vh_packages() {
	local p=(
		# --- основа: то, что нужно любой системе Void
		base-files thor runit-void removed-packages
		coreutils findutils diffutils dash bash grep gzip sed gawk less which tar
		util-linux shadow procps-ng iana-etc tzdata glibc-locales ncurses kbd
		kmod eudev iproute2 iputils libcap-progs ethtool iw pciutils usbutils
		mdocml man-pages nvi
		# --- ядро, прошивки, микрокод
		"$VH_KERNEL" linux-firmware-intel linux-firmware-network wireless-regdb intel-ucode
		# --- загрузка: UKI, Secure Boot, шифрование, ФС
		dracut dracut-uefi systemd-boot-efistub zstd lz4
		cryptsetup xfsprogs dosfstools efibootmgr limine sbctl tpm2-tools
		# --- безопасность и сервисы
		opendoas dumb_runtime_dir apparmor bubblewrap acl-progs
		socklog-void dbus iwd nftables unbound chrony
		# --- рабочий стол
		seatd mangowc foot swaylock swayidle wl-clipboard
		mesa-dri intel-media-driver
		pipewire wireplumber alsa-utils
		firefox libavcodec6 dejavu-fonts-ttf
	)
	[ "$VH_ETH" = dhcp ] && p+=(dhcpcd)
	[ "$VH_BLUETOOTH" != off ] && p+=(bluez)
	[ "$VH_GPU" = nouveau ] && p+=(linux-firmware-nvidia mesa-vulkan-nouveau)
	printf '%s\n' "${p[@]}"
}
