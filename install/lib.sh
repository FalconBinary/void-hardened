# shellcheck shell=bash
# Общие функции установщика. Подключается через «. lib.sh».

set -euo pipefail
umask 022

VH_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [ -t 1 ]; then
	C_B=$'\e[1m' C_R=$'\e[31m' C_G=$'\e[32m' C_Y=$'\e[33m' C_0=$'\e[0m'
else
	C_B="" C_R="" C_G="" C_Y="" C_0=""
fi

say()  { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s  !!%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%sОШИБКА:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

# В режиме --dry-run команды печатаются, но не выполняются.
DRY_RUN=${DRY_RUN:-0}
run() {
	if [ "$DRY_RUN" = 1 ]; then
		printf '   + %s\n' "$*"
	else
		"$@"
	fi
}

need_root() { [ "$(id -u)" = 0 ] || die "запустите от root"; }

# Подтверждение: пользователь должен ввести точную строку.
confirm_exact() {
	local want=$1 prompt=$2 got
	[ "${VH_YES:-0}" = 1 ] && return 0
	printf '%s%s%s\nВведите «%s» для продолжения: ' "$C_Y" "$prompt" "$C_0" "$want"
	read -r got
	[ "$got" = "$want" ] || die "отменено"
}

yesno() { # yesno ИМЯ ЗНАЧЕНИЕ — проверка значения yes/no
	case $2 in yes|no) ;; *) die "$1 должен быть yes или no, а не «$2»" ;; esac
}

load_config() {
	local cfg=${1:-$VH_ROOT/vh.conf}
	# Умолчания — из примера, затем — пользовательский файл. set -a экспортирует
	# переменные: их читает render (подстановка @VH_*@ в шаблоны).
	set -a
	# shellcheck source=/dev/null
	. "$VH_ROOT/vh.conf.example"
	if [ -f "$cfg" ]; then
		# shellcheck source=/dev/null
		. "$cfg"
	else
		warn "нет $cfg — используются значения по умолчанию"
	fi
	set +a
	yesno VH_TRIM "$VH_TRIM"
	yesno VH_CAMERA "$VH_CAMERA"
	yesno VH_CARDREADER "$VH_CARDREADER"
	yesno VH_VIRT "$VH_VIRT"
	yesno VH_IPV6 "$VH_IPV6"
	yesno VH_HOME_NOEXEC "$VH_HOME_NOEXEC"
	yesno VH_NETLINE "$VH_NETLINE"
	yesno VH_FIRMWARE_TRIM "$VH_FIRMWARE_TRIM"
	case $VH_GPU in igpu|nouveau) ;; *) die "VH_GPU: igpu или nouveau" ;; esac
	case $VH_BLUETOOTH in off|optional|on) ;; *) die "VH_BLUETOOTH: off, optional или on" ;; esac
	case $VH_ETH in dhcp|static|off) ;; *) die "VH_ETH: dhcp, static или off" ;; esac
	case $VH_INITRD_COMPRESS in zstd|lz4) ;; *) die "VH_INITRD_COMPRESS: zstd или lz4" ;; esac
	case $VH_ZRAM_ALGO in zstd|lz4|lzo-rle) ;; *) die "VH_ZRAM_ALGO: zstd, lz4 или lzo-rle" ;; esac
	case $VH_MIRROR in https://*) ;; *) die "VH_MIRROR должен начинаться с https://" ;; esac
	if [ "$VH_ETH" = static ]; then
		[ -n "$VH_ETH_ADDR" ] && [ -n "$VH_ETH_GW" ] || die "VH_ETH=static требует VH_ETH_ADDR и VH_ETH_GW"
	fi
	local n
	for n in "$VH_ADMIN" "$VH_USER" "$VH_BROWSER_USER" "$VH_HOSTNAME"; do
		[[ $n =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || die "недопустимое имя «$n»"
	done
	[ "$VH_ADMIN" != "$VH_USER" ] || die "VH_ADMIN и VH_USER должны различаться"
	if [ -n "$VH_DEV_DIR" ]; then
		[[ $VH_DEV_DIR =~ ^[A-Za-z0-9._-]+$ ]] || die "VH_DEV_DIR — одно имя каталога, без «/»"
	fi
}

# Разделы диска: nvme0n1 → nvme0n1p1, sda → sda1.
part() {
	case $1 in
		*[0-9]) printf '%sp%s' "$1" "$2" ;;
		*) printf '%s%s' "$1" "$2" ;;
	esac
}

# render ИСТОЧНИК НАЗНАЧЕНИЕ [РЕЖИМ]: подставляет @VH_*@ и @VAR@ из окружения.
# Неизвестная подстановка — ошибка (чтобы не оставить «@X@» в конфиге).
render() {
	local src=$1 dst=$2 mode=${3:-0644}
	mkdir -p "$(dirname "$dst")"
	awk -v src="$src" '
	{
		out = ""; s = $0
		while (match(s, /@[A-Z][A-Z0-9_]*@/)) {
			name = substr(s, RSTART + 1, RLENGTH - 2)
			if (name in ENVIRON) val = ENVIRON[name]
			else { missing[name] = 1; val = substr(s, RSTART, RLENGTH) }
			out = out substr(s, 1, RSTART - 1) val
			s = substr(s, RSTART + RLENGTH)
		}
		print out s
	}
	END {
		n = 0
		for (m in missing) list = list (n++ ? ", " : "") m
		if (n) { print "render " src ": не заданы " list > "/dev/stderr"; exit 1 }
	}' "$src" > "$dst.vhtmp" || { rm -f "$dst.vhtmp"; return 1; }
	chmod "$mode" "$dst.vhtmp"
	mv -f "$dst.vhtmp" "$dst"
}

# Копирует дерево rootfs/ в корень ROOT: файлы *.in проходят через render,
# остальные копируются как есть. Права: исполняемые → 0755, прочие → 0644,
# doas.conf — 0400. Файлы *.cin рендерит chroot.sh: им нужны значения, которые
# появляются только внутри системы (GID созданных групп).
install_tree() {
	local tree=$1 root=$2 f rel dst mode
	while IFS= read -r -d '' f; do
		rel=${f#"$tree"/}
		case $rel in *.cin) continue ;; esac
		dst=$root/${rel%.in}
		if [ -x "$f" ]; then mode=0755; else mode=0644; fi
		case $rel in
			etc/doas.conf*) mode=0400 ;;
			etc/sudoers*) mode=0440 ;;
		esac
		if [ "$DRY_RUN" = 1 ]; then
			printf '   + install %s (%s)\n' "/${rel%.in}" "$mode"
			continue
		fi
		mkdir -p "$(dirname "$dst")"
		case $rel in
			*.in) render "$f" "$dst" "$mode" ;;
			*) install -m "$mode" "$f" "$dst" ;;
		esac
	done < <(find "$tree" -type f -print0 | sort -z)
}

export -f render 2>/dev/null || true

# Модули, которые ядро откажется загружать (module_blacklist= в cmdline и
# «install … /bin/false» в modprobe.d). Обоснование — docs/03, docs/05.
vh_module_blacklist() {
	local m=(
		# редкие сетевые протоколы: доступны без привилегий через socket()
		sctp sctp_diag rds rds_tcp rds_rdma tipc can atm ax25 netrom rose x25
		appletalk ieee802154 nfc
		# порты с DMA и экзотика
		firewire_core firewire_ohci firewire_sbp2 thunderbolt usbip_host vhci_hcd
		# файловые системы, которые здесь не монтируются
		cramfs hfs hfsplus udf cifs nfs nfsv4 ksmbd 9p jffs2 freevxfs
		# монтирование в своём user namespace без привилегий (класс CVE-2023-0386):
		# в ядре Void это модули — запрещаем загрузку (flatpak/AppImage/podman не нужны)
		fuse overlay
		# прочее
		binfmt_misc uhid vivid pcspkr
		# интерфейс к Intel ME (AMT выключен; fTPM работает через tpm_crb)
		mei mei_me mei_hdcp mei_pxp mei_wdt
	)
	[ "$VH_BLUETOOTH" = off ] && m+=(bluetooth btusb btintel btrtl btbcm btmtk)
	[ "$VH_CAMERA" = no ] && m+=(uvcvideo)
	[ "$VH_CARDREADER" = no ] && m+=(rtsx_pci rtsx_pci_sdmmc)
	[ "$VH_VIRT" = no ] && m+=(kvm kvm_intel)
	[ "$VH_GPU" = igpu ] && m+=(nouveau)
	printf '%s\n' "${m[@]}"
}

# Прошивки: распаковываются только нужные этому ноутбуку (VH_FIRMWARE_TRIM=yes).
# Пакет linux-firmware-network — 440 МБ прошивок всех сетевых чипов (Qualcomm, Mediatek,
# Broadcom…); здесь нужны iwlwifi (AX201), Intel BT, rtl_nic (RTL8111), i915 и микрокод.
# noextract действует и на обновления; «!» возвращает совпавшее (man xbps.d). docs/02.
vh_firmware_noextract() {
	local keep=(
		"intel-ucode/*"          # микрокод CPU (dracut early_microcode)
		"regulatory.db*"         # база регуляторных доменов Wi-Fi (wireless-regdb)
		"i915/kbl_*" "i915/cml_*"   # Comet Lake: DMC (и GuC/HuC, если включить)
		"iwlwifi-Qu*"            # AX201 CNVi: Qu/QuZ-*-hr-*
		"intel/ibt-*"            # Bluetooth AX201 (8087:0026)
		"rtl_nic/*"              # RTL8111/8168 (r8169)
	)
	[ "$VH_GPU" = nouveau ] && keep+=("nvidia/tu11*")   # TU117: GSP, PMU и т. п.
	local k
	echo "# void-hardened: прошивки только для этого железа (VH_FIRMWARE_TRIM=yes, docs/02)."
	echo "# Вернуть всё: удалить этот файл и xbps-install -f linux-firmware-network linux-firmware-intel"
	echo "noextract=/usr/lib/firmware/*"
	# shellcheck disable=SC2206 # намеренное разбиение на слова
	for k in "${keep[@]}" ${VH_FIRMWARE_KEEP:-}; do
		echo "noextract=!/usr/lib/firmware/$k"
	done
}

# Командная строка ядра, встраиваемая в UKI. При Secure Boot systemd-stub
# игнорирует всё, что передано снаружи, — менять её можно только пересборкой UKI.
# Каждый параметр объяснён в docs/03-boot.md.
vh_cmdline() {
	local bl
	bl=$(vh_module_blacklist | paste -sd, -)
	local c=(
		"rd.luks.uuid=$VH_LUKS_UUID" "root=UUID=$VH_ROOT_UUID" rootfstype=xfs
		rootflags=noatime,logbsize=256k ro
		rd.lvm=0 rd.md=0 rd.dm=0 rd.shell=0 rd.emergency=poweroff
		quiet loglevel=3 net.ifnames=0
		panic=10
		lockdown=confidentiality module.sig_enforce=1
		lsm=landlock,lockdown,yama,apparmor
		intel_iommu=on iommu.strict=1 iommu.passthrough=0 efi=disable_early_pci_dma
		init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1
		debugfs=off ia32_emulation=0
		bdev_allow_write_mounted=0 efi_pstore.pstore_disable=1 proc_mem.force_override=never
		"cfg80211.ieee80211_regdom=$VH_REGDOM"
		preempt=full
		"module_blacklist=$bl"
	)
	[ "$VH_IPV6" = no ] && c+=(ipv6.disable=1)
	# shellcheck disable=SC2206 # намеренное разбиение на слова
	[ -n "${VH_EXTRA_CMDLINE:-}" ] && c+=($VH_EXTRA_CMDLINE)
	printf '%s' "${c[*]}"
}
