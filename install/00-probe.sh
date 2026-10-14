#!/bin/bash
# Этап 0: проба железа. Запускается в live-среде от root, ничего не пишет на диски.
# Собирает всё, что нужно знать до установки (модуль 0 руководства), и печатает
# рекомендации для vh.conf.
#
#   ./install/00-probe.sh                 — только то, что есть в live-образе
#   ./install/00-probe.sh --install-tools — сначала поставить в live (в RAM) pciutils,
#                                           usbutils, tpm2-tools, nvme-cli, iw, efibootmgr
#
# Отчёт: /tmp/vh-probe-<дата>.txt — его удобно приложить к вопросу или сохранить.

. "$(dirname "$0")/lib.sh"
set +e +o pipefail   # проба не должна обрываться на первой отсутствующей утилите
need_root

if [ "${1:-}" = "--install-tools" ]; then
	say "ставлю утилиты в live-среду (только RAM)"
	xbps-install -Syu xbps >/dev/null 2>&1
	xbps-install -Sy pciutils usbutils tpm2-tools nvme-cli iw efibootmgr python3 dmidecode \
		|| warn "не все утилиты установились (нет сети?)"
fi

OUT=/tmp/vh-probe-$(date +%Y%m%d-%H%M%S).txt
exec > >(tee "$OUT") 2>&1
have() { command -v "$1" >/dev/null 2>&1; }
sec() { printf '\n%s######## %s%s\n' "$C_B" "$*" "$C_0"; }
rd() { [ -r "$1" ] && tr -d '\0' < "$1" 2>/dev/null; }
REC=()   # рекомендации
rec() { REC+=("$*"); }

sec "Система"
for f in sys_vendor product_name product_version board_name bios_vendor bios_version bios_date; do
	printf '%-16s %s\n' "$f:" "$(rd /sys/class/dmi/id/$f)"
done
echo "ядро live:       $(uname -r)"
echo "RAM:             $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"

sec "Память"
if have dmidecode; then
	dmidecode -t memory 2>/dev/null | awk -F: '/^\tSize:/ {sz=$2} /^\tLocator:/ {loc=$2} /^\tConfigured Memory Speed:/ {printf "  %-12s %-12s %s\n", loc, sz, $2}'
	n=$(dmidecode -t memory 2>/dev/null | grep -cE '^\s+Size: [0-9]+ (GB|MB)')
	echo "модулей установлено: $n"
	[ "$n" = 1 ] && rec "Установлен один модуль памяти: встроенная графика работает в одноканальном режиме. Второй такой же модуль — самый большой прирост скорости графики и zram на этом ноутбуке (docs/15)."
else
	echo "нет dmidecode (запустите с --install-tools)"
fi

sec "CPU"
grep -m1 'model name' /proc/cpuinfo
echo "ядер/потоков:    $(grep -c ^processor /proc/cpuinfo)"
echo "микрокод:        $(grep -m1 microcode /proc/cpuinfo | awk '{print $3}')"
flags=$(grep -m1 '^flags' /proc/cpuinfo)
for fl in vmx smx tme ibt user_shstk sgx rdrand rdseed aes avx2 avx512f; do
	if [[ " $flags " == *" $fl "* ]]; then echo "  флаг $fl: есть"; else echo "  флаг $fl: нет"; fi
done
[[ " $flags " == *" tme "* ]] || rec "TME нет: открытый текст в DRAM не шифруется аппаратно — защита от холодной загрузки только программная (docs/05)."
[[ " $flags " == *" vmx "* ]] && rec "VT-x включён в BIOS. Если KVM не нужен — выключите его (docs/00), VH_VIRT=no."
echo "уязвимости и смягчения:"
for f in /sys/devices/system/cpu/vulnerabilities/*; do
	printf '  %-28s %s\n' "$(basename "$f")" "$(cat "$f")"
done

sec "Прошивка (UEFI)"
if [ -d /sys/firmware/efi ]; then
	echo "режим: UEFI, разрядность $(rd /sys/firmware/efi/fw_platform_size)"
	efv() { # efv ИМЯ — значение однобайтовой переменной EFI
		local f; f=$(ls /sys/firmware/efi/efivars/"$1"-* 2>/dev/null | head -1)
		[ -n "$f" ] && od -An -t u1 -j4 -N1 "$f" | tr -d ' ' || echo "нет"
	}
	echo "SecureBoot:      $(efv SecureBoot)"
	echo "SetupMode:       $(efv SetupMode)"
	echo "MOR (MemoryOverwriteRequestControl): $(efv MemoryOverwriteRequestControl)"
	ls /sys/firmware/efi/efivars/ | grep -q MemoryOverwriteRequestControl \
		&& rec "MOR поддерживается прошивкой: перезагрузка через прошивку стирает RAM (docs/03)." \
		|| rec "MOR не найден: очистки RAM прошивкой не будет — остаточный риск (docs/03)."
	[ "$(efv SetupMode)" = 1 ] && rec "Secure Boot уже в Setup Mode — ключи можно регистрировать сразу (docs/03)."
	have efibootmgr && { echo "записи загрузки:"; efibootmgr -v 2>/dev/null | sed 's/^/  /'; }
else
	echo "режим: BIOS/CSM — НЕ ПОДДЕРЖИВАЕТСЯ. Включите UEFI и выключите CSM."
	rec "Загрузитесь в режиме UEFI (CSM выключен) — установщик работает только с UEFI."
fi

sec "TPM"
if [ -e /sys/class/tpm/tpm0 ]; then
	echo "версия TPM: $(rd /sys/class/tpm/tpm0/tpm_version_major)"
	echo "драйвер:    $(basename "$(readlink -f /sys/class/tpm/tpm0/device/driver 2>/dev/null)")"
	ls -l /dev/tpm0 /dev/tpmrm0 2>/dev/null
	if have tpm2_getcap; then
		tpm2_getcap properties-fixed 2>/dev/null | grep -A2 -E 'TPM2_PT_MANUFACTURER|TPM2_PT_FIRMWARE_VERSION_1' | sed 's/^/  /'
		tpm2_getcap properties-fixed 2>/dev/null | grep -A1 TPM2_PT_MANUFACTURER | grep -q '"INTC"' \
			&& rec "TPM — fTPM Intel PTT (внутри ME): доверие к tpm2-totp = доверие к ME (docs/03)."
		echo "  lockoutAuthSet: $(tpm2_getcap properties-variable 2>/dev/null | grep -i lockoutAuthSet | awk '{print $2}')"
	fi
	EVLOG=/sys/kernel/security/tpm0/binary_bios_measurements
	if have tpm2_eventlog && [ -r "$EVLOG" ]; then
		n=$(tpm2_eventlog "$EVLOG" 2>/dev/null | grep -c 'EV_EFI_BOOT_SERVICES_DRIVER')
		echo "Option ROM в журнале измерений (EV_EFI_BOOT_SERVICES_DRIVER): $n"
		if [ "$n" -gt 0 ]; then
			rec "Есть Option ROM ($n шт.): ключи SB регистрировать с --tpm-eventlog, НЕ с --microsoft, иначе экран/диск могут не инициализироваться (docs/03)."
		else
			rec "Option ROM не найдено: sbctl enroll-keys без сертификатов Microsoft (docs/03)."
		fi
	else
		echo "журнал измерений: нет tpm2_eventlog (запустите с --install-tools)"
	fi
else
	echo "TPM не найден. Включите Intel PTT / fTPM в BIOS."
	rec "TPM не найден: включите PTT в BIOS (нужен для tpm2-totp)."
fi

sec "PCI-устройства"
if have lspci; then
	lspci -nnk | sed 's/^/  /'
	if lspci -vvv 2>/dev/null | grep -q 'Address Translation Service'; then
		echo "ATS: есть устройства с ATS:"
		lspci -vvv 2>/dev/null | awk '/^[0-9a-f]/{dev=$0} /Address Translation Service/{print "  " dev}'
		rec "Есть устройства с ATS — pci=noats не добавлять без проверки (docs/03)."
	else
		echo "ATS: ни одно устройство не использует"
		rec "ATS не используется — можно добавить pci=noats в cmdline (docs/03, опционально)."
	fi
	lspci -nn | grep -qi '10de:' && echo "NVIDIA dGPU: $(lspci -nn | grep -i '10de:' | head -1)"
else
	echo "нет lspci (запустите с --install-tools)"
fi

sec "Выходы видео (DRM)"
for c in /sys/class/drm/card*-*; do
	[ -e "$c/status" ] || continue
	card=${c##*/}; card=${card%%-*}
	drv=$(basename "$(readlink -f /sys/class/drm/$card/device/driver 2>/dev/null)")
	printf '  %-24s %-10s драйвер=%s\n' "${c##*/}" "$(cat "$c/status")" "$drv"
	case ${c##*/}:$drv in
		*HDMI*:nouveau|*DP*:nouveau|*HDMI*:nvidia*|*DP*:nvidia*)
			rec "Порт ${c##*/} разведён на NVIDIA: при VH_GPU=igpu он работать не будет. Нужен внешний монитор — ставьте VH_GPU=nouveau (docs/04)." ;;
	esac
done
lsmod | grep -q '^nouveau' || echo "  (nouveau не загружен — порты dGPU могут быть не видны: modprobe nouveau и запустите пробу снова)"

sec "USB"
if have lsusb; then
	lsusb | sed 's/^/  /'
	echo "дерево:"
	lsusb -t | sed 's/^/  /'
	lsusb | grep -qi '8087:0026' && echo "  Bluetooth AX201: 8087:0026 (внутреннее USB-устройство)"
fi
echo "тип подключения портов (connect_type):"
for p in /sys/bus/usb/devices/*/port/connect_type /sys/bus/usb/devices/*/*/connect_type; do
	[ -r "$p" ] && printf '  %-55s %s\n' "$p" "$(cat "$p")"
done 2>/dev/null | sort -u
rec "Внешние порты не должны быть «hardwired» (иначе usbcore.authorized_default=2 им доверяет) — сверьте список выше с физическими разъёмами (docs/05)."

sec "Устройства ввода"
awk 'BEGIN{RS=""} /Name=/ {print}' /proc/bus/input/devices | grep -E '^(N|P|S|H):' | sed 's/^/  /'
if grep -A3 -i 'keyboard' /proc/bus/input/devices | grep -q 'isa0060'; then
	echo "встроенная клавиатура: i8042 (PS/2)"
elif grep -B1 -A3 -i 'keyboard' /proc/bus/input/devices | grep -q 'usb-'; then
	echo "встроенная клавиатура: возможно, внутренний USB"
	rec "Клавиатура может быть на внутреннем USB: при USB-авторизации (optional/usb-auth) укажите её порт явно (docs/05)."
fi

sec "Сеть"
for n in /sys/class/net/*; do
	[ "${n##*/}" = lo ] && continue
	printf '  %-10s драйвер=%-10s mac=%s\n' "${n##*/}" \
		"$(basename "$(readlink -f "$n/device/driver" 2>/dev/null)")" "$(cat "$n/address")"
done
have iw && { echo "регуляторный домен:"; iw reg get 2>/dev/null | sed 's/^/  /' | head -20; }
have rfkill && rfkill list 2>/dev/null | sed 's/^/  /'
dmesg 2>/dev/null | grep -iE 'iwlwifi.*loaded firmware|iwlwifi.*firmware: direct-loading|rtl_nic|r8169.*firmware' | head -4 | sed 's/^/  прошивка: /'
grep -q 'iwlwifi' /proc/modules && have modinfo && {
	echo "параметры iwlwifi/iwlmvm:"
	modinfo -p iwlwifi 2>/dev/null | grep -E 'power_save|uapsd|bt_coex' | sed 's/^/  /'
	modinfo -p iwlmvm 2>/dev/null | grep -E 'power_scheme' | sed 's/^/  /'
}

sec "MSI: драйвер msi-ec (вентилятор, режимы мощности)"
if [ "$(rd /sys/class/dmi/id/sys_vendor)" = "Micro-Star International Co., Ltd." ]; then
	modprobe msi-ec 2>/dev/null
	if [ -d /sys/devices/platform/msi-ec ]; then
		echo "msi-ec поддерживает эту прошивку EC: $(ls /sys/devices/platform/msi-ec | paste -sd' ' -)"
	else
		dmesg 2>/dev/null | grep -i 'msi_ec\|msi-ec' | tail -3 | sed 's/^/  /'
		echo "msi-ec эту прошивку EC не поддерживает — режимы вентилятора только в Windows (docs/15)"
	fi
else
	echo "не MSI — пропуск"
fi

sec "Аппаратный сторож (iTCO)"
dmesg 2>/dev/null | grep -i tco | sed 's/^/  /'
ls /sys/class/watchdog/ 2>/dev/null | sed 's/^/  /'
lsmod | grep -E 'iTCO|lpc_ich|i2c_i801' | sed 's/^/  /'
dmesg 2>/dev/null | grep -qi 'unable to reset NO_REBOOT' && rec "Прошивка заблокировала NO_REBOOT у iTCO: аппаратный сторож недоступен (docs/05)."

sec "Накопители"
lsblk -d -o NAME,SIZE,MODEL,TRAN,ROTA,PHY-SEC,LOG-SEC 2>/dev/null | sed 's/^/  /'
for d in /dev/nvme?n1; do
	[ -b "$d" ] || continue
	echo "$d: планировщик $(cat /sys/block/${d##*/}/queue/scheduler)"
	if have nvme; then
		nvme id-ns -H "$d" 2>/dev/null | grep -E 'LBA Format' | sed 's/^/  /'
		nvme id-ctrl -H "${d%n1}" 2>/dev/null | grep -iE 'Crypto Erase|Sanitize|Format NVM' | head -8 | sed 's/^/  /'
		nvme id-ns -H "$d" 2>/dev/null | grep -E 'LBA Format' | grep -q 'Data Size: 4096' \
			&& rec "$d поддерживает LBA 4096: переформатирование (nvme format --lbaf=N, стирает всё) убирает эмуляцию 512 Б (docs/01, опционально)."
	fi
done

sec "Звук, подсветка, батарея"
for c in /proc/asound/card*/codec#*; do
	[ -r "$c" ] && { echo "  $c:"; head -3 "$c" | sed 's/^/    /'; }
done
ls /sys/class/backlight/ 2>/dev/null | sed 's/^/  подсветка: /'
ls /sys/class/power_supply/ 2>/dev/null | sed 's/^/  питание: /'
cat /sys/devices/system/cpu/cpufreq/policy0/scaling_driver 2>/dev/null | sed 's/^/  cpufreq: /'
cat /sys/devices/system/cpu/cpufreq/policy0/energy_performance_available_preferences 2>/dev/null | sed 's/^/  EPP: /'

sec "Рекомендации"
for r in "${REC[@]}"; do printf ' • %s\n' "$r"; done
echo
echo "Отчёт сохранён: $OUT"
echo "Скопируйте его на флешку или в сеть, прежде чем перезагружаться: /tmp живёт в RAM."
