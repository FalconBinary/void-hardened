#!/bin/bash
# Этап 3: запрет загрузки модулей ядра после старта (kernel.modules_disabled=1).
#   doas /root/vh/install/30-lock.sh
#
# Перед запуском за ЭТУ загрузку используйте всё железо, которое понадобится:
# Wi-Fi (свою сеть и, если бывает, чужую с DHCP), Ethernet, флешку (vfat/exfat),
# наушники, Bluetooth (если VH_BLUETOOTH≠off), FIDO2-ключ, внешний монитор.
# Скрипт возьмёт список загруженных модулей (lsmod) — их будут предзагружать в
# конце стадии 1, после чего загрузка модулей заблокируется до перезагрузки.
# Подробно — docs/05-system.md, раздел «Модули ядра».

. "$(dirname "$0")/lib.sh"
need_root
load_config /root/vh/vh.conf

LIST=/etc/vh/modules.preload
mapfile -t blocked < <(vh_module_blacklist)
# Нужны позже, даже если сейчас не загружены: ESP (vfat, nls), флешки, USB-HID.
extra=(vfat fat nls_cp437 nls_iso8859_1 nls_utf8 exfat usb_storage uas usbhid hid_generic tcp_bbr sch_fq)
{
	echo "# void-hardened: предзагрузка перед kernel.modules_disabled=1 ($(date -u +%F), ядро $(uname -r))"
	echo "# fuse и overlay сюда не входят никогда: после блокировки их не загрузит и userns."
	{
		awk 'NR > 1 {print $1}' /proc/modules
		printf '%s\n' "${extra[@]}"
	} | sort -u | while read -r m; do
		case $m in fuse|overlay) continue ;; esac
		printf '%s\n' "${blocked[@]}" | grep -qx "$m" && continue
		modinfo -n "$m" >/dev/null 2>&1 || continue   # встроенные и отсутствующие
		echo "$m"
	done
} > "$LIST.new"

echo "Будут предзагружаться ($(grep -vc '^#' "$LIST.new") модулей):"
grep -v '^#' "$LIST.new" | paste -sd' ' - | fold -s -w 100 | sed 's/^/  /'
cat <<EOF

После перезагрузки любой модуль не из этого списка не загрузится — даже root.
Новое железо другого типа (например, USB-сетевая карта) заработает только после
повторного запуска этого скрипта и перезагрузки. Отключить блокировку:
  doas rm /etc/vh/modlock.enabled   (действует со следующей загрузки)
EOF
confirm_exact lock "Включить блокировку модулей со следующей загрузки?"
mv "$LIST.new" "$LIST"
chmod 0644 "$LIST"
: > /etc/vh/modlock.enabled
ok "включено. Перезагрузитесь и проверьте: cat /proc/sys/kernel/modules_disabled → 1"
