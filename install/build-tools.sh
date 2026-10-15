#!/bin/bash
# void-hardened: инструменты системы на C (src/) — сборка и установка (docs/05, src/README.md).
#   install/build-tools.sh ROOT                     — собрать в RAM live-среды, поставить в ROOT
#   install/build-tools.sh --prebuilt КАТАЛОГ ROOT  — поставить уже собранные (VM-стенд, src/build.sh)
#
# В установленной системе нет ни компилятора, ни интерпретаторов вроде python3 — намеренно
# (docs/05): gcc ставится только в live-среду, в RAM, и исчезает с перезагрузкой. Обновить
# программы после git pull: загрузиться с флешки, открыть и смонтировать корень в /mnt и
# запустить этот скрипт ещё раз — заменятся и копии, уже поставленные модулями optional/.
set -euo pipefail
VH_ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$VH_ROOT/install/lib.sh"

# программа → место в системе [→ копия, которую ставит включённый модуль optional/]
MAP=(
	"vh-seccomp       /usr/local/libexec/vh/vh-seccomp"
	"vh-wlfilter      /usr/local/bin/vh-wlfilter"
	"vh-acpid         /usr/local/sbin/vh-acpid"
	"vh-limine-update /usr/local/sbin/vh-limine-update"
	"vh-pkg           /usr/local/sbin/vh-pkg"
	"vh-hashpw        /root/vh/tools/vh-hashpw"
	"vh-deadman       /root/vh/optional/deadman/vh-deadman             /usr/local/sbin/vh-deadman"
	"vh-uki-verify    /root/vh/optional/sb-offline-keys/vh-uki-verify  /usr/local/sbin/vh-uki-verify"
	"vh-open          /root/vh/optional/viewers/vh-open                /usr/local/bin/vh-open"
	"vh-usb-udev      /root/vh/optional/usb-auth/vh-usb-udev           /usr/local/libexec/vh/vh-usb-udev"
	"pin-fetch        /root/vh/optional/dns-pin/pin-fetch              /usr/local/libexec/vh/pin-fetch"
)

need_root
if [ "${1:-}" = --prebuilt ]; then
	BUILD=${2:?"каталог с программами"} ROOT=${3:?"корень системы"}
else
	ROOT=${1:?"корень системы, например /mnt"}
	BUILD=$(mktemp -d /tmp/vh-build.XXXXXX)
	trap 'rm -rf "$BUILD"' EXIT
	if ! command -v gcc >/dev/null || [ ! -e /usr/include/openssl/ssl.h ] || [ ! -e /usr/include/crypt.h ]; then
		say "компилятор и заголовки — в live-среду (RAM)"
		xbps-install -Sy gcc openssl-devel libxcrypt-devel
	fi
	say "сборка инструментов на C (src/)"
	sh "$VH_ROOT/src/build.sh" "$BUILD"
	"$BUILD/vh-seccomp" --selftest >/dev/null || die "vh-seccomp --selftest не прошёл"
fi
[ -d "$ROOT/usr/local" ] || die "$ROOT — не корень системы"

say "установка в $ROOT"
for line in "${MAP[@]}"; do
	read -r name dst copy <<< "$line"
	# -f, а не -x: каталог сборки может лежать на noexec (/tmp установленной системы)
	[ -f "$BUILD/$name" ] || die "нет собранной программы $name"
	install -D -m 0755 -o root -g root "$BUILD/$name" "$ROOT$dst"
	# модуль уже включён — его копия заменяется тоже
	if [ -n "${copy:-}" ] && [ -e "$ROOT$copy" ]; then
		install -m 0755 -o root -g root "$BUILD/$name" "$ROOT$copy"
		ok "$name → $dst, $copy"
	else
		ok "$name → $dst"
	fi
done
