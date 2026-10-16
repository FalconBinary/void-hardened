#!/bin/bash
# void-hardened: инструменты системы на Zig (zig/) — сборка и установка (docs/05, docs/17).
#   install/build-tools.sh ROOT                     — собрать в RAM live-среды, поставить в ROOT
#   install/build-tools.sh --prebuilt КАТАЛОГ ROOT  — поставить уже собранные (VM-стенд, tests/zig/build.sh)
#
# В установленной системе нет ни компилятора, ни интерпретаторов вроде python3 — намеренно
# (docs/05): Zig скачивается в live-среду (install/fetch-zig.sh, подпись minisign), живёт
# в RAM и исчезает с перезагрузкой. gcc не нужен. Обновить
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
	"vh-deep-clean    /usr/local/sbin/vh-deep-clean"
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
	# заголовки для pin-fetch (OpenSSL) и vh-hashpw (libxcrypt) — в RAM live-среды
	xbps-install -Sy openssl-devel libxcrypt-devel >/dev/null || die "не удалось поставить заголовки в live-среду"
	ZIG=$(bash "$VH_ROOT/install/fetch-zig.sh" "$(cat "$VH_ROOT/zig/ZIG_VERSION")" /tmp/vh-zig)
	say "сборка инструментов на Zig (zig/, ReleaseSafe)"
	cp -R "$VH_ROOT/zig" "$BUILD/src"
	( cd "$BUILD/src" && ZIG_GLOBAL_CACHE_DIR=$BUILD/gcache ZIG_LOCAL_CACHE_DIR=$BUILD/cache \
		"$ZIG" build -Dtarget=native -Dcpu=baseline -Dlibc-tools=true --prefix "$BUILD/out" )
	mv "$BUILD/out/bin"/* "$BUILD/"
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
