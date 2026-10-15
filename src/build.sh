#!/bin/sh
# void-hardened: сборка инструментов на C (src/README.md).
#   sh src/build.sh КАТАЛОГ   — собрать все программы в КАТАЛОГ
# Нужны gcc, заголовки glibc и ядра (glibc-devel, kernel-libc-headers), openssl-devel
# (pin-fetch) и libxcrypt-devel (vh-hashpw). В установленной системе компилятора нет:
# сборка идёт в live-среде (install/build-tools.sh) или на машине разработчика.
set -eu
src=$(cd "$(dirname "$0")" && pwd)
out=${1:?"каталог для программ"}
mkdir -p "$out"
CC=${CC:-gcc}
cet=""
case $(uname -m) in x86_64) cet=-fcf-protection=full ;; esac
# Защита от эксплуатации ошибок памяти: FORTIFY, канарейки стека, защита от stack clash,
# CET (IBT/SHSTK), PIE + полный RELRO, неисполняемый стек, обнуление локальных переменных.
CFLAGS="-std=gnu17 -O2 -pipe -Wall -Wextra -Wformat=2 -Wshadow -Wvla -Werror \
-D_GNU_SOURCE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
-fstack-clash-protection $cet -fPIE -fno-strict-aliasing \
-fno-strict-overflow -fno-delete-null-pointer-checks -ftrivial-auto-var-init=zero \
${EXTRA_CFLAGS:-}"
LDFLAGS="-pie -Wl,-z,relro,-z,now,-z,noexecstack,--as-needed ${EXTRA_LDFLAGS:-}"

build() {
	name=$1
	shift
	# shellcheck disable=SC2086
	(cd "$src" && $CC $CFLAGS -o "$out/$name" "$@" $LDFLAGS)
	echo "  $name"
}

build vh-seccomp      vh-seccomp.c seccomp.c vh.c
build vh-wlfilter     vh-wlfilter.c vh.c
build vh-acpid        vh-acpid.c vh.c
build vh-deadman      vh-deadman.c vh.c
build vh-limine-update vh-limine-update.c hash.c vh.c
build vh-pkg          vh-pkg.c vh.c
build vh-deep-clean   vh-deep-clean.c vh.c
build vh-uki-verify   vh-uki-verify.c hash.c vh.c
build vh-open         vh-open.c seccomp.c vh.c
build vh-usb-udev     vh-usb-udev.c vh.c
build pin-fetch       pin-fetch.c hash.c vh.c -lssl -lcrypto
build vh-hashpw       vh-hashpw.c vh.c -lcrypt
