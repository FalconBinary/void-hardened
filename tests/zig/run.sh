#!/bin/sh
# Проверка инструментов на Zig (zig/) в одноразовом контейнере Void родной архитектуры.
#   sh tests/zig/run.sh
#
# Zig собирает всё на хосте (кросс-компиляция под Linux), контейнер только запускает:
# эмуляции нет, тесты быстрые даже на Mac с 8 ГБ.
#  1. юнит-тесты zig/lib и программ (zig build tests);
#  2. дифференциальные тесты против C-эталона (src/, собирается gcc в контейнере) —
#     те же скрипты tests/c/*_diff.sh, что сверяли C с Python.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
img=$(sh "$repo/tests/docker/build.sh")
case $(uname -m) in arm64|aarch64) arch=aarch64 ;; *) arch=x86_64 ;; esac
out=$repo/build/zig-test       # внутри репозитория: временные каталоги macOS docker не видит
rm -rf "$out"
mkdir -p "$out"

echo "== сборка программ и юнит-тестов ($arch-linux)"
(cd "$repo/zig" && zig build install tests -Dtarget="$arch-linux" --prefix "$out")

docker run --rm --privileged -v "$repo:/src:ro" -v "$out:/t:ro" "$img" sh -c '
	set -e
	for t in /t/test/*; do printf "%s: " "$(basename "$t")"; "$t" 2>&1 | tail -1; done
	echo "== эталон: инструменты на C (src/)"
	sh /src/src/build.sh /tmp/c >/dev/null
	Z=/t/bin C=/tmp/c
	echo "== vh-seccomp"
	for k in browser viewer; do
		[ "$($Z/vh-seccomp $k | sha256sum)" = "$($C/vh-seccomp $k | sha256sum)" ] \
			&& echo "ok фильтр $k побайтно совпадает с C" || { echo "РАЗЛИЧИЕ фильтра $k"; exit 1; }
	done
	[ "$($Z/vh-seccomp --selftest)" = "$($C/vh-seccomp --selftest)" ] && echo "ok --selftest совпадает" \
		|| { echo "РАЗЛИЧИЕ --selftest"; exit 1; }
	r1=0; r2=0; $Z/vh-seccomp x 2>/tmp/e1 || r1=$?; $C/vh-seccomp x 2>/tmp/e2 || r2=$?
	[ "$r1" = "$r2" ] && cmp -s /tmp/e1 /tmp/e2 && echo "ok ошибка аргумента совпадает" || { echo "РАЗЛИЧИЕ ошибки"; exit 1; }
	echo "== vh-wlfilter: протокол против C и фаззинг (ReleaseSafe: любая паника = различие)"
	python3 /src/tests/c/wlfilter_diff.py $C/vh-wlfilter $Z/vh-wlfilter --fuzz ${FUZZ:-200} > /tmp/wl.log 2>&1 \
		|| { grep -v "^ok " /tmp/wl.log | tail -30; exit 1; }
	tail -1 /tmp/wl.log
	echo "== vh-limine-update"
	sh /src/tests/c/limine_diff.sh $C/vh-limine-update $Z/vh-limine-update
	echo "== vh-uki-verify"
	python3 /src/tests/c/uki_diff.py $C/vh-uki-verify $Z/vh-uki-verify
	echo "== vh-deadman: структуры ядра и режим test"
	gcc -o /tmp/dm /src/tests/zig/dm_check.c && [ "$(/tmp/dm)" = "312 0xc138fd06 0xc138fd0e 3074" ] && echo "ok dm_ioctl: размер, DM_DEV_SUSPEND, DM_TARGET_MSG, флаги" || { echo "РАЗЛИЧИЕ dm_ioctl: $(/tmp/dm)"; exit 1; }
	[ "$($Z/vh-deadman test 2>&1)" = "$($C/vh-deadman test 2>&1)" ] && echo "ok vh-deadman test совпадает" || { echo "РАЗЛИЧИЕ vh-deadman test"; $Z/vh-deadman test; $C/vh-deadman test; exit 1; }
	echo "== pin-fetch, vh-hashpw (OpenSSL, libxcrypt системы — сборка здесь)"
	cp -R /src/zig /tmp/zs && (cd /tmp/zs && zig build -Dtarget=native -Dlibc-tools=true --prefix /tmp/zl >/dev/null)
	$Z/../bin/vh-seccomp --selftest >/dev/null
	a=$(/tmp/zl/bin/pin-fetch 1.1.1.1 853 cloudflare-dns.com 2>/tmp/a2); b=$($C/pin-fetch 1.1.1.1 853 cloudflare-dns.com 2>/tmp/b2)
	[ -n "$a" ] && [ "$a" = "$b" ] && cmp -s /tmp/a2 /tmp/b2 && echo "ok pin-fetch: PEM и сводка совпадают с C ($(cut -d: -f1-3 /tmp/a2 | head -c 60)…)" \
		|| { echo "РАЗЛИЧИЕ pin-fetch"; cat /tmp/a2 /tmp/b2; exit 1; }
	r1=0; r2=0; /tmp/zl/bin/pin-fetch 1.1.1.1 853 example.com >/dev/null 2>/tmp/a3 || r1=$?; $C/pin-fetch 1.1.1.1 853 example.com >/dev/null 2>/tmp/b3 || r2=$?
	[ "$r1" = "$r2" ] && [ "$r1" != 0 ] && cmp -s /tmp/a3 /tmp/b3 && echo "ok pin-fetch: чужое имя — отказ, как в C" || { echo "РАЗЛИЧИЕ pin-fetch (имя)"; cat /tmp/a3 /tmp/b3; exit 1; }
	gcc -o /tmp/cc /src/tests/zig/crypt_check.c -lcrypt
	h=$(printf "пароль 1" | /tmp/zl/bin/vh-hashpw 5)
	case $h in "\$y\$"*) /tmp/cc "пароль 1" "$h" && echo "ok vh-hashpw: yescrypt, libcrypt подтверждает" || { echo "РАЗЛИЧИЕ vh-hashpw: не проверяется"; exit 1; } ;; *) echo "РАЗЛИЧИЕ vh-hashpw: $h"; exit 1 ;; esac
	echo "== vh-usb-udev"
	sh /src/tests/c/usb_diff.sh $C/vh-usb-udev $Z/vh-usb-udev
	echo "== vh-open"
	sh /src/tests/c/open_diff.sh $C/vh-open $Z/vh-open $C/vh-seccomp
	echo "== vh-deep-clean, vh-pkg rm (последним: удаляет пакеты, заводит пользователей)"
	sh /src/tests/c/clean_test.sh $Z
'
