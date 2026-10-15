#!/bin/sh
# Проверка инструментов на C (src/) в одноразовых контейнерах Void (docker).
#   sh tests/c/run.sh [--fuzz N]
#
#  1. сборка с -Werror и всеми флагами защиты (x86_64, как в live-среде);
#  2. vh-seccomp --selftest и побайтное совпадение фильтров с эталоном;
#  3. дифференциальные тесты против Python-эталона (последняя Python-версия — коммит
#     REF_COMMIT): vh-wlfilter, vh-limine-update, vh-uki-verify, vh-open, vh-usb-udev, vh-pkg;
#  4. фаззинг vh-wlfilter под AddressSanitizer и UBSan (в контейнере родной архитектуры:
#     под эмуляцией x86 на Apple Silicon ASan не работает).
# Контейнеры запускаются с --privileged (tmpfs вместо ESP, поддельный sysfs) и удаляются.
set -eu
REF_COMMIT=a7665bd
IMAGE=ghcr.io/void-linux/void-glibc-full:latest
FUZZ=200
[ "${1:-}" = --fuzz ] && FUZZ=$2
repo=$(cd "$(dirname "$0")/../.." && pwd)
ref=$repo/build/ref          # внутри репозитория: временные каталоги macOS docker не видит
rm -rf "$ref"
mkdir -p "$ref"
for f in rootfs/usr/local/libexec/vh/vh-seccomp rootfs/usr/local/bin/vh-wlfilter \
	rootfs/usr/local/sbin/vh-limine-update rootfs/usr/local/sbin/vh-pkg rootfs/usr/local/sbin/vh-suid-strip \
	optional/sb-offline-keys/vh-uki-verify optional/viewers/vh-open optional/usb-auth/vh-usb-udev; do
	git -C "$repo" show "$REF_COMMIT:$f" > "$ref/${f##*/}"
	chmod 0755 "$ref/${f##*/}"
done
deps="gcc openssl-devel libxcrypt-devel python3 zstd lz4 bash"

echo "== x86_64: сборка, seccomp, дифференциальные тесты"
docker run --rm --platform linux/amd64 --privileged -v "$repo:/src:ro" -v "$ref:/ref:ro" "$IMAGE" sh -c "
	set -e
	xbps-install -Syu xbps >/dev/null 2>&1; xbps-install -Sy $deps >/dev/null 2>&1
	# gcc под эмуляцией x86 изредка падает (internal compiler error) — до трёх попыток
	for i in 1 2 3; do sh /src/src/build.sh /tmp/b && break; done
	/tmp/b/vh-seccomp --selftest
	for k in browser viewer; do
		[ \"\$(/tmp/b/vh-seccomp \$k | sha256sum)\" = \"\$(python3 -I /ref/vh-seccomp \$k | sha256sum)\" ] \
			&& echo \"ok фильтр \$k совпадает с эталоном\" || { echo \"РАЗЛИЧИЕ фильтра \$k\"; exit 1; }
	done
	install -m 0755 /ref/vh-suid-strip /usr/local/sbin/vh-suid-strip
	python3 /src/tests/c/wlfilter_diff.py 'python3 -I /ref/vh-wlfilter' /tmp/b/vh-wlfilter
	sh /src/tests/c/limine_diff.sh 'python3 -I /ref/vh-limine-update' /tmp/b/vh-limine-update
	python3 /src/tests/c/uki_diff.py 'python3 -I /ref/vh-uki-verify' /tmp/b/vh-uki-verify
	sh /src/tests/c/open_diff.sh 'python3 -I /ref/vh-open' /tmp/b/vh-open /ref/vh-seccomp
	sh /src/tests/c/usb_diff.sh 'python3 -I /ref/vh-usb-udev' /tmp/b/vh-usb-udev
	sh /src/tests/c/pkg_diff.sh 'python3 -I /ref/vh-pkg' /tmp/b/vh-pkg
"

echo "== $(uname -m): фаззинг vh-wlfilter под ASan/UBSan ($FUZZ сценариев)"
docker run --rm --privileged -v "$repo:/src:ro" -v "$ref:/ref:ro" "$IMAGE" sh -c "
	set -e
	xbps-install -Syu xbps >/dev/null 2>&1; xbps-install -Sy $deps libsanitizer-devel >/dev/null 2>&1
	EXTRA_CFLAGS='-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -U_FORTIFY_SOURCE -Wno-error -w' \
		EXTRA_LDFLAGS='-fsanitize=address,undefined' sh /src/src/build.sh /tmp/asan >/dev/null
	# строгий режим: любое сообщение ASan/UBSan останавливает прокси и даёт различие
	if ! python3 /src/tests/c/wlfilter_diff.py 'python3 -I /ref/vh-wlfilter' /tmp/asan/vh-wlfilter --fuzz $FUZZ > /tmp/fuzz.log 2>&1; then
		grep -v '^ok ' /tmp/fuzz.log | tail -40
		exit 1
	fi
	tail -1 /tmp/fuzz.log
"
