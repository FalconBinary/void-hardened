#!/bin/sh
# Сборка для VM-стенда (x86_64, glibc Void) в build/ — без компилятора на хосте кроме Zig.
#   sh tests/zig/build.sh   → build/ (инструменты) и build/thor-repo (пакет thor);
#                             затем python3 tests/vm/check.py ШАГ --repo
#  * статические инструменты — кросс-компиляцией Zig прямо на хосте;
#  * pin-fetch, vh-hashpw (OpenSSL, libxcrypt) и thor (libxbps, libarchive) — кросс-сборкой
#    в контейнере Void родной архитектуры с sysroot x86_64.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
b=$repo/build
. "$repo/thor/UPSTREAM"
mkdir -p "$b/xbps-dl"
[ -f "$b/xbps-dl/xbps-$XBPS_VERSION.tar.gz" ] || curl -fsSL -o "$b/xbps-dl/xbps-$XBPS_VERSION.tar.gz" "$XBPS_URL"

echo "== статические инструменты (x86_64-linux, кросс-компиляция)"
rm -rf "$b/zx"
(cd "$repo/zig" && zig build -Dtarget=x86_64-linux -Dcpu=baseline --prefix "$b/zx")
cp "$b"/zx/bin/* "$b/"

# pin-fetch, vh-hashpw и thor — кросс-компиляцией в родном контейнере: Zig под эмуляцией
# amd64 в docker на Apple Silicon падает (SIGSEGV), а кросс-сборка — его сильная сторона.
# Заголовки и библиотеки x86_64 — из пакетов Void, распакованных без скриптов (sysroot).
img=$(sh "$repo/tests/docker/build.sh")
echo "== pin-fetch, vh-hashpw, thor (кросс-компиляция x86_64, sysroot из пакетов Void)"
rm -rf "$b/thor-repo"
docker run --rm -v "$repo:/src:ro" -v "$b:/out" "$img" sh -c "
	set -e
	mkdir -p /sx/var/db/xbps/keys && cp -a /var/db/xbps/keys/. /sx/var/db/xbps/keys/
	XBPS_ARCH=x86_64 xbps-install -SyU -r /sx -R https://repo-default.voidlinux.org/current \
		glibc-devel openssl-devel libarchive-devel zlib-devel libxcrypt-devel >/dev/null
	cp -R /src/zig /tmp/zs && cd /tmp/zs && zig build -Dtarget=x86_64-linux-gnu.2.41 -Dcpu=baseline -Dlibc-tools=true \
		--search-prefix /sx/usr --prefix /tmp/zl >/dev/null
	cp /tmp/zl/bin/pin-fetch /tmp/zl/bin/vh-hashpw /out/
	TARGET=x86_64-linux-gnu.2.41 SYSROOT=/sx sh /src/thor/build.sh /out/xbps-dl/xbps-$XBPS_VERSION.tar.gz /tmp/w /tmp/thor-dest >/dev/null
	XBPS_BIN=/usr/bin sh /src/thor/package.sh /tmp/thor-dest x86_64 /out/thor-repo"
ls "$b/thor-repo"
