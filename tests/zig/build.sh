#!/bin/sh
# Сборка для VM-стенда (x86_64, glibc Void) в build/ — без компилятора на хосте кроме Zig.
#   sh tests/zig/build.sh   → build/ (инструменты) и build/thor-repo (пакет thor);
#                             затем python3 tests/vm/check.py ШАГ --repo
#  * статические инструменты — кросс-компиляцией Zig прямо на хосте;
#  * pin-fetch, vh-hashpw (OpenSSL, libxcrypt) и thor (libxbps, libarchive) — в контейнере
#    Void x86_64: им нужны библиотеки системы. На Apple Silicon контейнер работает под
#    эмуляцией — медленно, но Zig в нём только компилирует.
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

img=$(sh "$repo/tests/docker/build.sh" x86_64)
echo "== pin-fetch, vh-hashpw, thor (контейнер x86_64)"
rm -rf "$b/thor-repo"
docker run --rm --platform linux/amd64 -v "$repo:/src:ro" -v "$b:/out" "$img" sh -c "
	set -e
	cp -R /src/zig /tmp/zs && cd /tmp/zs && zig build -Dtarget=native -Dcpu=baseline -Dlibc-tools=true --prefix /tmp/zl >/dev/null
	cp /tmp/zl/bin/pin-fetch /tmp/zl/bin/vh-hashpw /out/
	sh /src/thor/build.sh /out/xbps-dl/xbps-$XBPS_VERSION.tar.gz /tmp/w /tmp/thor-dest >/dev/null
	sh /src/thor/package.sh /tmp/thor-dest x86_64 /out/thor-repo
	/out/vh-seccomp --selftest | tail -1"
ls "$b/thor-repo"
