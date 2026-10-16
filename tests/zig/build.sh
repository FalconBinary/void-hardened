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

# Zig для x86_64 — тот же архив и та же проверка подписи, что у tests/docker/build.sh
ver=$(cat "$repo/zig/ZIG_VERSION")
t=zig-x86_64-linux-$ver.tar.xz
mkdir -p "$b/docker-ctx"
[ -f "$b/docker-ctx/$t" ] || curl -fsSL -o "$b/docker-ctx/$t" "https://ziglang.org/download/$ver/$t"
curl -fsSL -o "$b/docker-ctx/$t.minisig" "https://ziglang.org/download/$ver/$t.minisig"
minisign -Vqm "$b/docker-ctx/$t" -P RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
grep -q "^trusted comment: .*file:$t[[:space:]]" "$b/docker-ctx/$t.minisig"

echo "== pin-fetch, vh-hashpw, thor (одноразовый контейнер x86_64, эмуляция)"
rm -rf "$b/thor-repo"
docker pull -q --platform linux/amd64 ghcr.io/void-linux/void-glibc-full:latest >/dev/null
docker run --rm --platform linux/amd64 -v "$repo:/src:ro" -v "$b:/out" ghcr.io/void-linux/void-glibc-full:latest sh -c "
	set -e
	xbps-install -Syu xbps >/dev/null 2>&1 || true; xbps-install -Syu >/dev/null 2>&1 || true
	xbps-install -Sy openssl-devel libarchive-devel zlib-devel libxcrypt-devel pkgconf make xz patch >/dev/null
	mkdir -p /opt && tar -xJf /out/docker-ctx/$t -C /opt && export ZIG=/opt/${t%.tar.xz}/zig PATH=/opt/${t%.tar.xz}:\$PATH
	cp -R /src/zig /tmp/zs && cd /tmp/zs && zig build -Dtarget=native -Dcpu=baseline -Dlibc-tools=true --prefix /tmp/zl >/dev/null
	cp /tmp/zl/bin/pin-fetch /tmp/zl/bin/vh-hashpw /out/
	sh /src/thor/build.sh /out/xbps-dl/xbps-$XBPS_VERSION.tar.gz /tmp/w /tmp/thor-dest >/dev/null
	sh /src/thor/package.sh /tmp/thor-dest x86_64 /out/thor-repo
	/out/vh-seccomp --selftest | tail -1"
ls "$b/thor-repo"
