#!/bin/sh
# Образ vh-dev для тестов: Zig для Linux родной архитектуры (подпись minisign + имя файла
# в подписанном комментарии, как install/fetch-zig.sh) и заголовки Void.
#   sh tests/docker/build.sh   → печатает имя образа
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
ver=$(cat "$repo/zig/ZIG_VERSION")
case $(uname -m) in arm64|aarch64) a=aarch64 ;; *) a=x86_64 ;; esac
img=vh-dev:$a-$ver
if docker image inspect "$img" >/dev/null 2>&1; then echo "$img"; exit 0; fi
key=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
ctx=$repo/build/docker-ctx
mkdir -p "$ctx"
t=zig-$a-linux-$ver.tar.xz
[ -f "$ctx/$t" ] || curl -fsSL -o "$ctx/$t" "https://ziglang.org/download/$ver/$t"
curl -fsSL -o "$ctx/$t.minisig" "https://ziglang.org/download/$ver/$t.minisig"
minisign -Vm "$ctx/$t" -P "$key" >&2
grep -q "^trusted comment: .*file:$t[[:space:]]" "$ctx/$t.minisig"
cp "$repo/tests/docker/Dockerfile" "$ctx/"
docker build -q --build-arg ZIG_TARBALL="$t" -t "$img" "$ctx" >&2
echo "$img"
