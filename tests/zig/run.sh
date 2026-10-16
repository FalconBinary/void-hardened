#!/bin/sh
# Проверка инструментов на Zig (zig/) в одноразовом контейнере Void родной архитектуры.
#   sh tests/zig/run.sh
#
# Zig собирает всё на хосте (кросс-компиляция под aarch64/x86_64-linux), контейнер только
# запускает: эмуляции нет, сборка и тесты быстрые даже на Mac с 8 ГБ.
#  1. юнит-тесты zig/lib и программ (zig test);
#  2. дифференциальные тесты против C-эталона (src/, собранного gcc в контейнере).
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=$(sh "$(dirname "$0")/../docker/build.sh")
case $(uname -m) in arm64|aarch64) arch=aarch64 plat=linux/arm64 ;; *) arch=x86_64 plat=linux/amd64 ;; esac
out=$repo/build/zig-test       # внутри репозитория: временные каталоги macOS docker не видит
rm -rf "$out"
mkdir -p "$out"

echo "== сборка программ и юнит-тестов ($arch-linux)"
(cd "$repo/zig" && zig build install tests -Dtarget="$arch-linux" --prefix "$out")

docker run --rm --platform "$plat" --privileged -v "$repo:/src:ro" -v "$out:/t:ro" "$IMAGE" sh -c '
	set -e
	for t in /t/test/*; do [ -e "$t" ] || continue; echo "-- $(basename "$t")"; "$t" 2>&1 | tail -1; done
'
