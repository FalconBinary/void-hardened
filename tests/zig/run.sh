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
	echo "== vh-deep-clean, vh-pkg rm (последним: удаляет пакеты, заводит пользователей)"
	sh /src/tests/c/clean_test.sh $Z
'
