#!/bin/sh
# Сборка инструментов на C для VM-стенда (x86_64, glibc Void) в build/ — без gcc на хосте.
#   sh tests/c/build.sh      → build/; затем python3 tests/vm/check.py ШАГ --repo
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$repo/build"
docker run --rm --platform linux/amd64 -v "$repo:/src:ro" -v "$repo/build:/out" \
	ghcr.io/void-linux/void-glibc-full:latest sh -c '
	xbps-install -Syu xbps >/dev/null 2>&1; xbps-install -Sy gcc openssl-devel libxcrypt-devel >/dev/null 2>&1
	for i in 1 2 3; do sh /src/src/build.sh /out && break; done
	/out/vh-seccomp --selftest | tail -1'
