#!/bin/sh
# Проверка thor в одноразовых контейнерах Void родной архитектуры (docker).
#   sh tests/thor/run.sh
#  1. сборка: xbps + патчи + политика (zig cc), команда thor;
#  2. policy_test  — политика в libxbps на тестовых пакетах (SUID, хуки, udev, чёрный список);
#  3. fetch_test   — параллельная загрузка, запасное зеркало, подменённый пакет;
#  4. package_test — пакет thor заменяет xbps и libxbps на системе Void.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
img=$(sh "$repo/tests/docker/build.sh")
. "$repo/thor/UPSTREAM"
dl=$repo/build/xbps-dl
mkdir -p "$dl"
[ -f "$dl/xbps-$XBPS_VERSION.tar.gz" ] || curl -fsSL -o "$dl/xbps-$XBPS_VERSION.tar.gz" "$XBPS_URL"
dest=$repo/build/thor-dest
rm -rf "$dest"
echo "== сборка thor"
docker run --rm -v "$repo:/src:ro" -v "$repo/build:/b" "$img" \
	sh /src/thor/build.sh "/b/xbps-dl/xbps-$XBPS_VERSION.tar.gz" /tmp/w /b/thor-dest
# vh-pkg (Zig) — для теста на системе с thor
case $(uname -m) in arm64|aarch64) a=aarch64 ;; *) a=x86_64 ;; esac
(cd "$repo/zig" && zig build -Dtarget="$a-linux" --prefix "$repo/build/zig-bin")
for t in policy_test fetch_test package_test vhpkg_test; do
	echo "== $t"
	case $t in
		vhpkg_test) cmd="sh /src/tests/thor/package_test.sh /tmp/d >/dev/null && sh /src/tests/thor/vhpkg_test.sh /b/zig-bin/bin/vh-pkg" ;;
		*) cmd="sh /src/tests/thor/$t.sh /tmp/d" ;;
	esac
	docker run --rm -v "$repo:/src:ro" -v "$repo/build:/b:ro" "$img" sh -c "
		cp -R /b/thor-dest /tmp/d && $cmd" > "$repo/build/$t.log" 2>&1 \
		|| { grep -v '^ok ' "$repo/build/$t.log" | tail -30; exit 1; }
	tail -1 "$repo/build/$t.log"
done
