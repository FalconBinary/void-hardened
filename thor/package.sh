#!/bin/sh
# thor: пакет из дерева сборки (thor/build.sh) и индекс локального репозитория (docs/18).
#   sh thor/package.sh DESTDIR АРХИТЕКТУРА КАТАЛОГ_РЕПОЗИТОРИЯ
# Пакет заменяет xbps и libxbps (replaces) и предоставляет их (provides) — зависимости
# других пакетов на xbps остаются удовлетворёнными. Программы xbps-create и
# xbps-rindex — из самого DESTDIR.
set -eu
thor=$(cd "$(dirname "$0")" && pwd)
. "$thor/UPSTREAM"
dest=${1:?DESTDIR}
arch=${2:?"архитектура, например x86_64"}
repo=${3:?"каталог репозитория"}
pkgver=thor-$XBPS_VERSION.${THOR_REVISION}_1
# xbps-create и xbps-rindex — из DESTDIR; при кросс-сборке — программы машины сборки
X=${XBPS_BIN:-$dest/usr/bin}
[ -n "${XBPS_BIN:-}" ] || export LD_LIBRARY_PATH="$dest/usr/lib"

# файлы, которые пакет xbps в Void добавляет к upstream
install -d "$dest/usr/share/xbps.d"
echo "architecture=$arch" > "$dest/usr/share/xbps.d/xbps-arch.conf"
# основной репозиторий для архитектуры (как в шаблоне Void; upstream пишет только /current)
case $arch in
	x86_64) sub="" ;;
	*-musl) sub="/musl" ;;
	*) sub="/$arch" ;;
esac
echo "repository=https://repo-default.voidlinux.org/current$sub" > "$dest/usr/share/xbps.d/00-repository-main.conf"
: > "$dest/usr/share/xbps.d/void-virtualpkgs.conf"

mkdir -p "$repo"
repo=$(cd "$repo" && pwd)
rm -f "$repo"/thor-*.xbps "$repo"/*-repodata
cd "$repo"
"$X/xbps-create" -q -A "$arch" -n "$pkgver" \
	-s "xbps + политика безопасности void-hardened, параллельная загрузка" \
	-H "https://github.com/FalconBinary/void-hardened" \
	-l "BSD-2-Clause, GPL-3.0-or-later" -m "void-hardened" \
	-D "ca-certificates>=0 xbps-triggers>=0 glibc>=2.41_1 libarchive>=3.5.1_2 libcrypto3>=3.0_1 libssl3>=3.0_1 zlib>=1.2.3_1" \
	-P "xbps-${XBPS_VERSION}_1 libxbps-${XBPS_VERSION}_1" \
	-R "xbps>=0 libxbps>=0" \
	--shlib-provides "libxbps.so.6" \
	--shlib-requires "libarchive.so.13 libcrypto.so.3 libssl.so.3 libz.so.1 libc.so.6" \
	"$dest"
XBPS_TARGET_ARCH=$arch "$X/xbps-rindex" -a "$repo/$pkgver.$arch.xbps" >/dev/null
echo "$repo/$pkgver.$arch.xbps"
