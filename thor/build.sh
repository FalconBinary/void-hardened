#!/bin/sh
# thor: сборка xbps с патчами void-hardened и политикой на Zig (docs/18).
#   ZIG=путь/к/zig sh thor/build.sh АРХИВ_XBPS КАТАЛОГ_СБОРКИ DESTDIR
# АРХИВ_XBPS сверяется с thor/UPSTREAM. Нужны заголовки openssl-devel,
# libarchive-devel, zlib-devel, pkgconf, make, patch — gcc не нужен: C-код
# собирается через «zig cc». Результат — дерево установки в DESTDIR (/usr, /etc).
set -eu
thor=$(cd "$(dirname "$0")" && pwd)
. "$thor/UPSTREAM"
tarball=${1:?"архив xbps-$XBPS_VERSION.tar.gz"}
work=${2:?"каталог сборки"}
dest=${3:?"DESTDIR"}
ZIG=${ZIG:?"путь к zig (install/fetch-zig.sh)"}

echo "$XBPS_SHA256  $tarball" | sha256sum -c - >/dev/null || {
	echo "thor/build.sh: контрольная сумма $tarball не совпадает с thor/UPSTREAM" >&2
	exit 1
}
rm -rf "$work"
mkdir -p "$work/bin" "$dest"
tar -xzf "$tarball" -C "$work"
src=$work/xbps-$XBPS_VERSION
for p in "$thor"/patches/*.patch; do
	patch -s -d "$src" -p1 < "$p"
done

# ar/ranlib из Zig (binutils в live-среде нет)
printf '#!/bin/sh\nexec "%s" ar "$@"\n' "$ZIG" > "$work/bin/ar"
printf '#!/bin/sh\nexec "%s" ranlib "$@"\n' "$ZIG" > "$work/bin/ranlib"
chmod 0755 "$work/bin/ar" "$work/bin/ranlib"
PATH=$work/bin:$PATH
# кэш Zig — в каталоге сборки (RAM live-среды), а не в $HOME и не рядом с исходниками
ZIG_GLOBAL_CACHE_DIR=$work/zig-gcache ZIG_LOCAL_CACHE_DIR=$work/zig-cache
export PATH ZIG_GLOBAL_CACHE_DIR ZIG_LOCAL_CACHE_DIR

# Защита от эксплуатации ошибок памяти — тот же набор, что у инструментов (docs/17).
# -Wno-error: upstream собирается с -Werror, а новые glibc и clang дают предупреждения
# о const (strchr в C23) — к безопасности они не относятся.
cet=""
case $(uname -m) in x86_64) cet="-fcf-protection=full -march=x86-64" ;; esac
CFLAGS="-O2 -pipe -Wno-error -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
-fstack-clash-protection $cet -ftrivial-auto-var-init=zero"

echo "== политика (Zig) → thor_policy.o"
"$ZIG" build-obj "$thor/policy/policy.zig" -OReleaseSafe -fPIC -fno-omit-frame-pointer \
	-femit-bin="$src/lib/thor_policy.o"

echo "== xbps $XBPS_VERSION + патчи (zig cc)"
(
	cd "$src"
	# libcrypto явно: lld, в отличие от ld.bfd, не подтягивает зависимости libssl.
	# rpath $ORIGIN/../lib: программы берут libxbps (с политикой) из своего дерева, а не
	# штатную /usr/lib/libxbps.so.6 live-среды; в системе это та же /usr/lib.
	CC="$ZIG cc" CFLAGS="$CFLAGS" LDFLAGS="-lcrypto" \
		./configure --prefix=/usr --sysconfdir=/etc --enable-rpath > "$work/configure.log" 2>&1 \
		|| { tail -20 "$work/configure.log" >&2; exit 1; }
	make -j"$(nproc)" > "$work/make.log" 2>&1 || { grep -B2 -A8 -i 'error' "$work/make.log" | head -60 >&2; exit 1; }
	make DESTDIR="$dest" install > "$work/install.log" 2>&1
)
# в пакете не нужны: статическая библиотека, заголовки, xbps-uchroot (SUID-помощник
# xbps-src — здесь не собирают пакеты), xbps-uunshare, xbps-fbulk, xbps-dgraph
rm -f "$dest/usr/lib/libxbps.a" "$dest/usr/bin/xbps-uchroot" "$dest/usr/bin/xbps-uunshare" \
	"$dest/usr/bin/xbps-fbulk" "$dest/usr/bin/xbps-dgraph"
rm -rf "$dest/usr/include" "$dest/usr/lib/pkgconfig"

if [ -e "$thor/src/thor.zig" ]; then
	echo "== thor (Zig)"
	(
		cd "$thor"
		"$ZIG" build -Dxbps-src="$src" --prefix "$dest/usr"
	)
fi
echo "== готово: $dest"
