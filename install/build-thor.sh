#!/bin/bash
# void-hardened: thor — пакетный менеджер на основе xbps (docs/18): сборка в RAM
# live-среды, пакет thor и локальный репозиторий в целевой системе.
#   install/build-thor.sh ROOT
# Результат:
#   ROOT/var/lib/thor/repo     — репозиторий с пакетом thor (заменяет xbps и libxbps);
#   ROOT/etc/xbps.d/01-thor.conf — этот репозиторий в списке xbps;
#   /tmp/vh-thor/dest/usr/bin  — thor и xbps-* для установки системы из live-среды
#                                (10-install.sh ставит через них, уже с политикой).
# В live-среде /var/lib/thor/repo — ссылка на ROOT/var/lib/thor/repo: путь в
# 01-thor.conf один и тот же и во время установки, и в установленной системе.
#
# Обновление thor (новый xbps upstream или новая версия патчей): загрузиться с флешки,
# открыть и смонтировать корень в /mnt и запустить этот скрипт ещё раз, затем в системе
# doas xbps-install -Su thor. Локальный репозиторий подписывать не нужно: xbps сверяет
# пакет с sha256 из индекса, а писать в /var/lib/thor может только root.
set -euo pipefail
VH_ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$VH_ROOT/install/lib.sh"
. "$VH_ROOT/thor/UPSTREAM"
need_root
ROOT=${1:?"корень системы, например /mnt"}
[ "$(uname -m)" = x86_64 ] || die "нужен x86_64"
WORK=/tmp/vh-thor            # tmpfs live-среды
ZIG_VERSION=$(cat "$VH_ROOT/zig/ZIG_VERSION")
PKGVER=thor-$XBPS_VERSION.${THOR_REVISION}_1

say "thor: заголовки и инструменты сборки — в RAM live-среды (gcc не нужен)"
xbps-install -Sy openssl-devel libarchive-devel zlib-devel pkgconf make patch >/dev/null \
	|| die "не удалось поставить заголовки в live-среду"
ZIG=$(bash "$VH_ROOT/install/fetch-zig.sh" "$ZIG_VERSION" "$WORK/zig")
export ZIG

say "xbps $XBPS_VERSION: исходники (сверка с thor/UPSTREAM)"
mkdir -p "$WORK"
tarball=$WORK/xbps-$XBPS_VERSION.tar.gz
[ -f "$tarball" ] || xbps-fetch -o "$tarball" "$XBPS_URL"
echo "$XBPS_SHA256  $tarball" | sha256sum -c - >/dev/null || die "контрольная сумма xbps не совпадает с thor/UPSTREAM"
ok "sha256 совпадает (тот же архив, что в шаблоне Void)"

say "сборка thor: xbps + патчи + политика (Zig)"
rm -rf "$WORK/dest"
sh "$VH_ROOT/thor/build.sh" "$tarball" "$WORK/build" "$WORK/dest"
dest=$WORK/dest
"$dest/usr/bin/thor" --version >/dev/null || die "собранный thor не запускается"

say "пакет $PKGVER"
repo=$ROOT/var/lib/thor/repo
install -d -m 0755 "$repo"
sh "$VH_ROOT/thor/package.sh" "$dest" x86_64 "$repo" >/dev/null
ok "$repo/$PKGVER.x86_64.xbps"

install -d -m 0755 "$ROOT/etc/xbps.d" "$ROOT/etc/thor"
cat > "$ROOT/etc/xbps.d/01-thor.conf" <<'EOF'
# thor (docs/18): локальный репозиторий с пакетом thor — он заменяет xbps.
repository=/var/lib/thor/repo
EOF
# путь из 01-thor.conf — и в live-среде (установка в ROOT идёт отсюда)
if [ "$ROOT" != / ]; then
	install -d /var/lib/thor
	ln -sfn "$repo" /var/lib/thor/repo
fi
ok "thor собран: $dest/usr/bin"
