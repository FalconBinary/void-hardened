#!/bin/sh
# Пакет thor заменяет xbps и libxbps на настоящей системе Void (docs/18).
#   sh tests/thor/package_test.sh КАТАЛОГ_УСТАНОВКИ_THOR
# Только в одноразовом контейнере Void: ставит thor вместо штатного xbps.
set -eu
d=${1:?"DESTDIR сборки thor"}
repo_src=$(cd "$(dirname "$0")/../.." && pwd)
w=$(mktemp -d)
fail=0
okk() { echo "ok $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { if eval "$2"; then okk "$1"; else bad "$1"; fi; }
arch=$(xbps-uhelper arch)

# без ACL и xattr исходного каталога (том хоста в docker)
cp -R "$d" "$w/dest"
check "rpath: xbps-install берёт libxbps из своего дерева" \
	'env -u LD_LIBRARY_PATH ldd "$w/dest/usr/bin/xbps-install" | grep -q "$w/dest/usr/bin/../lib/libxbps.so.6\|$w/dest/usr/lib/libxbps.so.6"'
check "rpath: thor тоже" 'ldd "$w/dest/usr/bin/thor" | grep -q "$w/dest/usr/bin/../lib/libxbps.so.6\|$w/dest/usr/lib/libxbps.so.6"'
sh "$repo_src/thor/package.sh" "$w/dest" "$arch" /var/lib/thor/repo >/dev/null
echo "repository=/var/lib/thor/repo" > /etc/xbps.d/01-thor.conf
printf 'ignorepkg=xbps\nignorepkg=libxbps\n' > /etc/xbps.d/20-vh-ignorepkg.conf
mkdir -p /etc/thor; echo mode=enforce > /etc/thor/policy.conf
xbps-install -S >/dev/null 2>&1

echo "== установка thor штатным xbps"
xbps-install -y thor > "$w/inst.log" 2>&1 || { cat "$w/inst.log"; bad "установка thor"; }
check "thor установлен" 'xbps-query -p pkgver thor | grep -q "^thor-"'
check "xbps удалён из pkgdb" '! xbps-query -p pkgver xbps 2>/dev/null | grep -q "^xbps-"'
check "libxbps удалён из pkgdb" '! xbps-query -p pkgver libxbps 2>/dev/null | grep -q "^libxbps-"'
check "/usr/bin/xbps-install принадлежит thor" '[ "$(xbps-query -o /usr/bin/xbps-install | cut -d: -f1)" = "$(xbps-query -p pkgver thor)" ]'
check "/usr/bin/thor работает" 'thor --version | grep -q "^thor "'
check "ключ Void на месте" '[ -f "/var/db/xbps/keys/60:ae:0c:d6:f0:95:17:80:bc:93:46:7a:89:af:a3:2d.plist" ]'
check "libxbps — с политикой" 'grep -q thor_unpack_entry /usr/lib/libxbps.so.6'

echo "== система с thor"
check "xbps-install -Su: нет обновлений самого xbps по кругу" 'xbps-install -Sun > "$w/u.log" 2>&1; ! grep -q "^xbps-[0-9]" "$w/u.log"'
check "xbps-install xbps не заменяет thor (xbps — виртуальный пакет thor)" 'xbps-install -y xbps >/dev/null 2>&1; xbps-query -p pkgver thor | grep -q "^thor-" && ! xbps-query -p pkgver xbps | grep -q "^xbps-"'
check "зависимость на xbps удовлетворена thor (virtual)" 'xbps-query -p provides thor | grep -q "^xbps-"'
check "xbps-pkgdb thor: файлы пакета целы" 'xbps-pkgdb thor > "$w/pkgdb.log" 2>&1 || { cat "$w/pkgdb.log"; false; }'
check "thor install: пакет из официального репозитория" 'thor install -y tree > "$w/tree.log" 2>&1 && xbps-query tree >/dev/null'
check "thor remove" 'thor remove -y tree > /dev/null 2>&1 && ! xbps-query tree >/dev/null 2>&1'
check "чёрный список: fuse3 без разрешения не ставится" '! thor install -y fuse3 > "$w/deny.log" 2>&1 && grep -q "fuse3.*запрещён" "$w/deny.log"'
echo fuse3 > /etc/thor/allow.conf
check "SUID снимается и у официальных пакетов (fusermount3)" 'thor install -y fuse3 > "$w/fuse.log" 2>&1; [ -f /usr/bin/fusermount3 ] && [ ! -u /usr/bin/fusermount3 ] && grep -q "SUID/SGID снят: /usr/bin/fusermount3" "$w/fuse.log"'

[ "$fail" = 0 ] && echo "ok все проверки пакета thor" || exit 1
