#!/bin/sh
# vh-pkg (Zig) на системе с thor: обёртка над thor install/keep, --ignore, журнал конфигов.
#   sh tests/thor/vhpkg_test.sh ПУТЬ_К_VH-PKG
# Запускается после package_test.sh в том же контейнере (thor уже заменил xbps).
set -eu
P=${1:?"vh-pkg"}
w=$(mktemp -d)
fail=0
okk() { echo "ok $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { if eval "$2"; then okk "$1"; else bad "$1"; fi; }
rm -f /etc/thor/allow.conf

check "add: ставит через thor" '"$P" add -y tree > "$w/add.log" 2>&1 && xbps-query tree >/dev/null'
check "add: запрещённый пакет — отказ с причиной" '! "$P" add -y polkit > "$w/deny.log" 2>&1 && grep -q "polkit.*запрещён" "$w/deny.log"'
check "add --ignore: ignorepkg записан" '"$P" add -y tree --ignore gcc > /dev/null 2>&1; grep -qx "ignorepkg=gcc" /etc/xbps.d/51-vh-pkg-ignore.conf'
check "add --keep: исключение политики thor" '"$P" add -y tree --keep /usr/bin/t-keep > /dev/null 2>&1; grep -qx /usr/bin/t-keep /etc/thor/keep.conf'
check "scan: без ошибки" '"$P" scan tree > "$w/scan.log" 2>&1 && grep -q "thor" "$w/scan.log"'
"$P" add -y chrony > /dev/null 2>&1
echo "# изменено" >> /etc/chrony.conf
check "rm: удаляет" '"$P" rm chrony > /dev/null 2>&1 && ! xbps-query chrony >/dev/null 2>&1'
check "rm: изменённый конфиг — в журнале для vh-deep-clean" 'grep -qx /etc/chrony.conf /var/lib/vh/removed-conf.list'
check "неизвестная команда — код 2" '"$P" xyz >/dev/null 2>&1; [ $? = 2 ]'

[ "$fail" = 0 ] && echo "ok все проверки vh-pkg" || exit 1
