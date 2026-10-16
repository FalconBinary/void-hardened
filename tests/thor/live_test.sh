#!/bin/sh
# Путь установщика в live-среде (как 10-install.sh): build-thor.sh, установка пакетов в
# пустой корень через thor в режиме learn, build-tools.sh, затем enforce.
#   sh tests/thor/live_test.sh     — в одноразовом контейнере Void родной архитектуры
#   (на Mac — aarch64: Zig под эмуляцией amd64 падает; логика скриптов от архитектуры не зависит)
# Нужна сеть: Zig с ziglang.org, xbps с GitHub, пакеты с зеркала Void.
set -eu
R=/tmp/root
A=$(xbps-uhelper arch)
case $A in x86_64) M=https://repo-default.voidlinux.org/current ;; *) M=https://repo-default.voidlinux.org/current/$A ;; esac
fail=0
okk() { echo "ok $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { if eval "$2"; then okk "$1"; else bad "$1"; fi; }
cd /src
mkdir -p "$R/var/db/xbps/keys" "$R/etc/xbps.d"
cp -a /var/db/xbps/keys/. "$R/var/db/xbps/keys/"
for f in rootfs/etc/xbps.d/*; do
	b=$(basename "$f")
	case $b in
		*.in) sed "s|@VH_MIRROR@/current|$M|" "$f" > "$R/etc/xbps.d/${b%.in}" ;;
		*) install -m 0644 "$f" "$R/etc/xbps.d/$b" ;;
	esac
done

echo "== build-thor.sh"
bash install/build-thor.sh "$R" > /tmp/bt.log 2>&1 || { tail -30 /tmp/bt.log; exit 1; }
check "пакет thor в локальном репозитории" 'ls $R/var/lib/thor/repo/thor-*.xbps >/dev/null'
check "01-thor.conf" 'grep -q "^repository=/var/lib/thor/repo" $R/etc/xbps.d/01-thor.conf'
check "ссылка /var/lib/thor/repo в live-среде" '[ -L /var/lib/thor/repo ]'
check "thor берёт libxbps из своего дерева (rpath)" 'ldd /tmp/vh-thor/dest/usr/bin/thor | grep -q "/tmp/vh-thor/dest/usr/bin/../lib/libxbps"'

echo "== установка в пустой корень (learn), как 10-install.sh"
printf 'mode=learn\n' > "$R/etc/thor/policy.conf"
/tmp/vh-thor/dest/usr/bin/thor install -y -r "$R" \
	-R $M \
	base-files thor runit-void bash coreutils opendoas socklog-void util-linux shadow dracut eudev pam linux-base \
	> /tmp/inst.log 2>&1 || { tail -40 /tmp/inst.log; exit 1; }
check "параллельная загрузка" 'grep -q "Загрузка .* пакетов" /tmp/inst.log'
check "thor установлен в корень вместо xbps" 'xbps-query -r $R -p pkgver thor | grep -q ^thor- && ! xbps-query -r $R -p pkgver xbps | grep -q ^xbps-'
check "в корне libxbps с политикой" 'grep -q thor_unpack_entry $R/usr/lib/libxbps.so.6'
check "learn: все хуки kernel.d нового корня — в baseline" '[ -n "$(cd $R && find etc/kernel.d -type f)" ] && ( for f in $(cd $R && find etc/kernel.d -type f); do grep -qx "/$f" $R/etc/thor/baseline || exit 1; done )'
check "learn: модули dracut в baseline" 'grep -q "^/usr/lib/dracut/modules.d/" $R/etc/thor/baseline'
check "learn: правила udev 0666 eudev в baseline, не замаскированы" 'grep -q "^/usr/lib/udev/rules.d/" $R/etc/thor/baseline && [ ! -e $R/etc/udev/rules.d/50-udev-default.rules ]'
check "SUID: doas остался" '[ -u $R/usr/bin/doas ]'
check "SUID: у остальных снят (mount, passwd, su нет)" '! find $R/usr -xdev -perm -4000 -type f | grep -v -e /usr/bin/doas -e /usr/bin/unix_chkpwd'
check "cap_syslog у nanoklogd на месте" 'getcap $R/usr/bin/nanoklogd | grep -q cap_syslog'
check "журнал политики" 'grep -q "SUID/SGID снят" $R/var/log/thor.log'

echo "== build-tools.sh"
mkdir -p "$R/usr/local" "$R/root/vh/tools"
bash install/build-tools.sh "$R" > /tmp/tools.log 2>&1 || { tail -30 /tmp/tools.log; exit 1; }
check "инструменты на месте" '[ -x $R/usr/local/bin/vh-wlfilter ] && [ -x $R/usr/local/sbin/vh-pkg ] && [ -x $R/root/vh/tools/vh-hashpw ]'
check "статические (без библиотек системы)" 'ldd $R/usr/local/bin/vh-wlfilter 2>&1 | grep -q "statically linked\|not a dynamic"'
check "vh-seccomp --selftest" '$R/usr/local/libexec/vh/vh-seccomp --selftest | grep -q "selftest: OK"'

printf 'mode=enforce\n' > "$R/etc/thor/policy.conf"
echo "== enforce: установка в корень пакета с хуком dracut — модуль не распакован"
/tmp/vh-thor/dest/usr/bin/thor install -y -r "$R" tpm2-totp > /tmp/totp.log 2>&1 || { tail -20 /tmp/totp.log; bad "tpm2-totp"; }
check "enforce: модуль dracut tpm2-totp не распакован" '[ ! -e $R/usr/lib/dracut/modules.d/70tpm2-totp/module-setup.sh ] && grep -q "70tpm2-totp" /tmp/totp.log'

[ "$fail" = 0 ] && echo "ok все проверки пути live-среды" || exit 1
