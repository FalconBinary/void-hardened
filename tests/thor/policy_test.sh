#!/bin/sh
# Политика thor внутри libxbps — сквозной тест на настоящем xbps (docs/18).
#   sh tests/thor/policy_test.sh КАТАЛОГ_УСТАНОВКИ_THOR
# Только в одноразовом контейнере Void: ставит тестовые пакеты в корень контейнера,
# пишет в /etc/thor, /etc/sysctl.d, /etc/udev. Нужны libcap-progs (setcap/getcap).
set -eu
d=${1:?"DESTDIR сборки thor"}
export LD_LIBRARY_PATH=$d/usr/lib
X=$d/usr/bin
w=$(mktemp -d)
fail=0
okk() { echo "ok $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { if eval "$2"; then okk "$1"; else bad "$1"; fi; }

# --- тестовые пакеты
mk() { # mk ИМЯ КАТАЛОГ_ФАЙЛОВ [опции xbps-create]
	name=$1 dir=$2; shift 2
	"$X/xbps-create" -A noarch -n "$name-1.0_1" -s "тест thor" "$@" "$dir" >/dev/null
	mv "$name-1.0_1.noarch.xbps" "$w/repo/"
}
mkdir -p "$w/repo"
cd "$w"

p=$w/p-suid
mkdir -p "$p/usr/bin"
printf '#!/bin/sh\n' > "$p/usr/bin/t-suid"; chmod 4755 "$p/usr/bin/t-suid"
printf '#!/bin/sh\n' > "$p/usr/bin/t-sgid"; chmod 2755 "$p/usr/bin/t-sgid"
printf '#!/bin/sh\n' > "$p/usr/bin/t-keep"; chmod 4755 "$p/usr/bin/t-keep"
printf '#!/bin/sh\n' > "$p/usr/bin/t-script"; chmod 0755 "$p/usr/bin/t-script"
printf '#!/bin/sh\n' > "$p/usr/bin/t-cap"; chmod 0755 "$p/usr/bin/t-cap"
# скрипт INSTALL возвращает SUID и ставит capability — это снимает разбор после настройки
cat > "$p/INSTALL" <<'EOF'
case "$2" in post) chmod u+s usr/bin/t-script; setcap cap_net_raw+ep usr/bin/t-cap ;; esac
EOF
mk t-suid "$p"

p=$w/p-hooks
mkdir -p "$p/etc/kernel.d/post-install" "$p/etc/profile.d" "$p/usr/lib/dracut/modules.d/99evil" \
	"$p/usr/lib/sysctl.d" "$p/usr/lib/udev/rules.d" "$p/etc/udev/rules.d" "$p/etc/sv/t-svc" "$p/usr/bin"
echo 'echo evil' > "$p/etc/kernel.d/post-install/50-evil"; chmod 0755 "$p/etc/kernel.d/post-install/50-evil"
echo 'echo evil' > "$p/etc/profile.d/evil.sh"
echo 'echo evil' > "$p/usr/lib/dracut/modules.d/99evil/module-setup.sh"
echo 'kernel.kptr_restrict = 0' > "$p/usr/lib/sysctl.d/99-evil.conf"
echo 'KERNEL=="evil", MODE="0666"' > "$p/usr/lib/udev/rules.d/99-evil.rules"
echo 'KERNEL=="evil2", MODE:="0777"' > "$p/etc/udev/rules.d/98-evil.rules"
echo 'KERNEL=="fine", GROUP="video", MODE="0660"' > "$p/usr/lib/udev/rules.d/60-fine.rules"
printf '#!/bin/sh\nexec sleep 1\n' > "$p/etc/sv/t-svc/run"; chmod 0755 "$p/etc/sv/t-svc/run"
echo x > "$p/usr/bin/t-ok"
mk t-hooks "$p"

p=$w/p-learn
mkdir -p "$p/etc/kernel.d/post-install" "$p/usr/lib/dracut/modules.d/90base" "$p/usr/lib/udev/rules.d"
echo 'echo base' > "$p/etc/kernel.d/post-install/20-base"
echo 'echo base' > "$p/usr/lib/dracut/modules.d/90base/module-setup.sh"
echo 'KERNEL=="null", MODE="0666"' > "$p/usr/lib/udev/rules.d/50-base.rules"
mk t-learn "$p"

p=$w/p-deny
mkdir -p "$p/usr/share/doc/polkit"
echo x > "$p/usr/share/doc/polkit/x"
mk polkit "$p"
p=$w/p-dep
mkdir -p "$p/usr/share/doc/t-dep"
echo x > "$p/usr/share/doc/t-dep/x"
mk t-dep "$p" -D "polkit>=0"

"$X/xbps-rindex" -a "$w"/repo/*.xbps >/dev/null 2>&1
inst() { "$X/xbps-install" -R "$w/repo" -y "$@"; }

mkdir -p /etc/thor
rm -f /etc/thor/* /var/log/thor.log

echo "== режим learn: базовая система"
echo "mode=learn" > /etc/thor/policy.conf
inst t-learn > "$w/learn.log" 2>&1 || { cat "$w/learn.log"; bad "установка в режиме learn"; }
check "learn: хук ядра распакован" '[ -f /etc/kernel.d/post-install/20-base ]'
check "learn: модуль dracut распакован" '[ -f /usr/lib/dracut/modules.d/90base/module-setup.sh ]'
check "learn: хук в baseline" 'grep -qx /etc/kernel.d/post-install/20-base /etc/thor/baseline'
check "learn: модуль dracut в baseline (каталогом)" 'grep -qx /usr/lib/dracut/modules.d/90base/ /etc/thor/baseline'
check "learn: правило udev 0666 в baseline" 'grep -qx /usr/lib/udev/rules.d/50-base.rules /etc/thor/baseline'
check "learn: правило udev базы не замаскировано" '[ ! -e /etc/udev/rules.d/50-base.rules ]'

echo "== режим enforce"
echo "mode=enforce" > /etc/thor/policy.conf
echo "/usr/bin/t-keep" > /etc/thor/keep.conf
inst t-suid t-hooks > "$w/enforce.log" 2>&1 || { cat "$w/enforce.log"; bad "установка в режиме enforce"; }
check "SUID снят при распаковке" '[ -f /usr/bin/t-suid ] && [ ! -u /usr/bin/t-suid ] && [ -x /usr/bin/t-suid ]'
check "SGID снят при распаковке" '[ ! -g /usr/bin/t-sgid ]'
check "keep.conf: SUID оставлен" '[ -u /usr/bin/t-keep ]'
check "SUID из скрипта INSTALL снят" '[ ! -u /usr/bin/t-script ]'
check "capability из скрипта INSTALL снята" '[ -z "$(getcap /usr/bin/t-cap)" ]'
check "хук ядра не распакован" '[ ! -e /etc/kernel.d/post-install/50-evil ]'
check "profile.d не распакован" '[ ! -e /etc/profile.d/evil.sh ]'
check "модуль dracut не распакован" '[ ! -e /usr/lib/dracut/modules.d/99evil/module-setup.sh ]'
check "sysctl.d замаскирован" 'grep -q "thor" /etc/sysctl.d/99-evil.conf'
check "udev 0666 в /usr/lib замаскирован" 'grep -q "thor" /etc/udev/rules.d/99-evil.rules'
check "udev 0777 в /etc удалён" '[ ! -e /etc/udev/rules.d/98-evil.rules ]'
check "обычное правило udev не тронуто" '[ -f /usr/lib/udev/rules.d/60-fine.rules ] && [ ! -e /etc/udev/rules.d/60-fine.rules ]'
check "обычный файл распакован" '[ -f /usr/bin/t-ok ]'
check "отчёт о сервисе runit" 'grep -q "сервис runit t-svc" "$w/enforce.log"'
check "журнал /var/log/thor.log" 'grep -q "SUID/SGID снят: /usr/bin/t-suid" /var/log/thor.log'

echo "== обновление не возвращает SUID (файл уже на диске, хэш совпадает)"
inst -f t-suid > "$w/reinst.log" 2>&1 || { cat "$w/reinst.log"; bad "переустановка"; }
check "переустановка: SUID не вернулся" '[ ! -u /usr/bin/t-suid ]'

echo "== настоящее обновление: файл тот же, xbps не распаковывает, а делает chmod по режиму пакета"
cd "$w/p-suid" && "$X/xbps-create" -A noarch -n "t-suid-1.1_1" -s "тест thor" . >/dev/null && mv t-suid-1.1_1.noarch.xbps "$w/repo/" && cd "$w"
"$X/xbps-rindex" -a "$w"/repo/t-suid-1.1_1.noarch.xbps >/dev/null 2>&1
inst -u t-suid > "$w/upd.log" 2>&1 || { cat "$w/upd.log"; bad "обновление"; }
check "обновление прошло" '"$X/xbps-query" -p pkgver t-suid | grep -q 1.1_1'
check "обновление: SUID не вернулся" '[ ! -u /usr/bin/t-suid ] && [ ! -g /usr/bin/t-sgid ]'
check "обновление: keep.conf — SUID на месте" '[ -u /usr/bin/t-keep ]'

echo "== чёрный список"
if inst polkit > "$w/deny.log" 2>&1; then bad "polkit поставился"; else okk "polkit не поставился"; fi
check "причина в выводе" 'grep -q "polkit-1.0_1 запрещён: SUID pkexec" "$w/deny.log"'
if inst t-dep > "$w/dep.log" 2>&1; then bad "зависимость polkit поставилась"; else okk "зависимость из чёрного списка тоже запрещена"; fi
check "проверка при -n (план)" '! "$X/xbps-install" -R "$w/repo" -n t-dep >/dev/null 2>&1'
echo polkit > /etc/thor/allow.conf
if inst t-dep > "$w/allow.log" 2>&1; then okk "allow.conf: разрешено"; else cat "$w/allow.log"; bad "allow.conf не сработал"; fi

[ "$fail" = 0 ] && echo "ok все проверки политики" || { echo "--- enforce.log"; cat "$w/enforce.log"; exit 1; }
