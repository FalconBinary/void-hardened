#!/bin/sh
# Тест vh-deep-clean на настоящем xbps: что удаляется, что остаётся, резерв и restore.
#   sh tests/zig/clean_test.sh КАТАЛОГ_СБОРКИ
# Только в одноразовом контейнере Void: ставит и удаляет пакеты, заводит пользователей,
# пишет в /etc, /var/lib/vh, /var/cache/xbps.
set -u
b=${1:?"каталог с vh-deep-clean и vh-pkg"}
dc=$b/vh-deep-clean
bad=0
ok() { echo "ok $*"; }
no() { echo "ОШИБКА: $*"; bad=$((bad + 1)); }
t() { if eval "$2"; then ok "$1"; else no "$1"; fi; }

# ---- мусор
xbps-install -Sy >/dev/null 2>&1
mkdir -p /etc/vh /etc/sv/real /etc/runit/runsvdir/default
printf 'VH_KERNEL="linux6.18"\nVH_BROWSER_USER="browser"\n' > /etc/vh/vh.env
# (vh-pkg rm удаляет и всех сирот — поэтому до них) конфиг пакета, удалённого через vh-pkg rm (журнал /var/lib/vh/removed-conf.list)
xbps-install -y dhcpcd >/dev/null 2>&1
echo "# правка" >> /etc/dhcpcd.conf
"$b/vh-pkg" rm dhcpcd >/dev/null 2>&1
t "vh-pkg rm записал конфиг в журнал" 'grep -qx /etc/dhcpcd.conf /var/lib/vh/removed-conf.list'
# сирота с изменённым конфигом; сирота из keep-списка с зависимостью; просто сирота
xbps-install -Ay chrony tree jq >/dev/null 2>&1
echo "# правка" >> /etc/chrony.conf
printf '# keep\njq\n/etc/keep.conf.new-2.0_1\n' > /etc/vh/deep-clean.keep
# *.new-ВЕРСИЯ от xbps и похожие имена, которые трогать нельзя
echo new > /etc/foo.conf.new-1.2_1
echo x > /etc/bar.new-notversion
echo x > /etc/vh/x.conf.new-1.0_1
echo x > /etc/keep.conf.new-2.0_1
# сервисы: битая и живая ссылки
ln -s /etc/sv/ghost /etc/runit/runsvdir/default/ghost
ln -s /etc/sv/real /etc/runit/runsvdir/default/real
# пользователи: кэш, занятый файл, корзина, ловушки-симлинки; root; браузер
useradd -m -u 1000 alice
mkdir -p /home/alice/.cache/a/b /home/alice/.cache/busy /home/alice/.local/share/Trash/files /home/alice/.config
head -c 300000 /dev/urandom > /home/alice/.cache/a/b/blob
echo busy > /home/alice/.cache/busy/f
echo trash > /home/alice/.local/share/Trash/files/old.txt
echo conf > /home/alice/.config/app.conf
ln -s /etc /home/alice/.cache/evil-dir
ln -s /etc/passwd /home/alice/.cache/a/evil-file
chown -R alice:alice /home/alice
setpriv --reuid=alice --regid=alice --init-groups sh -c 'exec 3</home/alice/.cache/busy/f; exec sleep 600' &
holder=$!
mkdir -p /root/.cache/r && echo r > /root/.cache/r/f
useradd -r -m -d /var/lib/vh-browser browser
mkdir -p /var/lib/vh-browser/trusted/profile/cache2/entries /var/lib/vh-browser/trusted/.cache/mozilla
echo c > /var/lib/vh-browser/trusted/profile/cache2/entries/x
echo 'user_pref("a", 1);' > /var/lib/vh-browser/trusted/profile/prefs.js
echo m > /var/lib/vh-browser/trusted/.cache/mozilla/y
chown -R browser:browser /var/lib/vh-browser
# xbps при удалении пакета сам меняет строку его системного пользователя (chrony)
passwd_same() { [ "$(grep -v '^chrony:' /etc/passwd)" = "$(grep -v '^chrony:' /tmp/passwd.orig)" ]; }
cp /etc/passwd /tmp/passwd.orig
sleep 1

snap() {
	find /etc /home /root /var/lib/vh-browser /var/lib/vh /var/cache/xbps -xdev \
		-printf '%p %s %m %T@\n' 2>/dev/null | sort | sha256sum
	xbps-query -l | sha256sum
}

# ---- план ничего не меняет
s1=$(snap)
"$dc" --user > /tmp/plan.txt 2>&1
s2=$(snap)
t "план: система не изменилась" '[ "$s1" = "$s2" ]'
t "план: сирота tree в списке" 'grep -q "^   tree-" /tmp/plan.txt'
t "план: keep-пакет jq показан как остающийся" 'grep -q "остаётся.*: jq" /tmp/plan.txt'
t "план: .new-файл в списке" 'grep -q "/etc/foo.conf.new-1.2_1" /tmp/plan.txt'
t "план: конфиг из журнала vh-pkg в списке" 'grep -q "/etc/dhcpcd.conf" /tmp/plan.txt'
t "план: битая ссылка сервиса в списке" 'grep -q "default/ghost" /tmp/plan.txt'
t "план: занятый кэш показан как остающийся" 'grep -q "остаётся: busy" /tmp/plan.txt'
t "план: ядра — группа пропущена без ядра в базе" 'grep -q "группа пропущена" /tmp/plan.txt'
t "-y без --apply — ошибка" '! "$dc" -y >/dev/null 2>&1'

# ---- выполнение
"$dc" --apply -y --user > /tmp/apply.txt 2>&1
rc=$?
t "выполнение: код 0, новых ошибок базы пакетов нет" '[ $rc = 0 ] && grep -q "^Система в порядке" /tmp/apply.txt'
t "сироты: tree и chrony удалены" '! xbps-query tree >/dev/null && ! xbps-query chrony >/dev/null'
t "keep: jq и его зависимость oniguruma остались, jq — ручной" \
	'xbps-query jq >/dev/null && xbps-query oniguruma >/dev/null && xbps-query -m | grep -q "^jq-"'
t "изменённый конфиг сироты — в резерве" \
	'[ ! -e /etc/chrony.conf ] && grep -q правка /var/lib/vh/deep-clean/last/root/etc/chrony.conf'
t "конфиг из журнала — в резерве, журнал очищен" \
	'[ ! -e /etc/dhcpcd.conf ] && [ -e /var/lib/vh/deep-clean/last/root/etc/dhcpcd.conf ] && [ ! -e /var/lib/vh/removed-conf.list ]'
t ".new-файл — в резерве" '[ ! -e /etc/foo.conf.new-1.2_1 ]'
t "похожее имя, /etc/vh и keep-путь остались" \
	'[ -e /etc/bar.new-notversion ] && [ -e /etc/vh/x.conf.new-1.0_1 ] && [ -e /etc/keep.conf.new-2.0_1 ]'
t "чужие конфиги пакетов на месте" '[ -e /etc/hosts ] && passwd_same'
t "битая ссылка сервиса убрана, живая осталась" \
	'[ ! -L /etc/runit/runsvdir/default/ghost ] && [ -L /etc/runit/runsvdir/default/real ]'
t "кэш xbps пуст" '[ -z "$(find /var/cache/xbps -type f)" ]'
t "~/.cache очищен, занятое осталось" \
	'[ ! -e /home/alice/.cache/a ] && [ -e /home/alice/.cache/busy/f ]'
t "симлинк-ловушки удалены как ссылки, /etc цел" \
	'[ ! -L /home/alice/.cache/evil-dir ] && [ -d /etc/sv ] && passwd_same'
t "корзина пуста, ~/.config цел" \
	'[ -z "$(ls -A /home/alice/.local/share/Trash 2>/dev/null)" ] && [ -e /home/alice/.config/app.conf ]'
t "кэш root очищен" '[ ! -e /root/.cache/r ]'
t "кэш Firefox очищен, профиль цел" \
	'[ ! -e /var/lib/vh-browser/trusted/profile/cache2/entries ] && [ ! -e /var/lib/vh-browser/trusted/.cache/mozilla ] && [ -e /var/lib/vh-browser/trusted/profile/prefs.js ]'
t "резерв закрыт: 0700" '[ "$(stat -c %a /var/lib/vh/deep-clean/last)" = 700 ]'
t "итог напечатан" 'grep -q "^Освобождено: " /tmp/apply.txt'

# ---- Firefox запущен — кэш браузера не трогается
mkdir -p /var/lib/vh-browser/trusted/profile/cache2/z && chown -R browser:browser /var/lib/vh-browser
setpriv --reuid=browser --regid=browser --init-groups sleep 600 &
fx=$!
sleep 1
"$dc" --apply -y --only user > /tmp/fx.txt 2>&1
t "браузер работает — его кэш пропущен" \
	'grep -q "Firefox запущен" /tmp/fx.txt && [ -d /var/lib/vh-browser/trusted/profile/cache2/z ]'
kill $fx 2>/dev/null

# ---- restore
"$dc" restore > /tmp/restore.txt 2>&1
echo "restore rc=$?"
t "restore вернул конфиги, .new и ссылку сервиса" \
	'grep -q правка /etc/chrony.conf && grep -q правка /etc/dhcpcd.conf && [ -e /etc/foo.conf.new-1.2_1 ] && [ -L /etc/runit/runsvdir/default/ghost ]'
t "резерв после restore удалён" '[ ! -e /var/lib/vh/deep-clean/last ]'
t "второй restore — ошибка «резерва нет»" '! "$dc" restore >/dev/null 2>&1'

# ---- повторный запуск: убирать нечего, кроме вернувшегося
"$dc" --apply -y --only services > /dev/null 2>&1
"$dc" --only services > /tmp/again.txt 2>&1
t "повторно: ссылок сервисов нет" 'grep -A1 "services:" /tmp/again.txt | grep -q "нет"'

kill $holder 2>/dev/null
if [ $bad != 0 ]; then
	echo "--- план"; cat /tmp/plan.txt; echo "--- выполнение"; cat /tmp/apply.txt
fi
echo "vh-deep-clean: ошибок $bad"
[ $bad = 0 ]
