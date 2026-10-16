#!/bin/sh
# Команда thor: параллельная загрузка, запасные зеркала, проверка подписей (docs/18).
#   sh tests/thor/fetch_test.sh КАТАЛОГ_УСТАНОВКИ_THOR
# Только в одноразовом контейнере Void: два HTTP-зеркала (python3 -m http.server) с
# подписанным тестовым репозиторием, установка в корень контейнера.
set -eu
d=${1:?"DESTDIR сборки thor"}
export LD_LIBRARY_PATH=$d/usr/lib
X=$d/usr/bin
w=$(mktemp -d)
fail=0
okk() { echo "ok $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { if eval "$2"; then okk "$1"; else bad "$1"; fi; }
arch=$("$X/xbps-uhelper" arch)

command -v openssl >/dev/null || xbps-install -Sy openssl >/dev/null 2>&1

# --- подписанный репозиторий: good — всё, bad — только индекс (пакеты отдают 404)
mkdir -p "$w/good/current" "$w/bad/current" "$w/pk"
openssl genrsa -out "$w/key.pem" 2048 2>/dev/null
cd "$w/pk"
for i in $(seq 1 12); do
	mkdir -p "p$i/usr/share/t-pkg$i"
	head -c 300000 /dev/urandom > "p$i/usr/share/t-pkg$i/data"
	"$X/xbps-create" -A "$arch" -n "t-pkg$i-1.0_1" -s "тест thor $i" "p$i" >/dev/null
done
mkdir -p evil/usr/share/t-evil; echo good > evil/usr/share/t-evil/x
"$X/xbps-create" -A "$arch" -n "t-evil-1.0_1" -s "тест подмены" evil >/dev/null
mv ./*.xbps "$w/good/current/"
cd "$w/good/current"
"$X/xbps-rindex" -a ./*.xbps >/dev/null 2>&1
"$X/xbps-rindex" --sign --signedby "thor-test" --privkey "$w/key.pem" . >/dev/null 2>&1
"$X/xbps-rindex" --sign-pkg --privkey "$w/key.pem" ./*.xbps >/dev/null 2>&1
# подмена: пакет t-evil заменён другим содержимым, подпись — от настоящего
mkdir -p "$w/pk/evil2/usr/share/t-evil"; echo EVIL > "$w/pk/evil2/usr/share/t-evil/x"
(cd "$w/pk" && "$X/xbps-create" -A "$arch" -n "t-evil-1.0_1" -s "тест подмены" evil2 >/dev/null && mv "t-evil-1.0_1.$arch.xbps" "$w/good/current/")
cp "$w/good/current/$arch-repodata" "$w/bad/current/"

(cd "$w/good" && exec python3 -m http.server 8001 --bind 127.0.0.1 >/dev/null 2>&1) &
(cd "$w/bad" && exec python3 -m http.server 8002 --bind 127.0.0.1 >/dev/null 2>&1) &
sleep 1

mkdir -p /etc/xbps.d /etc/thor
# то же имя, что у файла в /usr/share/xbps.d, — официальный репозиторий отключается:
# тест не ходит в сеть, а штатный xbps контейнера не попадает в транзакцию
echo "repository=http://127.0.0.1:8002/current" > /etc/xbps.d/00-repository-main.conf
for f in /usr/share/xbps.d/*repository*; do [ -e "$f" ] && : > "/etc/xbps.d/${f##*/}"; done
echo "repository=http://127.0.0.1:8002/current" > /etc/xbps.d/00-repository-main.conf
printf 'parallel=4\nmirror-fallback=http://127.0.0.1:8001\n' > /etc/thor/thor.conf
echo "mode=enforce" > /etc/thor/policy.conf
rm -rf /var/cache/xbps; mkdir -p /var/cache/xbps
# ключ репозитория: импорт при первой синхронизации (вопрос — «y»)
yes y | "$X/xbps-install" -S >/dev/null 2>&1 || true

pkgs=""; for i in $(seq 1 12); do pkgs="$pkgs t-pkg$i"; done

echo "== thor install: основное зеркало без пакетов, запасное — с ними"
# shellcheck disable=SC2086
"$X/thor" install -y $pkgs > "$w/inst.log" 2>&1 || { cat "$w/inst.log"; bad "thor install"; }
check "загрузка в 4 потока" 'grep -q "Загрузка 12 пакетов .* в 4 потока" "$w/inst.log"'
check "все 12 скачаны" '[ "$(grep -c "^  \[[0-9]*/12\] t-pkg" "$w/inst.log")" = 12 ] && ! grep -q "НЕ скачан" "$w/inst.log"'
check "все 12 установлены" '[ "$("$X/xbps-query" -l | grep -c " t-pkg")" = 12 ]'
check "подписи из кэша проверены xbps" 'grep -qi "verifying\|Verifying" "$w/inst.log"'
check "файлы на месте" '[ -s /usr/share/t-pkg7/data ]'

echo "== подменённый пакет: xbps-install отказывается"
if "$X/thor" install -y t-evil > "$w/evil.log" 2>&1; then bad "подменённый пакет установлен"; else okk "подменённый пакет не установлен"; fi
check "причина — подпись" 'grep -qi "signature\|подпис" "$w/evil.log"'
check "файл подмены не появился" '[ ! -e /usr/share/t-evil/x ]'

echo "== thor fetch: только скачать"
"$X/xbps-remove" -Ry t-pkg1 t-pkg2 >/dev/null 2>&1
rm -f /var/cache/xbps/t-pkg1-* /var/cache/xbps/t-pkg2-*
"$X/thor" fetch -j 1 t-pkg1 t-pkg2 > "$w/fetch.log" 2>&1 || { cat "$w/fetch.log"; bad "thor fetch"; }
check "fetch: -j 1 — один поток" 'grep -q "в 1 потока" "$w/fetch.log"'
check "fetch: пакеты и подписи в кэше" '[ -f "/var/cache/xbps/t-pkg1-1.0_1.$arch.xbps" ] && [ -f "/var/cache/xbps/t-pkg1-1.0_1.$arch.xbps.sig2" ]'
check "fetch: не установлены" '! "$X/xbps-query" t-pkg1 >/dev/null 2>&1'
"$X/thor" install -y t-pkg1 > "$w/cached.log" 2>&1 || { cat "$w/cached.log"; bad "установка из кэша"; }
check "из кэша: повторно не качает" '! grep -q "Загрузка" "$w/cached.log"'

echo "== команды политики"
"$X/thor" keep /usr/bin/t-test > "$w/keep.log" 2>&1
check "keep: путь записан" 'grep -qx /usr/bin/t-test /etc/thor/keep.conf'
"$X/thor" keep /usr/bin/t-test > /dev/null 2>&1
check "keep: без дублей" '[ "$(grep -c t-test /etc/thor/keep.conf)" = 1 ]'
echo y | "$X/thor" allow cups > "$w/allow.log" 2>&1
check "allow: с причиной и подтверждением" 'grep -q "сервер печати" "$w/allow.log" && grep -qx cups /etc/thor/allow.conf'
echo n | "$X/thor" allow polkit > /dev/null 2>&1 || true
check "allow: отказ — не записан" '! grep -qx polkit /etc/thor/allow.conf'
"$X/thor" allow firefox > "$w/allow2.log" 2>&1
check "allow: не из списка — нечего разрешать" 'grep -q "не в чёрном списке" "$w/allow2.log"'
"$X/thor" baseline > "$w/base.log" 2>&1 || { cat "$w/base.log"; bad "thor baseline"; }
check "baseline: записан" 'grep -q "Записан командой thor baseline" /etc/thor/baseline'
"$X/thor" policy > "$w/policy.log" 2>&1
check "policy: показывает режим" 'grep -q "режим: enforce" "$w/policy.log"'

kill %1 %2 2>/dev/null || true
[ "$fail" = 0 ] && echo "ok все проверки thor" || exit 1
