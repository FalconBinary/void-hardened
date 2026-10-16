#!/bin/bash
# Сборка netline в RAM live-среды и установка готовых бинарников в целевой корень.
#   build-netline.sh /mnt
#
# Почему так: в репозитории Void есть только zig 0.13, а netline нужен 0.17,
# и в установленной системе компилятора быть не должно (docs/08). Компилятор
# скачивается с ziglang.org (install/fetch-zig.sh: подпись minisign и контрольная
# сумма), живёт в /tmp (RAM) и исчезает после перезагрузки. Сборка — то же, что
# «параноидальный вариант» из модуля 3: из проверенной live-среды.

. "$(dirname "$0")/lib.sh"
load_config "${VH_CONFIG:-$VH_ROOT/vh.conf}"
TARGET=${1:?укажите целевой корень, например /mnt}

# в live-образе нет git — ставится в RAM live-среды
command -v git >/dev/null || xbps-install -Sy git >/dev/null || die "не удалось поставить git в live-среду"

WORK=$(mktemp -d /tmp/vh-netline.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
# компилятор: загрузка, подпись minisign и контрольная сумма — install/fetch-zig.sh
# тот же Zig и тот же каталог, что у build-tools.sh и build-thor.sh: один компилятор на всё
ZIG_VERSION=$(cat "$VH_ROOT/zig/ZIG_VERSION")
ZIG=$(bash "$VH_ROOT/install/fetch-zig.sh" "$ZIG_VERSION" /tmp/vh-zig)
cd "$WORK"
"$ZIG" version

say "netline: исходники $VH_NETLINE_REPO @ $VH_NETLINE_REF"
git clone --quiet "$VH_NETLINE_REPO" netline
git -C netline -c advice.detachedHead=false checkout --quiet "$VH_NETLINE_REF"
commit=$(git -C netline rev-parse HEAD)
ok "коммит $commit"

# Настройки netline задаются в src/config.zig при сборке. Для void-hardened:
# Bluetooth по требованию — zbt сам запускает и останавливает сервис через doas.
if [ "$VH_BLUETOOTH" = optional ]; then
	sed -i \
		-e 's|^pub const bt_service_on_cmd: ?\[\*:0\]const u8 = null;|pub const bt_service_on_cmd: ?[*:0]const u8 = "doas -n /usr/local/sbin/vh-bluetooth on";|' \
		-e 's|^pub const bt_service_off_cmd: ?\[\*:0\]const u8 = null;|pub const bt_service_off_cmd: ?[*:0]const u8 = "doas -n /usr/local/sbin/vh-bluetooth off";|' \
		netline/src/config.zig
	grep -q 'vh-bluetooth on' netline/src/config.zig || warn "в этой версии netline нет bt_service_on_cmd — Bluetooth включается только командой vh-bluetooth"
fi

say "сборка (ReleaseSafe)"
( cd netline && "$ZIG" build -Doptimize=ReleaseSafe --cache-dir "$WORK/cache" \
	--global-cache-dir "$WORK/gcache" -p "$WORK/out" )

say "установка в $TARGET/usr/local/bin"
install -d -m 0755 "$TARGET/usr/local/bin" "$TARGET/etc/vh"
for b in "$WORK"/out/bin/*; do
	install -m 0755 -o root -g root "$b" "$TARGET/usr/local/bin/"
done
{
	echo "# netline $commit, zig $ZIG_VERSION, собрано $(date -u +%Y-%m-%dT%H:%MZ)"
	( cd "$TARGET/usr/local/bin" && for b in "$WORK"/out/bin/*; do sha256sum "$(basename "$b")"; done )
} > "$TARGET/etc/vh/netline.sha256"
ok "$(ls "$WORK/out/bin" | tr '\n' ' ')"
