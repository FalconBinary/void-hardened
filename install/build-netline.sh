#!/bin/bash
# Сборка netline в RAM live-среды и установка готовых бинарников в целевой корень.
#   build-netline.sh /mnt
#
# Почему так: в репозитории Void есть только zig 0.13, а netline нужен 0.16,
# и в установленной системе компилятора быть не должно (docs/08). Компилятор
# скачивается с ziglang.org, проверяется подписью minisign и контрольной суммой,
# живёт в /tmp (RAM) и исчезает после перезагрузки. Сборка — то же, что
# «параноидальный вариант» из модуля 3: из проверенной live-среды.

. "$(dirname "$0")/lib.sh"
load_config "${VH_CONFIG:-$VH_ROOT/vh.conf}"
TARGET=${1:?укажите целевой корень, например /mnt}

# Ключ подписи релизов Zig, опубликован на https://ziglang.org/download/.
# Сверьте его по второму независимому каналу (docs/08), прежде чем доверять.
ZIG_PUBKEY="RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
# Контрольные суммы известных версий (из https://ziglang.org/download/index.json).
declare -A ZIG_SHA256=(
	[0.16.0]=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
)

# в live-образе нет xz (архив Zig — .tar.xz), git и minisign — ставятся в RAM live-среды
for t in minisign git xz; do
	command -v "$t" >/dev/null || xbps-install -Sy "$t" >/dev/null || die "не удалось поставить $t в live-среду"
done

WORK=$(mktemp -d /tmp/vh-netline.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

tarball=zig-x86_64-linux-$VH_ZIG_VERSION.tar.xz
url=https://ziglang.org/download/$VH_ZIG_VERSION/$tarball
say "Zig $VH_ZIG_VERSION: загрузка и проверка подписи"
xbps-fetch -o "$tarball" "$url"
xbps-fetch -o "$tarball.minisig" "$url.minisig"
minisign -Vm "$tarball" -x "$tarball.minisig" -P "$ZIG_PUBKEY" || die "подпись Zig не сошлась"
if [ -n "${ZIG_SHA256[$VH_ZIG_VERSION]:-}" ]; then
	echo "${ZIG_SHA256[$VH_ZIG_VERSION]}  $tarball" | sha256sum -c - || die "контрольная сумма Zig не сошлась"
else
	warn "для Zig $VH_ZIG_VERSION нет сохранённой контрольной суммы — проверена только подпись"
fi
tar -xJf "$tarball"
ZIG=$WORK/zig-x86_64-linux-$VH_ZIG_VERSION/zig
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
	echo "# netline $commit, zig $VH_ZIG_VERSION, собрано $(date -u +%Y-%m-%dT%H:%MZ)"
	( cd "$TARGET/usr/local/bin" && for b in "$WORK"/out/bin/*; do sha256sum "$(basename "$b")"; done )
} > "$TARGET/etc/vh/netline.sha256"
ok "$(ls "$WORK/out/bin" | tr '\n' ' ')"
