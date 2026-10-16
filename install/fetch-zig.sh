#!/bin/bash
# Компилятор Zig для сборки в RAM live-среды (netline, thor, инструменты zig/).
#   ZIG=$(install/fetch-zig.sh ВЕРСИЯ КАТАЛОГ)   — путь к zig на stdout, сообщения в stderr
#
# В репозитории Void Zig старый, а в установленной системе компилятора быть не должно
# (docs/05). Архив скачивается с ziglang.org в КАТАЛОГ (tmpfs live-среды) и проверяется
# дважды: подписью minisign ключом Zig (с проверкой имени файла в подписанном
# комментарии — иначе подошёл бы любой другой подписанный архив, например старой
# версии) и сохранённой здесь контрольной суммой.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
VER=${1:?"версия Zig, например 0.17.0"}
DIR=${2:?"каталог для компилятора (в RAM)"}

# Ключ подписи релизов Zig, опубликован на https://ziglang.org/download/.
# Сверьте его по второму независимому каналу (docs/08), прежде чем доверять.
ZIG_PUBKEY="RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
# Контрольные суммы (из https://ziglang.org/download/index.json, сверены с подписью
# minisign). aarch64 — только для тестов в контейнере на Apple Silicon.
declare -A ZIG_SHA256=(
	[0.16.0-x86_64]=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
	[0.17.0-x86_64]=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
	[0.17.0-aarch64]=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
)
ARCH=$(uname -m)

# в live-образе нет xz (архив Zig — .tar.xz) и minisign — ставятся в RAM live-среды
for t in minisign xz; do
	command -v "$t" >/dev/null || xbps-install -Sy "$t" >/dev/null || die "не удалось поставить $t в live-среду"
done

tarball=zig-$ARCH-linux-$VER.tar.xz
zig=$DIR/zig-$ARCH-linux-$VER/zig
if [ -x "$zig" ]; then
	echo "$zig"
	exit 0
fi
mkdir -p "$DIR"
cd "$DIR"
url=https://ziglang.org/download/$VER/$tarball
say "Zig $VER: загрузка и проверка подписи" >&2
xbps-fetch -o "$tarball" "$url" >&2
xbps-fetch -o "$tarball.minisig" "$url.minisig" >&2
minisign -Vm "$tarball" -x "$tarball.minisig" -P "$ZIG_PUBKEY" >&2 || die "подпись Zig не сошлась"
grep -q "^trusted comment: .*file:$tarball[[:space:]]" "$tarball.minisig" \
	|| die "подпись Zig выдана на другой файл, не $tarball"
if [ -n "${ZIG_SHA256[$VER-$ARCH]:-}" ]; then
	echo "${ZIG_SHA256[$VER-$ARCH]}  $tarball" | sha256sum -c - >&2 || die "контрольная сумма Zig не сошлась"
else
	warn "для Zig $VER нет сохранённой контрольной суммы — проверена только подпись"
fi
tar -xJf "$tarball"
rm -f "$tarball"
"$zig" version >/dev/null || die "zig $VER не запускается"
echo "$zig"
