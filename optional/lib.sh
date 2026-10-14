# shellcheck shell=bash
# void-hardened: общие функции параноидальных модулей optional/* (docs/13).
# Модуль запускается в установленной системе от root:
#   doas /root/vh/optional/<модуль>/enable    — включить
#   doas /root/vh/optional/<модуль>/disable   — выключить (вернуть базовый слой)
#   doas /root/vh/optional/status             — что включено
# Каждый модуль идемпотентен: повторный enable ничего не ломает.

. "$(dirname "${BASH_SOURCE[0]}")/../install/lib.sh"
need_root
load_config "$VH_ROOT/vh.conf"
MOD_DIR=$(cd "$(dirname "$0")" && pwd)
MOD=$(basename "$MOD_DIR")
STATE=/etc/vh/optional

mark_enabled()  { install -d -m 0755 "$STATE"; date -u +%FT%TZ > "$STATE/$MOD"; ok "модуль $MOD включён"; }
mark_disabled() { rm -f "$STATE/$MOD"; ok "модуль $MOD выключен"; }
is_enabled()    { [ -e "$STATE/${1:-$MOD}" ]; }

# Копия исходного файла перед первой правкой; restore_orig возвращает её.
save_orig()    { [ -e "$1" ] && [ ! -e "$1.vh-orig" ] && cp -a "$1" "$1.vh-orig"; return 0; }
restore_orig() { if [ -e "$1.vh-orig" ]; then mv -f "$1.vh-orig" "$1"; fi; }

# Набор nftables: сначала проверка, потом загрузка — ошибка не оставит систему без правил.
reload_nft() {
	nft -c -f /etc/nftables.conf || return 1
	nft -f /etc/nftables.conf
}

# Пересобрать UKI текущего ядра (после правки cmdline, модулей dracut и т. п.).
rebuild_uki() {
	say "пересборка и подпись UKI ($VH_KERNEL)"
	xbps-reconfigure -f "$VH_KERNEL"
}

# Добавить/убрать параметр в KERNEL_CMDLINE (/etc/default/dracut-uefi-hook).
cmdline_add() {
	local f=/etc/default/dracut-uefi-hook p
	for p in "$@"; do
		grep -q "KERNEL_CMDLINE=\".* $p\( \|\"\)" "$f" && continue
		sed -i "s|^KERNEL_CMDLINE=\"\(.*\)\"|KERNEL_CMDLINE=\"\1 $p\"|" "$f"
	done
}
cmdline_del() {
	local f=/etc/default/dracut-uefi-hook p
	for p in "$@"; do
		sed -i "s| $p\( \|\"\)|\1|" "$f"
	done
}
