# vim: set ts=4 sw=4 et:
# void-hardened: правила файрвола — до старта любых сетевых сервисов (стадия 2).
# Если набор не загрузился, ставится аварийный «запретить всё»: сеть закрыта,
# а не открыта (fail-closed). Сервисы iwd/dhcpcd проверяют наличие таблицы vh.
msg "vh: nftables..."
if ! nft -f /etc/nftables.conf; then
    printf '! nftables.conf не загрузился — включён аварийный набор (вся сеть закрыта)\n'
    nft -f - <<'NFT'
flush ruleset
table inet vh_failsafe {
    chain input { type filter hook input priority filter; policy drop; iif "lo" accept; }
    chain forward { type filter hook forward priority filter; policy drop; }
    chain output { type filter hook output priority filter; policy drop; oif "lo" accept; }
}
NFT
fi
