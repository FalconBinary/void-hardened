# vim: set ts=4 sw=4 et:
# void-hardened: профили AppArmor (docs/08). Загружаются только перечисленные —
# не все ~150 профилей пакета apparmor — и из кэша скомпилированной политики:
# компиляция идёт один раз, после обновления apparmor или ядра (кэш сверяется сам).
[ -d /sys/kernel/security/apparmor ] || return 0
msg "vh: профили AppArmor..."
_vh_aa="/etc/apparmor.d/vh.firefox /etc/apparmor.d/vh.unbound /etc/apparmor.d/vh.chronyd /etc/apparmor.d/vh.iwd /etc/apparmor.d/unix-chkpwd"
for _vh_p in /etc/apparmor.d/vh.local.*; do
    [ -e "$_vh_p" ] && _vh_aa="$_vh_aa $_vh_p"
done
# shellcheck disable=SC2086
apparmor_parser --replace --write-cache --cache-loc /var/cache/apparmor -- $_vh_aa \
    || printf '! AppArmor: профили загрузились не все — docs/08\n'
unset _vh_aa _vh_p
