# vim: set ts=4 sw=4 et:
# void-hardened: финал штатного выключения (optional/deadman, docs/13). Корень уже только
# для чтения (80-filesystems): данные сброшены. Стирание ключа тома, zram, кэшей и
# перезагрузка через прошивку (MOR) — vh-deadman final. Сюда не возвращаемся.
if [ -e /etc/vh/optional/deadman ] && [ -x /usr/local/sbin/vh-deadman ]; then
    msg "vh: стирание ключа LUKS и RAM..."
    /usr/local/sbin/vh-deadman final
fi
