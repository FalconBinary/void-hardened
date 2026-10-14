# vim: set ts=4 sw=4 et:
# void-hardened: обновление пакета возвращает SUID и file capabilities, снятые
# chmod/setcap. Снимаем их снова при каждой загрузке (и в vh-update) — docs/05.
/usr/local/sbin/vh-suid-strip --quiet
