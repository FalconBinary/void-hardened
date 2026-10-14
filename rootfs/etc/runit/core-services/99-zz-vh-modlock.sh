# vim: set ts=4 sw=4 et:
# void-hardened: kernel.modules_disabled=1 в самом конце стадии 1 (docs/05).
# До этого момента любой процесс может вызвать автозагрузку редкого модуля
# (socket(AF_…), выражения nft_, qdisc); к концу стадии 1 udev уже загрузил
# драйверы имеющегося железа, а нужные позже модули предзагружаются здесь.
# Включается этапом 3 (install/30-lock.sh). Отключить: rm /etc/vh/modlock.enabled
[ -e /etc/vh/modlock.enabled ] || return 0
if [ -s /etc/vh/modules.preload ]; then
    msg "vh: предзагрузка модулей..."
    grep -v '^#' /etc/vh/modules.preload | xargs -r modprobe -a
fi
msg "vh: загрузка модулей ядра заблокирована до перезагрузки"
echo 1 > /proc/sys/kernel/modules_disabled
