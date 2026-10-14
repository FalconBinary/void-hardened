#!/bin/sh
# Самый ранний хук: до TOTP и запроса пароля. Флаг — переменная NVRAM VhPoweroff;
# её подделка даёт атакующему только DoS (выключение), не доступ.
f=/sys/firmware/efi/efivars/VhPoweroff-cfc8fc79-be2e-4ddc-97f0-9f98bfe298a0
grep -q ' /sys/firmware/efi/efivars ' /proc/mounts || mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null
if [ -e "$f" ]; then
	# удалить флаг; если не вышло — не выключаемся (иначе каждая загрузка = выключение)
	if rm -f "$f" && [ ! -e "$f" ]; then
		echo "void-hardened: RAM стёрта прошивкой (MOR) после аварийного/штатного выключения — выключение"
		echo o > /proc/sysrq-trigger
		sleep 10
	else
		echo "void-hardened: флаг VhPoweroff не удаляется — продолжаю загрузку"
	fi
fi
