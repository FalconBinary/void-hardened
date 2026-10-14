#!/bin/sh
# После разблокировки LUKS, до switch_root: генерация или перезапечатывание по флагу на
# корневой ФС (содержимое флага не читается — только факт), затем расширение PCR.
. /lib/vh-totp-lib.sh
[ -s /run/vh-totp.pid ] && kill "$(cat /run/vh-totp.pid)" 2>/dev/null
GEN=/sysroot/var/lib/vh/totp-generate
RESEAL=/sysroot/var/lib/vh/totp-reseal
tty=/dev/console
# Пароль восстановления tpm2-totp: 0.3.0 принимает его только аргументом -P (stdin не
# читает). В initramfs других пользователей нет — аргумент никто, кроме нас, не увидит.
# Корень в initramfs смонтирован только для чтения (cmdline «ro»): флаг снимается
# временным перемонтированием (найдено на стенде — иначе генерация повторялась бы)
clear_flag() {
	mount -o remount,rw /sysroot && rm -f "$1"
	mount -o remount,ro /sysroot
}
ask_pw() {
	stty -echo < $tty 2>/dev/null
	printf '%s' "$1" > $tty
	read -r pw < $tty
	stty echo < $tty 2>/dev/null
	echo > $tty
}
if [ -e "$GEN" ]; then
	{
		echo
		echo "=== tpm2-totp: генерация секрета (PCR $PCRS) ==="
		echo "Ожидается ТОЛЬКО после «optional/tpm2-totp/enable». Неожиданный запрос —"
		echo "признак вмешательства: выключите ноутбук и проверяйте его с live-флешки."
		echo "Придумайте пароль восстановления (diceware от 5 слов, НЕ пароль LUKS) —"
		echo "он нужен для перезапечатывания после обновлений. Затем отсканируйте QR."
	} > $tty
	tpm2-totp clean >/dev/null 2>&1      # старый секрет (повторное включение модуля)
	while :; do
		ask_pw "Пароль восстановления: "; p1=$pw
		ask_pw "Ещё раз: "; p2=$pw
		[ -n "$p1" ] && [ "$p1" = "$p2" ] && break
		echo "не совпало или пусто — ещё раз" > $tty
	done
	if tpm2-totp -p "$PCRS" -P "$p1" generate > $tty 2>&1; then
		# секрет запечатан на текущее состояние — перезапечатывание (флаг от пересборки
		# UKI при включении модуля) уже не нужно
		clear_flag "$GEN"
		[ -e "$RESEAL" ] && clear_flag "$RESEAL"
		echo "Нажмите Enter, когда код добавлен в приложение…" > $tty; read -r _ < $tty
	else
		echo "генерация не удалась — флаг оставлен, попытка будет при следующей загрузке" > $tty
	fi
	p1="" p2="" pw=""
elif [ -e "$RESEAL" ]; then
	{
		echo
		echo "=== tpm2-totp: запрос перезапечатывания ==="
		echo "Ожидается ТОЛЬКО сразу после обновления ядра, микрокода или прошивки."
		echo "Ядро: $(cat /proc/version)"
		echo "Сверьте версию с записанной при обновлении (vh-update). Неожиданный запрос ="
		echo "признак подмены загрузки: тогда выключите ноутбук и проверяйте с live-флешки."
		printf 'Перезапечатать на текущее состояние? Введите RESEAL: '
	} > $tty
	read -r ans < $tty
	if [ "$ans" = RESEAL ]; then
		ask_pw "Пароль восстановления tpm2-totp: "
		tpm2-totp -p "$PCRS" -P "$pw" reseal > $tty 2>&1 && clear_flag "$RESEAL" \
			&& echo "перезапечатано; при следующей загрузке код совпадёт" > $tty
		pw=""
	else
		echo "отказ — флаг оставлен, код по-прежнему не совпадает" > $tty
	fi
fi
vh_totp_lock
