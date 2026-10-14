#!/bin/sh
# После разблокировки LUKS, до switch_root: генерация или перезапечатывание по флагу на
# корневой ФС (содержимое флага не читается — только факт), затем расширение PCR.
. /lib/vh-totp-lib.sh
[ -s /run/vh-totp.pid ] && kill "$(cat /run/vh-totp.pid)" 2>/dev/null
GEN=/sysroot/var/lib/vh/totp-generate
RESEAL=/sysroot/var/lib/vh/totp-reseal
tty=/dev/console
if [ -e "$GEN" ]; then
	{
		echo
		echo "=== tpm2-totp: генерация секрета (PCR $PCRS) ==="
		echo "Придумайте пароль восстановления (diceware от 5 слов, НЕ пароль LUKS) —"
		echo "он нужен для перезапечатывания после обновлений. Затем отсканируйте QR."
	} > $tty
	tpm2-totp -p "$PCRS" -P - generate < $tty > $tty 2>&1 && rm -f "$GEN"
	echo "Нажмите Enter, когда код добавлен в приложение…" > $tty; read -r _ < $tty
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
		echo "Пароль восстановления tpm2-totp:" > $tty
		tpm2-totp -p "$PCRS" -P - reseal < $tty > $tty 2>&1 && rm -f "$RESEAL" \
			&& echo "перезапечатано; при следующей загрузке код совпадёт" > $tty
	else
		echo "отказ — флаг оставлен, код по-прежнему не совпадает" > $tty
	fi
fi
vh_totp_lock
