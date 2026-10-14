#!/bin/bash
# Этап 2: первая загрузка установленной системы. Запуск от админа на tty2:
#   doas /root/vh/install/20-firstboot.sh
# Скрипт сам определяет, на каком шаге вы находитесь, и говорит, что делать дальше:
#   A. система загрузилась без Secure Boot → проверка базового слоя;
#   B. прошивка в Setup Mode → регистрация своих ключей (sbctl enroll-keys);
#   C. Secure Boot включён → проверка подписей. Дальше — этап 3 (30-lock.sh).
# Подробно — docs/03-boot.md.

. "$(dirname "$0")/lib.sh"
need_root
load_config /root/vh/vh.conf
FORCE_MS=0
[ "${1:-}" = "--microsoft" ] && FORCE_MS=1

efv() { od -An -t u1 -j4 -N1 /sys/firmware/efi/efivars/"$1"-* 2>/dev/null | tr -d ' '; }
SB=$(efv SecureBoot) SETUP=$(efv SetupMode)

say "проверка базового слоя"
grep -q 'lockdown=confidentiality' /proc/cmdline && ok "cmdline из UKI" || warn "cmdline не из UKI?"
[ "$(cat /sys/kernel/security/lockdown)" = "none integrity [confidentiality]" ] \
	&& ok "lockdown: confidentiality" || warn "lockdown: $(cat /sys/kernel/security/lockdown)"
ok "LSM: $(cat /sys/kernel/security/lsm)"
nft list table inet vh >/dev/null 2>&1 && ok "nftables: таблица vh" || warn "нет таблицы vh"
for s in dbus iwd unbound chronyd seatd; do
	sv status "$s" | grep -q '^run:' && ok "сервис $s" || warn "сервис $s не работает"
done
getent hosts voidlinux.org >/dev/null && ok "DNS через unbound (DoT)" || warn "DNS не отвечает — подключите сеть: iwctl"
chronyc -n tracking 2>/dev/null | grep -q 'Leap status *: Normal' && ok "время синхронизировано (NTS)" \
	|| warn "время ещё не синхронизировано (chronyc -N authdata)"

say "Secure Boot: SecureBoot=$SB SetupMode=$SETUP"
if [ "$SB" = 1 ]; then
	sbctl status
	sbctl verify || die "есть неподписанные EFI-файлы"
	ok "Secure Boot включён, подписи на месте. Дальше: этап 3 — doas /root/vh/install/30-lock.sh"
	exit 0
fi

if [ "$SETUP" != 1 ]; then
	cat <<EOF

Прошивка не в Setup Mode. Сделайте в настройках BIOS (docs/00, docs/03):
  1. задайте пароль администратора (supervisor) BIOS;
  2. Secure Boot → «Reset to Setup Mode» / «Delete all keys» / «Clear Secure Boot keys»
     (название зависит от производителя; Secure Boot при этом выключен);
  3. загрузитесь в систему и снова запустите этот скрипт.
EOF
	exit 0
fi

say "регистрация своих ключей"
sbctl status
EVLOG=/sys/kernel/security/tpm0/binary_bios_measurements
n=-1
if [ -r "$EVLOG" ]; then
	n=$(tpm2_eventlog "$EVLOG" 2>/dev/null | grep -c EV_EFI_BOOT_SERVICES_DRIVER || true)
fi
args=()
if [ "$FORCE_MS" = 1 ]; then
	warn "--microsoft: в db попадут сертификаты Microsoft (UEFI CA 2011 подписывает shim с известными уязвимостями)"
	args=(--microsoft)
elif [ "$n" = 0 ]; then
	ok "Option ROM в журнале измерений нет — только свои ключи"
elif [ "$n" -gt 0 ] 2>/dev/null; then
	warn "найдено Option ROM: $n. Их хэши вносятся в db (--tpm-eventlog), сертификаты Microsoft — нет"
	args=(--tpm-eventlog)
else
	die "журнал измерений TPM недоступен: нельзя проверить Option ROM. Без этого регистрация может оставить машину без экрана. Варианты — docs/03"
fi
confirm_exact enroll "Ключи PK/KEK/db будут записаны в прошивку."
sbctl enroll-keys "${args[@]}"
ok "ключи записаны"
cat <<EOF

Дальше:
  1. перезагрузитесь в BIOS и включите Secure Boot (пароль BIOS уже должен стоять);
  2. там же: выключите загрузку с USB/сети, CSM, UEFI Shell; поставьте Limine
     («Void Linux (Limine)») первой в порядке загрузки;
  3. загрузитесь и снова запустите этот скрипт — он проверит подписи.
Если система не загрузится — docs/03, раздел «Восстановление».
EOF
