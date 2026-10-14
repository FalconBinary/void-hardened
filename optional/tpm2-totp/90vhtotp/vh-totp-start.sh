#!/bin/sh
# Запускается из initqueue, когда появился /dev/tpm0: показ кода каждые 30 с в фоне.
. /etc/vh/totp.conf
echo
echo "=== void-hardened: сверьте код TOTP с телефоном ДО ввода пароля LUKS ==="
/bin/show-tpm2-totp -p "$PCRS" &
echo $! > /run/vh-totp.pid
