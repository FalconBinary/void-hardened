#!/bin/sh
# pre-udev: правило — показать код, как только ядро создаст /dev/tpm0.
echo 'KERNEL=="tpm0", RUN+="/sbin/initqueue --settled --onetime /bin/vh-totp-start"' \
	> /etc/udev/rules.d/80-vh-totp.rules
