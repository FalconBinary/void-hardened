#!/bin/sh
# void-hardened: общие функции tpm2-totp в initramfs.
. /etc/vh/totp.conf            # PCRS="0,2,4,7,14"  LOCK_PCR=14
# Расширить PCR LOCK_PCR случайным значением: секрет TOTP больше не вычисляется до
# следующей загрузки — ни работающей системой, ни поддельной цепочкой после неё.
vh_totp_lock() {
	[ -e /run/vh-totp-locked ] && return 0
	r=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	tpm2_pcrextend "${LOCK_PCR}:sha256=$r" >/dev/null 2>&1 && : > /run/vh-totp-locked
}
