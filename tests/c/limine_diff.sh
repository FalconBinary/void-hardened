#!/bin/sh
# Дифференциальный тест vh-limine-update: эталон (Python) против C-версии.
#   sh tests/c/limine_diff.sh "ЭТАЛОН" ПРОВЕРЯЕМЫЙ
# Только в одноразовом контейнере с --privileged: монтирует tmpfs на /boot/efi и
# подменяет sbctl и limine в /usr/bin заглушками.
set -eu
ref=$1 new=$2
w=$(mktemp -d)
mkdir -p /boot/efi /usr/share/limine /var/lib/sbctl/keys/db /etc/vh
mountpoint -q /boot/efi || mount -t tmpfs tmpfs /boot/efi
head -c 300000 /dev/urandom > /usr/share/limine/BOOTX64.EFI
head -c 1048577 /dev/urandom > "$w/big"
printf '#!/bin/sh\nprintf "signed\\n" >> "$2"\n' > /usr/bin/sbctl
printf '#!/bin/sh\nprintf "enrolled %%s\\n" "$3" >> "$2"\n' > /usr/bin/limine
chmod 0755 /usr/bin/sbctl /usr/bin/limine

setup() {
	rm -rf /boot/efi/EFI
	mkdir -p /boot/efi/EFI/void
	i=0
	for v in 6.18.54_1 6.18.55_1 6.18.56_1 6.17.9_2; do
		i=$((i + 1))
		head -c $((i * 129 + 127)) /dev/zero | tr '\0' "$i" > "/boot/efi/EFI/void/linux-$v.efi"
	done
	cat "$w/big" >> /boot/efi/EFI/void/linux-6.18.56_1.efi
	echo junk > /boot/efi/EFI/void/other.efi
	printf 'KEEP=%s\nTIMEOUT=3\n' "$1" > /etc/vh/boot.conf
}

bad=0
for keep in 1 2 3; do
	for key in yes no; do
		rm -f /var/lib/sbctl/keys/db/db.key
		[ $key = yes ] && touch /var/lib/sbctl/keys/db/db.key
		for args in "--dry-run" "--new 6.18.56_1" "" "--new 9.9.9_9"; do
			for impl in ref new; do
				setup $keep
				eval "cmd=\$$impl"
				# shellcheck disable=SC2086
				$cmd $args > "$w/$impl.o" 2> "$w/$impl.e" && rc=0 || rc=$?
				{ cat "$w/$impl.o"; echo "--- stderr"; cat "$w/$impl.e"; echo "rc=$rc"; } |
					sed 's|/tmp/[^/]*/BOOTX64.EFI|/tmp/X/BOOTX64.EFI|' > "$w/$impl.out"
				(cd /boot/efi && find . -type f | sort | while read -r f; do sha256sum "$f"; done) > "$w/$impl.esp"
			done
			if ! cmp -s "$w/ref.out" "$w/new.out" || ! cmp -s "$w/ref.esp" "$w/new.esp"; then
				bad=$((bad + 1))
				echo "РАЗЛИЧИЕ: KEEP=$keep ключ=$key $args"
				diff "$w/ref.out" "$w/new.out" | head -20 || true
				diff "$w/ref.esp" "$w/new.esp" | head -20 || true
			else
				echo "ok KEEP=$keep ключ=$key $args"
			fi
		done
	done
done
echo "различий: $bad"
[ $bad = 0 ]
