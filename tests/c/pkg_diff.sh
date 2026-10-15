#!/bin/sh
# Дифференциальный тест vh-pkg: эталон (Python) против C-версии на настоящем xbps.
#   sh tests/c/pkg_diff.sh "ЭТАЛОН" ПРОВЕРЯЕМЫЙ
# Только в одноразовом контейнере Void: ставит и удаляет fuse3 (SUID + udev MODE 0666)
# и iputils (capabilities), пишет в /etc/xbps.d, /etc/vh, /etc/udev.
set -eu
ref=$1 new=$2
w=$(mktemp -d)
mkdir -p /etc/vh /usr/local/sbin
xbps-install -Sy libcap-progs >/dev/null
xbps-install -Dy fuse3 >/dev/null
reset() {
	xbps-remove -Ry fuse3 >/dev/null 2>&1 || true
	rm -f /etc/xbps.d/50-vh-pkg.conf /etc/xbps.d/51-vh-pkg-ignore.conf /etc/vh/suid-strip.list \
		/etc/udev/rules.d/99-fuse3.rules
}
state() {
	stat -c '%A %n' /usr/bin/fusermount3 2>/dev/null || true
	for f in /etc/xbps.d/5*-vh-pkg*.conf /etc/vh/suid-strip.list /etc/udev/rules.d/*; do
		[ -e "$f" ] && { echo "== $f"; cat "$f"; }
	done
	true
}
for impl in ref new; do
	reset
	eval "cmd=\$$impl"
	{
		# shellcheck disable=SC2086
		echo y | $cmd add fuse3; echo "rc=$?"
		# shellcheck disable=SC2086
		echo y | $cmd add fuse3 --ignore gcc --keep /nothing; echo "rc=$?"
		chmod u+s /usr/bin/fusermount3
		# shellcheck disable=SC2086
		$cmd scan fuse3; echo "rc=$?"
		state
		# shellcheck disable=SC2086
		$cmd rm fuse3; echo "rc=$?"
		# shellcheck disable=SC2086
		echo n | $cmd add fuse3; echo "rc=$?"
	} > "$w/$impl.raw" 2>&1 || true
	# строки самого xbps (прогресс, размеры) не сравниваются
	grep -vE '^\[\*\]|Downloading|downloaded|Unpacking|Configuring|Removing|Verifying|Collecting|Registered|^[[:space:]]*$|successfully|Name +Action|^fuse3-|^  fuse3|^[0-9]+ (download|install|remov)|Size |Free space|Space available|package will be' \
		"$w/$impl.raw" > "$w/$impl" || true
done
bad=0
if cmp -s "$w/ref" "$w/new"; then echo "ok vh-pkg add/scan/rm fuse3"; else bad=1; diff "$w/ref" "$w/new" || true; fi
# только C: capabilities (iputils-ping ставится с cap_net_raw)
xbps-install -Sy iputils >/dev/null
setcap cap_net_raw+ep /usr/bin/iputils-ping
$new scan iputils
if [ -z "$(getcap /usr/bin/iputils-ping)" ]; then echo "ok capabilities сняты"; else bad=1; echo "ОШИБКА: capabilities остались"; fi
reset
echo "различий: $bad"
[ $bad = 0 ]
