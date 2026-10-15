#!/bin/sh
# Дифференциальный тест vh-usb-udev: эталон (Python) против C-версии.
#   sh tests/c/usb_diff.sh "ЭТАЛОН" ПРОВЕРЯЕМЫЙ
# Только в одноразовом контейнере с --privileged: в своём пространстве монтирования
# кладёт поддельное дерево USB на /sys/devices и tmpfs на /run/vh и /etc/vh.
set -eu
[ "${VH_IN_NS:-}" = 1 ] || exec env VH_IN_NS=1 unshare -m sh "$0" "$@"
ref=$1 new=$2
w=$(mktemp -d)
mount -t tmpfs tmpfs /sys/devices
mkdir -p /run/vh /etc/vh
mount -t tmpfs tmpfs /run/vh
mount -t tmpfs tmpfs /etc/vh
U=/sys/devices/pci0000:00/0000:00:14.0/usb1

# дескрипторы: конфигурация + интерфейсы (класс, подкласс, протокол)
desc() {
	printf '\022\001\000\002\000\000\000\100\000\000\000\000\000\001\001\002\003\001'
	printf '\011\002\040\000\001\001\000\200\062'
	for i in "$@"; do
		set -- $(echo "$i" | tr , ' ')
		printf "\\011\\004\\000\\000\\001\\$(printf %03o "$1")\\$(printf %03o "$2")\\$(printf %03o "$3")\\000"
	done
}

mkdev() {   # mkdev ПОРТ ТИП VID PID SERIAL ИНТЕРФЕЙС…
	d=$U/$1 port=$1 ct=$2 vid=$3 pid=$4 ser=$5
	shift 5
	mkdir -p "$d/port"
	echo 0 > "$d/authorized"
	echo "$vid" > "$d/idVendor"
	echo "$pid" > "$d/idProduct"
	echo "$ser" > "$d/serial"
	echo "Maker" > "$d/manufacturer"
	echo "Thing $port" > "$d/product"
	echo "$ct" > "$d/port/connect_type"
	desc "$@" > "$d/descriptors"
	n=0
	for i in "$@"; do
		mkdir -p "$d/$port:1.$n"
		echo 0 > "$d/$port:1.$n/authorized"
		printf '%02x\n' "$(echo "$i" | cut -d, -f1)" > "$d/$port:1.$n/bInterfaceClass"
		n=$((n + 1))
	done
}

setup() {
	rm -rf "${U:?}"/* /run/vh/* /etc/vh/*
	mkdev 1-1 hotplug 0951 1666 AAA 8,6,80            # флешка, не подключена
	mkdev 1-2 hardwired 5986 211b "" 14,1,0 14,2,0    # встроенная камера
	mkdev 1-3 hardwired 8087 0026 "" 224,1,1 224,1,1  # встроенный Bluetooth
	mkdev 1-4 hardwired 1038 1122 "" 3,1,1            # встроенная клавиатура
	mkdev 1-5 hotplug 1050 0407 KEY123 3,0,0          # свой FIDO-ключ
	mkdev 1-6 hotplug 1050 0407 KEY999 3,0,0          # чужой ключ того же типа
	mkdev 1-7 hotplug 1050 0407 KEY777 3,0,0 3,1,1    # «ключ» с интерфейсом клавиатуры
	mkdev 1-8 hotplug 0951 1666 BBB 8,6,80 3,1,1      # флешка + клавиатура (BadUSB)
	mkdev 1-9 hotplug 1050 0407 KEY777 3,0,0 3,1,1    # тот же serial, другой порт
	mkdir -p /run/vh/usb-attach
	: > /run/vh/usb-attach/1-8
	printf '# порт vid:pid serial\n1-5 1050:0407 KEY123\n1-7 1050:0407 KEY777\n' > /etc/vh/usb-keys.conf
	printf 'VH_CAMERA="%s"\nVH_BLUETOOTH="%s"\n' "$1" "$2" > /etc/vh/vh.env
}

state() {
	(cd /sys/devices && find . -name authorized | sort | while read -r f; do echo "$f=$(cat "$f")"; done)
	cat /run/vh/usb-blocked 2>/dev/null && echo
}

bad=0
for env in "no off" "yes optional" "no on"; do
	for impl in ref new; do
		# shellcheck disable=SC2086
		setup $env
		eval "cmd=\$$impl"
		for d in 1-1 1-2 1-3 1-4 1-5 1-6 1-7 1-8 1-9; do
			# shellcheck disable=SC2086
			$cmd device "${U#/sys}/$d" || true
			for i in "$U/$d"/"$d":1.*; do
				# shellcheck disable=SC2086
				$cmd interface "${i#/sys}" || true
			done
		done
		state > "$w/$impl"
	done
	if cmp -s "$w/ref" "$w/new"; then
		echo "ok VH_CAMERA/VH_BLUETOOTH = $env"
	else
		bad=$((bad + 1))
		echo "РАЗЛИЧИЕ $env"
		diff "$w/ref" "$w/new" || true
	fi
done
cat "$w/new"
# только C: пути вне /sys/devices и несуществующие (Python пропускал /class/net/lo) — отказ
for p in "/devices/../../etc" "/class/net/lo" "/devices" "/devices/nope"; do
	if $new device "$p"; then
		bad=$((bad + 1))
		echo "ОШИБКА: принят путь $p"
	fi
done
echo "различий: $bad"
[ $bad = 0 ]
