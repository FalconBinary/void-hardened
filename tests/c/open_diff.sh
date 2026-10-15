#!/bin/sh
# Дифференциальный тест vh-open: эталон (Python) против C-версии.
#   sh tests/c/open_diff.sh "ЭТАЛОН" ПРОВЕРЯЕМЫЙ ГЕНЕРАТОР_SECCOMP_ЭТАЛОНА
# Только в одноразовом контейнере: подменяет /usr/bin/bwrap заглушкой, которая печатает
# аргументы, содержимое фильтра seccomp и цель дескриптора файла.
set -eu
ref=$1 new=$2 gen=$3
w=$(mktemp -d)
mkdir -p /usr/local/libexec/vh /run/vh-sandbox
install -m 0755 "$gen" /usr/local/libexec/vh/vh-seccomp
rm -f /run/vh-sandbox/wayland; : > /run/vh-sandbox/wayland
cat > /usr/bin/bwrap <<'EOF'
#!/bin/sh
next=""
for a; do
	case $next in
		seccomp) echo "SECCOMP $(sha256sum < /proc/self/fd/$a | cut -c1-16)"; next=""; continue ;;
		fd) echo "FD -> $(readlink /proc/self/fd/$a)"; next=""; continue ;;
	esac
	case $a in --seccomp) next=seccomp ;; --ro-bind-fd) next=fd ;; esac
	printf '%s\n' "$a"
done | sed -E 's#/tmp/vh-open-[0-9]+-[0-9]+#/tmp/vh-open-X#'
EOF
chmod 0755 /usr/bin/bwrap
d=$w/files
mkdir -p "$d/sub"
printf '%%PDF-1.7\n' > "$d/a.pdf"
printf '\211PNG\r\n\032\n0000' > "$d/b.png"
printf '\377\330\377\340' > "$d/c.JPG"
printf '\0\0\0\030ftypmp42' > "$d/d.mp4"
printf '\377\373\220\0' > "$d/e.mp3"
printf 'просто текст\n' > "$d/f.txt"
printf '\001\002\0\003' > "$d/g.bin"
printf 'RIFF\0\0\0\0WEBPVP8 ' > "$d/h.webp"
ln -s a.pdf "$d/link.pdf"
ln -s "$d/sub" "$d/linkdir"
bad=0
for args in "$d/a.pdf" "$d/b.png" "$d/c.JPG" "$d/d.mp4" "--gpu $d/d.mp4" "$d/e.mp3" "$d/f.txt" \
	"$d/g.bin" "$d/h.webp" "$d/link.pdf" "$d/linkdir/../a.pdf" "$d/sub" "$d/nope" "$d/sub/../f.txt" \
	"f.txt" "" "--gpu" "/"; do
	for impl in ref new; do
		eval "cmd=\$$impl"
		# shellcheck disable=SC2086
		(cd "$d" && HOME=/home/u LANG=ru_RU.UTF-8 TERM=foot $cmd $args) > "$w/$impl.o" 2> "$w/$impl.e" && rc=0 || rc=$?
		echo "rc=$rc" >> "$w/$impl.o"
	done
	# справка (код 2) намеренно короче — сравниваются только коды
	if cmp -s "$w/ref.o" "$w/new.o" || { [ "$(tail -1 "$w/ref.o")" = rc=2 ] && [ "$(tail -1 "$w/new.o")" = rc=2 ]; }; then
		echo "ok '$args' ($(tail -1 "$w/new.o"))"
	else
		bad=$((bad + 1))
		echo "РАЗЛИЧИЕ '$args'"
		diff "$w/ref.o" "$w/new.o" | head -20 || true
		echo "  stderr эталона: $(head -c 300 "$w/ref.e")"
		echo "  stderr C:       $(head -c 300 "$w/new.e")"
	fi
done
rm -rf /tmp/vh-open-*
echo "различий: $bad"
[ $bad = 0 ]
