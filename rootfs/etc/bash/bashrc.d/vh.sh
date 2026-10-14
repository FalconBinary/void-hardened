# void-hardened: root-шелл (doas -s) — не login-шелл, /etc/profile он не читает.
# Ограничение бездействия задаём здесь. trap 'kill -KILL -1' для root сюда класть
# нельзя: от root он убил бы всю систему.
if [ "$(id -u)" = 0 ]; then
	readonly TMOUT=600
	export TMOUT
fi
