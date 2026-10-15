/* vh-pkg — установка программ с проверкой и обезвреживанием (docs/12, раздел «Программы»).
 *
 *   doas vh-pkg add ПАКЕТ… [--ignore ЗАВИСИМОСТЬ…] [--keep ПУТЬ…] [-y]
 *   doas vh-pkg scan ПАКЕТ… [--keep ПУТЬ…] — разобрать уже установленные пакеты (vh-update — сам)
 *   doas vh-pkg rm ПАКЕТ…                — удалить вместе с ненужными больше зависимостями
 *
 * У xbps нет хуков «после установки пакета», поэтому ставить через эту обёртку:
 *
 * 1. До установки — список всего, что потянется (xbps-install -n). Пакеты из чёрного
 *    списка (компиляторы, polkit, elogind, avahi, cups, NetworkManager, Xwayland, cron…)
 *    показываются с причиной; без подтверждения установка не идёт. Ненужную зависимость
 *    можно не ставить: --ignore ИМЯ (ignorepkg в /etc/xbps.d — проверьте, что программа
 *    работает без неё).
 * 2. После установки — разбор файлов каждого нового пакета:
 *      SUID/SGID, file capabilities  → снимаются; путь в /etc/vh/suid-strip.list
 *                                      (vh-suid-strip снимает их снова после обновлений);
 *      sysctl.d                      → маскируется одноимённым пустым файлом в /etc/sysctl.d
 *                                      (иначе файл пакета 99-* перекрыл бы 30-vh-hardening);
 *      правила udev с MODE 0666/0777 → маскируются в /etc/udev/rules.d (устройство для всех);
 *      хуки /etc/kernel.d, модули dracut, скрипты profile.d/bashrc.d
 *                                    → не распаковываются (noextract) и удаляются: они
 *                                      исполняются от root при сборке UKI или в каждом шелле;
 *      сервисы runit, D-Bus, автозапуск XDG, cron
 *                                    → только отчёт: в этой системе они не запускаются сами.
 *    Исключение для конкретного файла: --keep ПУТЬ.
 * 3. Сироты (зависимости, которые больше никому не нужны) — xbps-remove -o.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vh.h"

#define NOEXTRACT "/etc/xbps.d/50-vh-pkg.conf"
#define IGNORE "/etc/xbps.d/51-vh-pkg-ignore.conf"
#define STRIP_LIST "/etc/vh/suid-strip.list"
#define STRIP_HDR "# void-hardened: снимать SUID/SGID и capabilities после обновлений (vh-pkg)"

static const char *const deny[][2] = {
	/* компиляторы: вредонос собрал бы инструмент на месте */
	{"gcc", "компилятор C (часто тянет libgccjit — например, emacs-pgtk/gtk3)"},
	{"clang", "компилятор C"}, {"tcc", "компилятор C"}, {"make", "система сборки"},
	{"rust", "компилятор"}, {"go", "компилятор"},
	/* интерпретаторы: обходят noexec (ctypes, FFI) — в системе их нет намеренно */
	{"python3", "интерпретатор: исполняет код из файлов на noexec (docs/05)"},
	{"perl", "интерпретатор: исполняет код из файлов на noexec (docs/05)"},
	{"ruby", "интерпретатор"}, {"nodejs", "интерпретатор"},
	/* привилегированные демоны и помощники */
	{"polkit", "SUID pkexec и демон прав — здесь его работу делает doas"},
	{"elogind", "менеджер сеансов — здесь seatd"},
	{"udisks2", "монтирование дисков без пароля через D-Bus"},
	{"gvfs", "демоны виртуальных ФС"}, {"avahi", "mDNS: рассылает имя в сеть, слушает порт"},
	{"cups", "сервер печати, слушает порт"}, {"NetworkManager", "второй менеджер сети рядом с iwd"},
	{"ModemManager", "демон модемов"}, {"connman", "второй менеджер сети"},
	{"wpa_supplicant", "второй Wi-Fi-демон рядом с iwd"},
	{"openssh", "содержит сервер sshd (сервис не включайте)"},
	{"sudo", "второй SUID-инструмент повышения прав"}, {"usbguard", "тянет polkit"},
	{"cronie", "планировщик — точка закрепления"}, {"dcron", "планировщик"}, {"fcron", "планировщик"},
	{"snooze", "планировщик"}, {"at", "планировщик"},
	{"xorg-server", "X11: нет изоляции окон"}, {"xorg-server-xwayland", "Xwayland: нет изоляции окон"},
	{"xdg-desktop-portal", "D-Bus-порталы"}, {"gnome-keyring", "демон ключей с D-Bus"},
	{"pulseaudio", "конфликтует с PipeWire"}, {"fuse", "SUID fusermount; модуль fuse запрещён"},
	{"fuse3", "SUID fusermount3; модуль fuse запрещён"}, {"flatpak", "нужны userns и fuse"},
	{"podman", "нужны userns и overlay"}, {"docker", "root-демон, нужны overlay и iptables"},
	{"tlp", "демон питания — работу делает vh-power"}, {"thermald", "демон питания"},
	{"power-profiles-daemon", "демон питания"}, {"auto-cpufreq", "демон питания"},
	{"acpid", "усыпляет по крышке — здесь vh-acpid"},
};
static const char *const deny_prefix[][2] = {
	{"xdg-desktop-portal-", "D-Bus-порталы"}, {"llvm", "компилятор (LLVM)"},
};

static char *pkgname(const char *pkgver)
{
	const char *d = strrchr(pkgver, '-');
	return d ? xstrndup(pkgver, (size_t)(d - pkgver)) : xstrdup(pkgver);
}

static const char *deny_reason(const char *name)
{
	for (size_t i = 0; i < sizeof(deny) / sizeof(deny[0]); i++)
		if (strcmp(name, deny[i][0]) == 0)
			return deny[i][1];
	for (size_t i = 0; i < sizeof(deny_prefix) / sizeof(deny_prefix[0]); i++)
		if (startswith(name, deny_prefix[i][0]))
			return deny_prefix[i][1];
	return NULL;
}

/* «да» на вопрос: y, yes, д, да в любом регистре */
static bool ask(const char *question, bool yes)
{
	if (yes)
		return true;
	printf("%s [y/N] ", question);
	fflush(stdout);
	char line[64];
	if (!fgets(line, sizeof(line), stdin))
		return false;
	char *a = strip(line);
	for (char *p = a; *p; p++)
		if (*p >= 'A' && *p <= 'Z')
			*p = (char)(*p - 'A' + 'a');
	/* Д (D0 94) → д (D0 B4), А (D0 90) → а (D0 B0) */
	for (unsigned char *p = (unsigned char *)a; p[0] && p[1]; p++)
		if (p[0] == 0xD0 && (p[1] == 0x94 || p[1] == 0x90))
			p[1] = (unsigned char)(p[1] + 0x20);
	return !strcmp(a, "y") || !strcmp(a, "yes") || !strcmp(a, "д") || !strcmp(a, "да");
}

/* строка в файл, если её там нет; первая строка нового файла — заголовок */
static bool append_unique(const char *path, const char *line, const char *header)
{
	struct buf b = {0};
	char *text = read_file(path, NULL);
	bool empty = true;
	if (text) {
		char *save = NULL;
		char *copy = xstrdup(text);
		for (char *l = strtok_r(copy, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
			if (strcmp(l, line) == 0) {
				free(copy);
				free(text);
				return false;
			}
			empty = false;
		}
		free(copy);
		buf_adds(&b, text);
		if (b.len && b.p[b.len - 1] != '\n')
			buf_adds(&b, "\n");
		free(text);
	}
	if (empty) {
		buf_free(&b);
		buf_addf(&b, "%s\n", header);
	}
	buf_addf(&b, "%s\n", line);
	write_atomic(path, b.p, b.len, 0644);
	buf_free(&b);
	return true;
}

static void files_of(const char *name, struct strv *out)
{
	struct buf o = {0};
	run((char *const[]){"xbps-query", "-f", (char *)name, NULL}, NULL, 0, &o, NULL);
	char *save = NULL;
	for (char *l = strtok_r(o.p, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
		char *arrow = strstr(l, " -> ");
		if (arrow)
			*arrow = 0;
		l = strip(l);
		if (*l == '/')
			strv_add(out, l);
	}
	buf_free(&o);
}

static const char *base(const char *p)
{
	const char *s = strrchr(p, '/');
	return s ? s + 1 : p;
}

/* пустой одноимённый файл в /etc маскирует файл пакета (udev, sysctl) */
static char *mask(const char *path, const char *dst_dir, const char *why)
{
	char *dst = xasprintf("%s/%s", dst_dir, base(path));
	if (path_exists(dst))
		return xasprintf("уже есть %s", dst);
	mkdirs(dst_dir, 0755);
	char *text = xasprintf("# void-hardened (vh-pkg): маскирует %s — %s\n", path, why);
	write_atomic(dst, text, strlen(text), 0644);
	free(text);
	char *r = xasprintf("замаскирован файлом %s", dst);
	free(dst);
	return r;
}

/* noextract (переживает обновления) + удалить сейчас */
static char *drop(const char *path, const char *why)
{
	char *line = xasprintf("noextract=%s", path);
	append_unique(NOEXTRACT, line,
		      "# void-hardened: файлы пакетов, которые vh-pkg запретил распаковывать (docs/12)");
	free(line);
	if (unlink(path) != 0 && errno != ENOENT)
		warnmsg("%s: %s", path, strerror(errno));
	return xasprintf("удалён и не будет распакован при обновлениях (%s)", why);
}

/* MODE="0666" и подобное: устройство для всех */
static bool udev_world_mode(const char *t, size_t n)
{
	static const char *const modes[] = {"666", "777", "766", "776", "677"};
	for (const char *p = t; (p = memmem(p, n - (size_t)(p - t), "MODE", 4)); p += 4) {
		const char *q = p + 4, *e = t + n;
		while (q < e && is_space((unsigned char)*q))
			q++;
		if (q < e && *q == ':')
			q++;
		if (q >= e || *q != '=')
			continue;
		q++;
		while (q < e && is_space((unsigned char)*q))
			q++;
		if (q >= e || *q != '"')
			continue;
		q++;
		if (q < e && *q == '0')
			q++;
		for (size_t i = 0; i < 5; i++)
			if (e - q >= 4 && memcmp(q, modes[i], 3) == 0 && q[3] == '"')
				return true;
	}
	return false;
}

static bool has(const char *t, size_t n, const char *needle)
{
	return memmem(t, n, needle, strlen(needle)) != NULL;
}

static void report(struct strv *r, char *msg)
{
	strv_take(r, msg);
}

/* разобрать файлы пакетов; возвращает число обезвреженных объектов */
static int scan(char **names, size_t nn, const struct strv *keep)
{
	int acted = 0;
	for (size_t ni = 0; ni < nn; ni++) {
		const char *name = names[ni];
		struct strv files = {0}, rep = {0};
		files_of(name, &files);
		for (size_t fi = 0; fi < files.n; fi++) {
			const char *f = files.v[fi];
			struct stat st;
			if (strv_has(keep, f) || lstat(f, &st) != 0)
				continue;
			bool reg = S_ISREG(st.st_mode);
			if (reg) {
				if (st.st_mode & (S_ISUID | S_ISGID)) {
					chmod(f, st.st_mode & 07777 & ~(mode_t)(S_ISUID | S_ISGID));
					append_unique(STRIP_LIST, f, STRIP_HDR);
					report(&rep, xasprintf("SUID/SGID снят: %s (для root программа работает и так)", f));
					acted++;
				}
				struct buf caps = {0};
				run((char *const[]){"getcap", (char *)f, NULL}, NULL, 0, &caps, NULL);
				char *c = strip(caps.p);
				if (*c) {
					struct buf ignore = {0};
					run((char *const[]){"setcap", "-r", (char *)f, NULL}, NULL, 0, &ignore, &ignore);
					buf_free(&ignore);
					append_unique(STRIP_LIST, f, STRIP_HDR);
					report(&rep, xasprintf("capabilities сняты: %s", c));
					acted++;
				}
				buf_free(&caps);
			}
			bool sysctl = (startswith(f, "/usr/lib/sysctl.d/") || startswith(f, "/run/sysctl.d/")) &&
				      endswith(f, ".conf") && strlen(base(f)) > 5;
			bool udev = (startswith(f, "/usr/lib/udev/rules.d/") || startswith(f, "/etc/udev/rules.d/")) &&
				    endswith(f, ".rules") && strlen(base(f)) > 6;
			if (sysctl) {
				char *m = mask(f, "/etc/sysctl.d", "перекрыл бы sysctl защиты");
				report(&rep, xasprintf("sysctl %s: %s", f, m));
				free(m);
				acted++;
			} else if (udev && reg) {
				size_t tn = 0;
				char *t = read_file(f, &tn);
				if (t && udev_world_mode(t, tn)) {
					char *m = startswith(f, "/etc/") ? drop(f, "устройство для всех")
									 : mask(f, "/etc/udev/rules.d", "устройство для всех");
					report(&rep, xasprintf("udev %s: даёт устройство всем (MODE 0666) — %s", f, m));
					free(m);
					acted++;
				} else if (t && (has(t, tn, "RUN=") || has(t, tn, "RUN+=") || has(t, tn, "MODE") ||
						 has(t, tn, "GROUP") || has(t, tn, "OWNER"))) {
					report(&rep, xasprintf("udev %s: правило прав/запуска — проверьте: %s", f, f));
				}
				free(t);
			} else if (startswith(f, "/etc/kernel.d/")) {
				char *m = drop(f, "исполняется от root при каждой сборке UKI");
				report(&rep, xasprintf("хук ядра %s: %s", f, m));
				free(m);
				acted++;
			} else if (startswith(f, "/usr/lib/dracut/modules.d/") && endswith(f, "module-setup.sh")) {
				char *dir = xstrndup(f, (size_t)(base(f) - f - 1));
				char *pre = xasprintf("%s/", dir);
				for (size_t g = 0; g < files.n; g++)
					if (startswith(files.v[g], pre) && !strv_has(keep, files.v[g]))
						free(drop(files.v[g], "модуль dracut"));
				report(&rep, xasprintf("модуль dracut %s: удалён и не будет распакован (попал бы в initramfs)", dir));
				free(pre);
				free(dir);
				acted++;
			} else if (reg && ((startswith(f, "/etc/profile.d/") && endswith(f, ".sh") && strlen(f) > 18) ||
					   (startswith(f, "/etc/bash/bashrc.d/") && strlen(f) > 19))) {
				char *m = drop(f, "исполнялся бы в каждом шелле, в том числе у админа");
				report(&rep, xasprintf("скрипт входа %s: %s", f, m));
				free(m);
				acted++;
			} else if (startswith(f, "/etc/sv/") && endswith(f, "/run") &&
				   strchr(f + 8, '/') == f + strlen(f) - 4 && strlen(f) > 12) {
				char *svc = xstrndup(f + 8, (size_t)(strrchr(f, '/') - f - 8));
				char *link = xasprintf("/var/service/%s", svc);
				report(&rep, xasprintf("сервис runit %s: %s", svc,
						       path_exists(link) ? "ВКЛЮЧЁН — проверьте, нужен ли"
									 : "установлен, но не включён (Void сам не включает)"));
				free(link);
				free(svc);
			} else if (startswith(f, "/usr/share/dbus-1/system-services/")) {
				report(&rep, xasprintf("D-Bus-сервис %s: не запустится сам (активация выключена)", base(f)));
			} else if (startswith(f, "/etc/xdg/autostart/") || startswith(f, "/etc/cron")) {
				report(&rep, xasprintf("автозапуск %s: mango и runit его не исполняют", f));
			} else if (startswith(f, "/usr/lib/modprobe.d/") || startswith(f, "/etc/modprobe.d/")) {
				report(&rep, xasprintf("modprobe.d %s: проверьте (modules_disabled, module_blacklist)", f));
			}
		}
		if (rep.n) {
			printf("── %s\n", name);
			for (size_t i = 0; i < rep.n; i++)
				printf("   %s\n", rep.v[i]);
		}
		strv_free(&rep);
		strv_free(&files);
	}
	return acted;
}

/* код возврата или выход с ошибкой; out/err — для текста ошибки */
static void must(char *const argv[])
{
	int rc = run(argv, NULL, 0, NULL, NULL);
	if (rc != 0)
		die("%s: код %d", argv[0], rc);
}

static void strip_quiet(void)
{
	struct buf o = {0};
	run((char *const[]){"/usr/local/sbin/vh-suid-strip", "--quiet", NULL}, NULL, 0, &o, &o);
	buf_free(&o);
}

static _Noreturn void usage(void)
{
	fputs("doas vh-pkg add ПАКЕТ… [--ignore ЗАВИСИМОСТЬ…] [--keep ПУТЬ…] [-y]\n"
	      "doas vh-pkg scan ПАКЕТ… [--keep ПУТЬ…]\n"
	      "doas vh-pkg rm ПАКЕТ…\n", stderr);
	exit(2);
}

int main(int argc, char **argv)
{
	vh_prog = "vh-pkg";
	setenv("PATH", "/usr/bin", 1);
	if (geteuid() != 0)
		die("запустите: doas vh-pkg …");
	if (argc < 2)
		usage();
	const char *cmd = argv[1];
	bool is_add = !strcmp(cmd, "add"), is_scan = !strcmp(cmd, "scan"), is_rm = !strcmp(cmd, "rm");
	if (!is_add && !is_scan && !is_rm)
		usage();
	struct strv pkgs = {0}, ignore = {0}, keep = {0};
	bool yes = false, opts = true;
	for (int i = 2; i < argc; i++) {
		const char *a = argv[i];
		if (opts && !strcmp(a, "--")) {
			opts = false;
		} else if (opts && is_add && !strcmp(a, "--ignore") && i + 1 < argc) {
			strv_add(&ignore, argv[++i]);
		} else if (opts && is_add && startswith(a, "--ignore=")) {
			strv_add(&ignore, a + 9);
		} else if (opts && !is_rm && !strcmp(a, "--keep") && i + 1 < argc) {
			strv_add(&keep, argv[++i]);
		} else if (opts && !is_rm && startswith(a, "--keep=")) {
			strv_add(&keep, a + 7);
		} else if (opts && is_add && (!strcmp(a, "-y") || !strcmp(a, "--yes"))) {
			yes = true;
		} else if (opts && a[0] == '-') {
			usage();
		} else {
			strv_add(&pkgs, a);
		}
	}
	if (!pkgs.n)
		usage();

	if (is_scan) {
		int n = scan(pkgs.v, pkgs.n, &keep);
		strip_quiet();
		printf("обезврежено объектов: %d\n", n);
		return 0;
	}
	if (is_rm) {
		struct strv a = {0};
		strv_add(&a, "xbps-remove");
		strv_add(&a, "-Ry");
		for (size_t i = 0; i < pkgs.n; i++)
			strv_add(&a, pkgs.v[i]);
		must(a.v);
		run((char *const[]){"xbps-remove", "-oy", NULL}, NULL, 0, NULL, NULL);
		return 0;
	}

	/* add */
	if (path_exists("/etc/vh/optional/strict-net"))
		must((char *const[]){"/usr/local/sbin/vh-net", "xbps", "30", NULL});
	for (size_t i = 0; i < ignore.n; i++) {
		char *line = xasprintf("ignorepkg=%s", ignore.v[i]);
		if (append_unique(IGNORE, line,
				  "# void-hardened: зависимости, которые vh-pkg по просьбе админа не ставит (docs/12)"))
			printf("%s: зависимость не будет ставиться (проверьте, что программа работает)\n", line);
		free(line);
	}
	struct strv a = {0};
	strv_add(&a, "xbps-install");
	strv_add(&a, "-Sn");
	for (size_t i = 0; i < pkgs.n; i++)
		strv_add(&a, pkgs.v[i]);
	struct buf out = {0}, err = {0};
	int rc = run(a.v, NULL, 0, &out, &err);
	if (rc != 0 && rc != 6)               /* 6: всё уже установлено */
		die("%s", *strip(err.p) ? strip(err.p) : strip(out.p));
	struct strv plan = {0};
	char *save = NULL;
	for (char *l = strtok_r(out.p, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
		char f0[256], f1[64];
		if (sscanf(l, "%255s %63s", f0, f1) == 2 && (!strcmp(f1, "install") || !strcmp(f1, "update")))
			strv_add(&plan, f0);
	}
	if (!plan.n) {
		puts("нечего ставить — всё уже установлено");
		return 0;
	}
	printf("Будет установлено (%zu):\n", plan.n);
	struct strv bad = {0}, names = {0};
	for (size_t i = 0; i < plan.n; i++) {
		char *n = pkgname(plan.v[i]);
		const char *why = deny_reason(n);
		if (why) {
			printf("   !! %s  — %s\n", plan.v[i], why);
			strv_add(&bad, n);
		} else {
			printf("      %s\n", plan.v[i]);
		}
		strv_take(&names, n);
	}
	if (bad.n) {
		struct strv deps = {0};
		for (size_t i = 0; i < bad.n; i++)
			if (!strv_has(&pkgs, bad.v[i]))
				strv_add(&deps, bad.v[i]);
		puts("\nВ списке нежелательное (!!).");
		if (deps.n) {
			char *p = strv_join(&pkgs, " ");
			puts("Если программа работает без этих зависимостей, не ставьте их:");
			printf("   doas vh-pkg add %s", p);
			for (size_t i = 0; i < deps.n; i++)
				printf(" --ignore %s", deps.v[i]);
			putchar('\n');
			free(p);
		}
		if (!ask("Ставить всё равно?", false))
			die("отменено");
	} else if (!ask("Установить?", yes)) {
		die("отменено");
	}
	free(a.v[1]);                         /* -Sn → -y */
	a.v[1] = xstrdup("-y");
	must(a.v);
	puts("\nРазбор файлов новых пакетов:");
	int n = scan(names.v, names.n, &keep);
	run((char *const[]){"xbps-remove", "-oy", NULL}, NULL, 0, NULL, NULL);
	strip_quiet();
	printf("\nОбезврежено объектов: %d. Проверка всей системы: doas vh-audit\n", n);
	return 0;
}
