/* vh-acpid — крышка и кнопка питания без acpid и без suspend (docs/05, docs/12).
 *
 * Читает только два встроенных устройства ввода ACPI: «Lid Switch» (PNP0C0D) и
 * «Power Button» (LNXPWRBN / PNP0C0C). USB-клавиатуры и виртуальные устройства
 * (uinput) не слушает — их события сюда не попадают.
 *
 *   крышка закрыта          → блокировка экрана повседневного пользователя (swaylock);
 *   закрыта дольше LID_MIN  → штатное выключение (suspend запрещён: ключ LUKS в RAM,
 *                             а работающий ноутбук в сумке перегревается);
 *   внешний монитор подключён → крышка ничего не делает (работа с закрытой крышкой);
 *   кнопка питания          → POWER_KEY: poweroff (по умолчанию) | lock | ignore;
 *   простой (IDLE_*_MIN > 0) → блокировка и штатное выключение по времени без ФИЗИЧЕСКОГО
 *                             ввода: учитываются только встроенные клавиатура (i8042) и
 *                             тачпад (I2C-HID/PS2). idle-inhibit браузера, USB-устройства и
 *                             uinput сеанс не продлевают; захват устройства (EVIOCGRAB) =
 *                             нет ввода = выключение — отказ в безопасную сторону.
 *                             По умолчанию выключено; включает optional/deadman.
 *
 * Штатное выключение — /usr/bin/poweroff: стадия 3 runit останавливает сервисы,
 * сбрасывает данные и размонтирует ФС. Длинное нажатие кнопки (4 с) — аппаратное
 * выключение, мимо этого демона.
 *
 * Настройки — /etc/vh/acpi.conf. Ожидание — блокирующий poll(): в простое ни
 * одного пробуждения.
 */
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <linux/input.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "vh.h"

#define CONF "/etc/vh/acpi.conf"
#define ENV "/etc/vh/vh.env"
#define MAX_DEV 32

enum kind { K_LID, K_POWER, K_INPUT };

struct dev {
	int fd;
	enum kind kind;
};

static double now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char *kind_name(enum kind k)
{
	return k == K_LID ? "lid" : k == K_POWER ? "power" : "input";
}

/* /dev/input/eventN: крышка и кнопка питания (только ACPI) и встроенные устройства
 * ввода для сторожа простоя (i8042, I2C-HID и явно указанные части пути sysfs) */
static void find_devices(char *lid, char *power, struct strv *builtin, const struct strv *extra)
{
	glob_t g;
	lid[0] = power[0] = 0;
	if (glob("/sys/class/input/event*", 0, NULL, &g) != 0)
		return;
	for (size_t i = 0; i < g.gl_pathc; i++) {
		const char *ev = g.gl_pathv[i];
		char p[PATH_MAX], name[256], phys[256], real[PATH_MAX], node[PATH_MAX];
		snprintf(p, sizeof(p), "%s/device/name", ev);
		rd(p, name, sizeof(name));
		snprintf(p, sizeof(p), "%s/device/phys", ev);
		rd(p, phys, sizeof(phys));
		snprintf(p, sizeof(p), "%s/device", ev);
		if (!realpath(p, real))
			real[0] = 0;
		snprintf(node, sizeof(node), "/dev/input/%s", strrchr(ev, '/') + 1);
		char first[256];
		snprintf(first, sizeof(first), "%s", phys);
		char *slash = strchr(first, '/');
		if (slash)
			*slash = 0;
		bool ext = false;
		for (size_t j = 0; j < extra->n; j++)
			ext |= strstr(real, extra->v[j]) != NULL;
		if (strcmp(name, "Lid Switch") == 0 && startswith(phys, "PNP0C0D/")) {
			if (!lid[0])
				snprintf(lid, PATH_MAX, "%s", node);
		} else if (strcmp(name, "Power Button") == 0 &&
			   (strcmp(first, "LNXPWRBN") == 0 || strcmp(first, "PNP0C0C") == 0)) {
			if (!power[0])
				snprintf(power, PATH_MAX, "%s", node);
		} else if (strstr(real, "/virtual/")) {
			continue;                     /* uinput и т. п. — не физический ввод */
		} else if (startswith(phys, "isa0060/serio") ||
			   (strstr(real, "/i2c-") && !strstr(real, "/usb")) || ext) {
			strv_add(builtin, node);
		}
	}
	globfree(&g);
}

static bool lid_closed(int fd)
{
	unsigned char sw[8] = {0};
	if (ioctl(fd, EVIOCGSW(sizeof(sw)), sw) < 0)
		return false;
	return sw[0] & (1 << SW_LID);
}

/* подключён ли внешний монитор (работа с закрытой крышкой) */
static bool external_display(void)
{
	glob_t g;
	bool found = false;
	if (glob("/sys/class/drm/card*-*/status", 0, NULL, &g) != 0)
		return false;
	for (size_t i = 0; i < g.gl_pathc && !found; i++) {
		const char *st = g.gl_pathv[i];
		if (strstr(st, "-eDP-") || strstr(st, "-LVDS-") || strstr(st, "-DSI-"))
			continue;
		char v[64];
		found = strcmp(rd(st, v, sizeof(v)), "connected") == 0;
	}
	globfree(&g);
	return found;
}

/* swaylock в сеансе пользователя: его UID, GID и группы, чистое окружение */
static void lock_session(const char *user)
{
	struct passwd *pw = user[0] ? getpwnam(user) : NULL;
	if (!pw)
		return;
	char rt[64], pat[96];
	snprintf(rt, sizeof(rt), "/run/user/%u", pw->pw_uid);
	snprintf(pat, sizeof(pat), "%s/wayland-*", rt);
	glob_t g;
	const char *sock = NULL;
	if (glob(pat, 0, NULL, &g) == 0)
		for (size_t i = 0; i < g.gl_pathc && !sock; i++)
			if (!endswith(g.gl_pathv[i], ".lock") && access(g.gl_pathv[i], F_OK) == 0)
				sock = g.gl_pathv[i];
	if (!sock) {
		globfree(&g);
		return;                       /* сеанс не запущен: блокировать нечего */
	}
	char *reuid = xasprintf("--reuid=%u", pw->pw_uid), *regid = xasprintf("--regid=%u", pw->pw_gid);
	char *home = xasprintf("HOME=%s", pw->pw_dir), *xdg = xasprintf("XDG_RUNTIME_DIR=%s", rt);
	char *wd = xasprintf("WAYLAND_DISPLAY=%s", strrchr(sock, '/') + 1);
	globfree(&g);
	char *argv[] = {"/usr/bin/setpriv", reuid, regid, "--init-groups", "--reset-env",
			"--no-new-privs", "--", "env", "-i", "PATH=/usr/bin", home, xdg, wd,
			"swaylock", "-f", NULL};
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		int nul = open("/dev/null", O_RDWR);
		dup2(nul, 0);
		dup2(nul, 1);
		dup2(nul, 2);
		close_fds_from(3);
		signal(SIGPIPE, SIG_DFL);
		execv(argv[0], argv);
		_exit(127);
	}
	if (pid < 0) {
		logmsg("swaylock не запустился: %s", strerror(errno));
	} else {
		/* swaylock -f сам уходит в фон, когда экран заблокирован; ждём не больше 10 с */
		int st;
		double end = now() + 10;
		while (waitpid(pid, &st, WNOHANG) == 0) {
			if (now() >= end) {
				kill(pid, SIGKILL);
				waitpid(pid, &st, 0);
				logmsg("swaylock не запустился: таймаут");
				break;
			}
			struct timespec ts = {0, 50 * 1000 * 1000};
			nanosleep(&ts, NULL);
		}
	}
	free(reuid);
	free(regid);
	free(home);
	free(xdg);
	free(wd);
}

static _Noreturn void poweroff(const char *reason)
{
	logmsg("штатное выключение: %s", reason);
	execv("/usr/bin/poweroff", (char *[]){"poweroff", NULL});
	die("poweroff: %s", strerror(errno));
}

int main(void)
{
	vh_prog = "vh-acpid";
	struct kvs conf = {0}, env = {0};
	kv_set(&conf, "LID_MIN", "10");
	kv_set(&conf, "POWER_KEY", "poweroff");
	kv_set(&conf, "IDLE_LOCK_MIN", "0");
	kv_set(&conf, "IDLE_POWEROFF_MIN", "0");
	kv_set(&conf, "INTERNAL_INPUT", "");
	kv_read(&conf, CONF, KV_INLINE);
	kv_read(&env, ENV, KV_INLINE);
	const char *user = kv_get(&env, "VH_USER", "");
	long lid_min = kv_int(&conf, "LID_MIN", "10");
	if (lid_min < 1)
		lid_min = 1;
	const char *power_key = kv_get(&conf, "POWER_KEY", "poweroff");
	long idle_lock = kv_int(&conf, "IDLE_LOCK_MIN", "0") * 60;
	long idle_off = kv_int(&conf, "IDLE_POWEROFF_MIN", "0") * 60;

	struct strv extra = {0}, builtin = {0};
	char *ii = xstrdup(kv_get(&conf, "INTERNAL_INPUT", "")), *save = NULL;
	for (char *t = strtok_r(ii, " \t", &save); t; t = strtok_r(NULL, " \t", &save))
		strv_add(&extra, t);
	char lid_dev[PATH_MAX], power_dev[PATH_MAX];
	find_devices(lid_dev, power_dev, &builtin, &extra);
	if (!(idle_lock || idle_off))
		strv_free(&builtin);
	if (!lid_dev[0] && !power_dev[0] && !builtin.n) {
		logmsg("нет ни крышки, ни кнопки питания ACPI — выходим (стационарный ПК или VM?)");
		execv("/usr/bin/pause", (char *[]){"pause", NULL});   /* runit не перезапускает нас каждую секунду */
		die("pause: %s", strerror(errno));
	}

	struct dev devs[MAX_DEV];
	struct pollfd pfd[MAX_DEV];
	size_t nd = 0;
	const char *paths[MAX_DEV];
	enum kind kinds[MAX_DEV];
	size_t np = 0;
	if (lid_dev[0]) {
		paths[np] = lid_dev;
		kinds[np++] = K_LID;
	}
	if (power_dev[0]) {
		paths[np] = power_dev;
		kinds[np++] = K_POWER;
	}
	for (size_t i = 0; i < builtin.n && np < MAX_DEV; i++) {
		paths[np] = builtin.v[i];
		kinds[np++] = K_INPUT;
	}
	int lid_fd = -1;
	for (size_t i = 0; i < np; i++) {
		int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			die("%s: %s", paths[i], strerror(errno));
		devs[nd] = (struct dev){fd, kinds[i]};
		pfd[nd] = (struct pollfd){.fd = fd, .events = POLLIN};
		nd++;
		if (kinds[i] == K_LID)
			lid_fd = fd;
		logmsg("%s: %s", kind_name(kinds[i]), paths[i]);
	}
	bool have_input = builtin.n > 0;
	double closed_since = lid_fd >= 0 && lid_closed(lid_fd) ? now() : -1;
	double last_input = now();
	bool idle_locked = false;

	for (;;) {
		double t = now(), deadline = -1;
		double cand[3];
		int nc = 0;
		if (closed_since >= 0)
			cand[nc++] = closed_since + (double)lid_min * 60;
		if (have_input && idle_lock && !idle_locked)
			cand[nc++] = last_input + (double)idle_lock;
		if (have_input && idle_off)
			cand[nc++] = last_input + (double)idle_off;
		for (int i = 0; i < nc; i++)
			if (deadline < 0 || cand[i] < deadline)
				deadline = cand[i];
		int timeout = -1;
		if (deadline >= 0) {
			double ms = (deadline - t) * 1000;
			timeout = ms <= 0 ? 0 : ms > INT_MAX ? INT_MAX : (int)ms + 1;
		}
		int r = poll(pfd, nd, timeout);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			die("poll: %s", strerror(errno));
		}
		if (r == 0) {
			t = now();
			if (have_input && idle_off && t >= last_input + (double)idle_off) {
				char why[128];
				snprintf(why, sizeof(why), "нет физического ввода %ld мин", idle_off / 60);
				poweroff(why);
			}
			if (have_input && idle_lock && !idle_locked && t >= last_input + (double)idle_lock) {
				idle_locked = true;
				lock_session(user);
			}
			if (closed_since >= 0 && t >= closed_since + (double)lid_min * 60) {
				if (external_display()) {
					closed_since = -1;    /* подключили монитор, пока крышка закрыта */
					continue;
				}
				char why[128];
				snprintf(why, sizeof(why), "крышка закрыта дольше %ld мин", lid_min);
				poweroff(why);
			}
			continue;
		}
		for (size_t i = 0; i < nd; i++) {
			if (!pfd[i].revents)
				continue;
			struct input_event ev[64];
			ssize_t n = read(devs[i].fd, ev, sizeof(ev));
			if (n < 0 && (errno == EINTR || errno == EAGAIN))
				continue;
			if (n <= 0)
				die("чтение %s: %s", kind_name(devs[i].kind), n < 0 ? strerror(errno) : "конец");
			if (devs[i].kind == K_INPUT) {
				last_input = now();   /* содержимое не разбирается — только факт */
				idle_locked = false;
				continue;
			}
			for (size_t j = 0; j < (size_t)n / sizeof(ev[0]); j++) {
				if (devs[i].kind == K_LID && ev[j].type == EV_SW && ev[j].code == SW_LID) {
					if (ev[j].value == 1) {
						if (external_display()) {
							logmsg("крышка закрыта, внешний монитор — ничего не делаем");
							continue;
						}
						closed_since = now();
						lock_session(user);
					} else {
						closed_since = -1;
					}
				} else if (devs[i].kind == K_POWER && ev[j].type == EV_KEY &&
					   ev[j].code == KEY_POWER && ev[j].value == 1) {
					if (strcmp(power_key, "poweroff") == 0)
						poweroff("кнопка питания");
					else if (strcmp(power_key, "lock") == 0)
						lock_session(user);
				}
			}
		}
	}
}
