/* vh-deadman — стирание ключа LUKS и открытого текста из RAM (optional/deadman, docs/13).
 *
 * Два режима выключения:
 *   тревожный  — извлечение метки (USB-устройство) или комбинация клавиш на встроенной
 *                клавиатуре: ключ тома стирается за доли секунды, данные последних секунд
 *                не сохраняются;
 *   штатный    — стадия 3 runit (кнопка питания, крышка, простой, doas poweroff): сервисы
 *                остановлены, данные сброшены, корень только для чтения — затем то же
 *                стирание (shutdown.d/85-vh-deadman.sh вызывает «vh-deadman final»).
 *
 * Порядок после триггера (без fork, exec и чтения с диска — всё открыто и закреплено в
 * RAM заранее, mlockall):
 *   1. DM_DEV_SUSPEND с NOFLUSH|SKIP_LOCKFS + DM_TARGET_MSG «key wipe» для каждого тома
 *      dm-crypt — ключ тома стёрт из памяти ядра; после этого читать с диска нельзя;
 *   2. kill(-1, SIGKILL) — память процессов освобождается и (init_on_free=1) обнуляется;
 *   3. swapoff и reset zram — zsmalloc не обнуляет освобождённые объекты сам;
 *   4. drop_caches=3 — page cache с расшифрованными файлами, dentry и inode;
 *   5. MOR есть: флаг VhPoweroff в NVRAM и sysrq b — прошивка стирает RAM при POST, а
 *      initramfs по флагу выключает машину (91vhdeadman); MOR нет: sysrq o (выключение).
 * Остаточный риск: процессы, застрявшие в D-state на приостановленном томе, и грязные
 * страницы недавно записанных файлов (без MOR — в RAM до потери питания); длинное нажатие
 * кнопки питания обходит всё это.
 *
 *   vh-deadman daemon   — резидентный режим (runit-сервис vh-deadman)
 *   vh-deadman final    — финал штатного выключения (стадия 3)
 *   vh-deadman test     — показать, что найдено, ничего не делая
 */
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <linux/dm-ioctl.h>
#include <linux/input.h>
#include <linux/netlink.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <time.h>
#include <unistd.h>

#include "vh.h"

#define CONF "/etc/vh/deadman.conf"
/* GUID LINUX_EFI_CRASH_GUID: переменные с ним efivarfs создаёт удаляемыми — initramfs
 * снимет флаг без chattr. Имя не начинается с dump- — efi-pstore его не трогает. */
#define EFI_FLAG "VhPoweroff-cfc8fc79-be2e-4ddc-97f0-9f98bfe298a0"
#define MOR_VAR "/sys/firmware/efi/efivars/MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829"
#define MAX_VOL 16

static const char usage_text[] =
	"vh-deadman daemon   — резидентный режим (runit-сервис vh-deadman)\n"
	"vh-deadman final    — финал штатного выключения (стадия 3)\n"
	"vh-deadman test     — показать, что найдено, ничего не делая\n";

/* struct dm_ioctl с данными; размер кратен 8 */
struct dm_req {
	struct dm_ioctl io;
	char data[64];
};

struct vol {
	char name[DM_NAME_LEN];
	struct dm_req suspend, msg;
};

/* всё, что нужно для стирания, — открыто и подготовлено заранее */
static struct {
	int dmctl, drop, sysrq, efi;
	struct vol vol[MAX_VOL];
	size_t nvol;
	char zdev[MAX_VOL][32];
	int zreset[MAX_VOL];
	size_t nz;
} W = {.efi = -1};

static void dm_init(struct dm_req *r, const char *name, uint32_t flags, const void *payload, size_t plen)
{
	memset(r, 0, sizeof(*r));
	r->io.version[0] = DM_VERSION_MAJOR;
	r->io.version[1] = 0;
	r->io.version[2] = 0;
	r->io.data_size = (uint32_t)((sizeof(struct dm_ioctl) + plen + 7) & ~(size_t)7);
	r->io.data_start = sizeof(struct dm_ioctl);
	r->io.flags = flags;
	snprintf(r->io.name, sizeof(r->io.name), "%s", name);
	if (plen)
		memcpy((char *)r + sizeof(struct dm_ioctl), payload, plen);
}

static void wiper_init(void)
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		logmsg("mlockall: %s — память демона может уйти в zram", strerror(errno));
	W.dmctl = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
	if (W.dmctl < 0)
		die("/dev/mapper/control: %s", strerror(errno));
	glob_t g;
	if (glob("/sys/block/dm-*/dm", 0, NULL, &g) == 0) {
		for (size_t i = 0; i < g.gl_pathc && W.nvol < MAX_VOL; i++) {
			char p[PATH_MAX], uuid[256], name[DM_NAME_LEN];
			snprintf(p, sizeof(p), "%s/uuid", g.gl_pathv[i]);
			if (!startswith(rd(p, uuid, sizeof(uuid)), "CRYPT-"))
				continue;
			snprintf(p, sizeof(p), "%s/name", g.gl_pathv[i]);
			rd(p, name, sizeof(name));
			struct vol *v = &W.vol[W.nvol++];
			snprintf(v->name, sizeof(v->name), "%s", name);
			dm_init(&v->suspend, name, DM_SUSPEND_FLAG | DM_SKIP_LOCKFS_FLAG | DM_NOFLUSH_FLAG, NULL, 0);
			/* struct dm_target_msg: сектор (u64) и текст сообщения */
			char m[8 + sizeof("key wipe")] = {0};
			memcpy(m + 8, "key wipe", sizeof("key wipe"));
			dm_init(&v->msg, name, 0, m, sizeof(m));
		}
		globfree(&g);
	}
	if (glob("/sys/block/zram*", 0, NULL, &g) == 0) {
		for (size_t i = 0; i < g.gl_pathc && W.nz < MAX_VOL; i++) {
			const char *n = strrchr(g.gl_pathv[i], '/') + 1;
			char p[PATH_MAX];
			snprintf(W.zdev[W.nz], sizeof(W.zdev[0]), "/dev/%s", n);
			snprintf(p, sizeof(p), "%s/reset", g.gl_pathv[i]);
			W.zreset[W.nz] = open(p, O_WRONLY | O_CLOEXEC);
			if (W.zreset[W.nz] >= 0)
				W.nz++;
		}
		globfree(&g);
	}
	W.drop = open("/proc/sys/vm/drop_caches", O_WRONLY | O_CLOEXEC);
	W.sysrq = open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC);
	if (W.drop < 0 || W.sysrq < 0)
		die("/proc/sys/vm/drop_caches, /proc/sysrq-trigger: %s", strerror(errno));
	if (path_exists(MOR_VAR))
		W.efi = open("/sys/firmware/efi/efivars", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	/* прогрев: первые вызовы не должны ничего подгружать */
	if (write(W.drop, "1", 1) < 0)
		logmsg("drop_caches: %s", strerror(errno));
}

static void describe(char *out, size_t sz)
{
	char names[256] = "";
	for (size_t i = 0; i < W.nvol; i++) {
		size_t l = strlen(names);
		snprintf(names + l, sizeof(names) - l, "%s%s", i ? ", " : "", W.vol[i].name);
	}
	snprintf(out, sz, "тома dm-crypt: %s; zram: %zu; MOR: %s", W.nvol ? names : "нет", W.nz,
		 W.efi >= 0 ? "есть" : "нет");
}

static _Noreturn void wipe(bool reboot)
{
	for (size_t i = 0; i < W.nvol; i++) {
		/* следующий том стираем, даже если с этим не вышло */
		ioctl(W.dmctl, DM_DEV_SUSPEND, &W.vol[i].suspend);
		ioctl(W.dmctl, DM_TARGET_MSG, &W.vol[i].msg);
	}
	kill(-1, SIGKILL);
	struct timespec ts = {0, 300 * 1000 * 1000};
	nanosleep(&ts, NULL);             /* процессы выходят, слоты swap освобождаются */
	for (size_t i = 0; i < W.nz; i++) {
		swapoff(W.zdev[i]);
		if (write(W.zreset[i], "1", 1) < 0) {
			/* reset занятого устройства не удался — RAM всё равно стирается ниже */
		}
	}
	if (write(W.drop, "3", 1) < 0) {
		/* нечего делать: ключ уже стёрт */
	}
	if (W.efi < 0) {
		/* MOR нет: прошивка RAM не сотрёт — выключение мимо userspace, без перезагрузки */
		if (write(W.sysrq, reboot ? "b" : "o", 1) < 0) {
		}
		for (;;)
			pause();
	}
	if (!reboot) {
		int fd = openat(W.efi, EFI_FLAG, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		if (fd >= 0) {
			static const char v[] = {0x07, 0x00, 0x00, 0x00, 0x01};   /* NV|BS|RT + 1 байт */
			if (write(fd, v, sizeof(v)) < 0) {
			}
			close(fd);
		}
	}
	if (write(W.sysrq, "b", 1) < 0) {  /* перезагрузка через прошивку: MOR стирает RAM */
	}
	for (;;)
		pause();
}

/* TAG = vid:pid (hex, как в lsusb) */
static void parse_tag(const char *tag, unsigned *vid, unsigned *pid)
{
	char *end;
	errno = 0;
	unsigned long v = strtoul(tag, &end, 16);
	if (errno || end == tag || *end != ':' || v > 0xFFFF)
		die("TAG=%s: нужен vid:pid (lsusb)", tag);
	const char *p = end + 1;
	unsigned long q = strtoul(p, &end, 16);
	if (errno || end == p || (*end && *end != ':') || q > 0xFFFF)
		die("TAG=%s: нужен vid:pid (lsusb)", tag);
	*vid = (unsigned)v;
	*pid = (unsigned)q;
}

/* есть ли такое USB-устройство; его DEVPATH (без /sys) — в out */
static bool tag_present(unsigned vid, unsigned pid, char *out, size_t sz)
{
	glob_t g;
	bool found = false;
	if (glob("/sys/bus/usb/devices/*", 0, NULL, &g) != 0)
		return false;
	for (size_t i = 0; i < g.gl_pathc && !found; i++) {
		char p[PATH_MAX], v[16], q[16];
		snprintf(p, sizeof(p), "%s/idVendor", g.gl_pathv[i]);
		if (!*rd(p, v, sizeof(v)))
			continue;
		snprintf(p, sizeof(p), "%s/idProduct", g.gl_pathv[i]);
		rd(p, q, sizeof(q));
		if (strtoul(v, NULL, 16) != vid || strtoul(q, NULL, 16) != pid)
			continue;
		char real[PATH_MAX];
		if (realpath(g.gl_pathv[i], real) && startswith(real, "/sys")) {
			snprintf(out, sz, "%s", real + 4);
			found = true;
		}
	}
	globfree(&g);
	return found;
}

static void status(const char *s)
{
	FILE *f = fopen("/run/vh/deadman", "w");
	if (f) {
		fprintf(f, "%s\n", s);
		fclose(f);
	}
}

/* значение KEY= в сообщении uevent (поля через \0) */
static const char *uev(const char *d, size_t n, const char *key)
{
	size_t kl = strlen(key);
	for (size_t i = 0; i < n;) {
		const char *f = d + i;
		size_t l = strnlen(f, n - i);
		if (l > kl && memcmp(f, key, kl) == 0 && f[kl] == '=')
			return f + kl + 1;
		i += l + 1;
	}
	return "";
}

static _Noreturn void daemon_loop(const struct kvs *conf)
{
	const char *tag = kv_get(conf, "TAG", "");
	unsigned vid = 0, pid = 0;
	char armed[PATH_MAX] = "", prod[32] = "";
	struct pollfd pfd[2];
	int np = 0, nl = -1, kbd = -1, wd = -1;
	if (*tag) {
		parse_tag(tag, &vid, &pid);
		snprintf(prod, sizeof(prod), "%x/%x/", vid, pid);
		nl = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
		struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = 1};
		if (nl < 0 || bind(nl, (struct sockaddr *)&sa, sizeof(sa)) != 0)
			die("netlink uevent: %s", strerror(errno));
		pfd[np++] = (struct pollfd){.fd = nl, .events = POLLIN};
		tag_present(vid, pid, armed, sizeof(armed));
	}
	if (strcmp(kv_get(conf, "COMBO", "no"), "yes") == 0) {
		glob_t g;
		if (glob("/sys/class/input/event*", 0, NULL, &g) == 0) {
			for (size_t i = 0; i < g.gl_pathc && kbd < 0; i++) {
				char p[PATH_MAX], phys[128];
				snprintf(p, sizeof(p), "%s/device/phys", g.gl_pathv[i]);
				if (!startswith(rd(p, phys, sizeof(phys)), "isa0060/serio0"))
					continue;     /* только встроенная клавиатура i8042 */
				snprintf(p, sizeof(p), "/dev/input/%s", strrchr(g.gl_pathv[i], '/') + 1);
				kbd = open(p, O_RDONLY | O_CLOEXEC);
			}
			globfree(&g);
		}
		if (kbd >= 0)
			pfd[np++] = (struct pollfd){.fd = kbd, .events = POLLIN};
	}
	if (strcmp(kv_get(conf, "WATCHDOG", "no"), "yes") == 0 && path_exists("/dev/watchdog"))
		wd = open("/dev/watchdog", O_WRONLY | O_CLOEXEC);
	mkdirs("/run/vh", 0755);
	status(armed[0] ? "armed" : "disarmed");
	char d[512];
	describe(d, sizeof(d));
	logmsg("%s; метка %s: %s; комбинация: %s; сторож: %s", d, *tag ? tag : "—",
	       armed[0] ? "вставлена" : "нет", kbd >= 0 ? "да" : "нет", wd >= 0 ? "да" : "нет");
	bool rctrl = false, ralt = false, end = false;
	for (;;) {
		if (wd >= 0 && write(wd, "\0", 1) < 0)
			logmsg("watchdog: %s", strerror(errno));
		int r = poll(pfd, (nfds_t)np, wd >= 0 ? 10000 : -1);
		if (r < 0 && errno != EINTR)
			die("poll: %s", strerror(errno));
		for (int i = 0; r > 0 && i < np; i++) {
			if (!pfd[i].revents)
				continue;
			if (pfd[i].fd == nl) {
				static char buf[8192];
				struct sockaddr_nl from;
				socklen_t fl = sizeof(from);
				ssize_t n = recvfrom(nl, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fl);
				if (n <= 0 || from.nl_pid != 0)
					continue;     /* только сообщения ядра */
				buf[n] = 0;
				if (strcmp(uev(buf, (size_t)n, "SUBSYSTEM"), "usb") != 0 ||
				    strcmp(uev(buf, (size_t)n, "DEVTYPE"), "usb_device") != 0 ||
				    !startswith(uev(buf, (size_t)n, "PRODUCT"), prod))
					continue;
				const char *action = uev(buf, (size_t)n, "ACTION");
				const char *devpath = uev(buf, (size_t)n, "DEVPATH");
				if (strcmp(action, "add") == 0) {
					snprintf(armed, sizeof(armed), "%s", devpath);
					status("armed");
				} else if (strcmp(action, "remove") == 0 && armed[0] &&
					   strcmp(devpath, armed) == 0) {
					logmsg("метка извлечена — тревожное выключение");
					wipe(false);
				}
			} else if (pfd[i].fd == kbd) {
				struct input_event ev[64];
				ssize_t n = read(kbd, ev, sizeof(ev));
				if (n <= 0)
					continue;
				for (size_t j = 0; j < (size_t)n / sizeof(ev[0]); j++) {
					if (ev[j].type != EV_KEY || ev[j].value == 2)
						continue;
					bool down = ev[j].value == 1;
					if (ev[j].code == KEY_RIGHTCTRL)
						rctrl = down;
					else if (ev[j].code == KEY_RIGHTALT)
						ralt = down;
					else if (ev[j].code == KEY_END)
						end = down;
					if (rctrl && ralt && end) {
						logmsg("тревожная комбинация — выключение");
						wipe(false);
					}
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	vh_prog = "vh-deadman";
	if (geteuid() != 0)
		die("нужен root");
	const char *mode = argc > 1 ? argv[1] : "";
	struct kvs conf = {0};
	kv_set(&conf, "TAG", "");
	kv_set(&conf, "COMBO", "no");
	kv_set(&conf, "WATCHDOG", "no");
	kv_read(&conf, CONF, KV_INLINE);
	if (strcmp(mode, "test") == 0) {
		wiper_init();
		char d[512], armed[PATH_MAX] = "";
		describe(d, sizeof(d));
		const char *tag = kv_get(&conf, "TAG", "");
		if (*tag) {
			unsigned vid, pid;
			parse_tag(tag, &vid, &pid);
			tag_present(vid, pid, armed, sizeof(armed));
		}
		printf("%s | метка: %s %s\n", d, *tag ? tag : "—", armed[0] ? "вставлена" : "");
	} else if (strcmp(mode, "final") == 0) {
		wiper_init();
		if (strcmp(kv_get(&conf, "WATCHDOG", "no"), "yes") == 0) {
			int wd = open("/dev/watchdog", O_WRONLY | O_CLOEXEC);
			if (wd >= 0 && write(wd, "\0", 1) < 0) {
			}
		}
		bool reboot = access("/run/runit/reboot", X_OK) == 0;
		printf("vh-deadman: стирание ключа и RAM (%s)\n", reboot ? "перезагрузка" : "выключение");
		fflush(stdout);
		wipe(reboot);
	} else if (strcmp(mode, "daemon") == 0) {
		wiper_init();
		daemon_loop(&conf);
	} else {
		fputs(usage_text, stdout);
		return 2;
	}
	return 0;
}
