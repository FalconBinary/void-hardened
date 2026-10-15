/* vh-open — открыть недоверенный файл в песочнице (optional/viewers, docs/12, docs/13).
 *
 *   vh-open ФАЙЛ          — PDF → zathura, картинки → imv, видео/аудио → mpv, текст → less
 *   vh-open --gpu ФАЙЛ    — mpv с аппаратным декодированием (свои файлы: render node i915)
 *
 * Песочница bwrap: без сети и user namespace, свой /proc без счётчиков прерываний, /tmp —
 * каталог на noexec-tmpfs хоста, Wayland — только через фильтр vh-wlfilter, звук — через
 * ограниченный сокет PipeWire (без микрофона), seccomp-фильтр (тот же генератор, что
 * vh-seccomp viewer), PR_SET_MDWE (W^X силами ядра) для программ без JIT.
 *
 * Файл открывается без гонки «проверил путь — открыл другой»: компоненты пути проходятся
 * через openat(O_NOFOLLOW) от каталога, последний — O_PATH|O_NOFOLLOW, затем fstat —
 * обычный файл; в bwrap передаётся дескриптор (--ro-bind-fd), путь больше не используется.
 * Симлинки, подложенные браузером, отвергаются (а на /home/xfer — nosymfollow и так).
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "seccomp.h"
#include "vh.h"

#define WL "/run/vh-sandbox/wayland"
#define PULSE "/run/vh-sandbox/pulse"
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif

static const char usage_text[] =
	"vh-open ФАЙЛ          — PDF → zathura, картинки → imv, видео/аудио → mpv, текст → less\n"
	"vh-open --gpu ФАЙЛ    — mpv с аппаратным декодированием (свои файлы: render node i915)\n";

/* абсолютный путь без «.» и «..» (как os.path.abspath: без разрешения симлинков) */
static char *abspath(const char *p)
{
	struct buf in = {0};
	if (p[0] != '/') {
		char cwd[PATH_MAX];
		if (!getcwd(cwd, sizeof(cwd)))
			die("getcwd: %s", strerror(errno));
		buf_addf(&in, "%s/", cwd);
	}
	buf_adds(&in, p);
	struct strv parts = {0};
	char *save = NULL;
	for (char *t = strtok_r(in.p, "/", &save); t; t = strtok_r(NULL, "/", &save)) {
		if (!strcmp(t, "."))
			continue;
		if (!strcmp(t, "..")) {
			if (parts.n)
				free(parts.v[--parts.n]);
			continue;
		}
		strv_add(&parts, t);
	}
	struct buf out = {0};
	buf_adds(&out, "");
	for (size_t i = 0; i < parts.n; i++)
		buf_addf(&out, "/%s", parts.v[i]);
	if (!out.len)
		buf_adds(&out, "/");
	strv_free(&parts);
	buf_free(&in);
	return out.p;
}

/* O_PATH-дескриптор обычного файла; ни один компонент пути не симлинк */
static int open_nofollow(const char *path, char **name)
{
	char *copy = xstrdup(path);
	char *last = strrchr(copy, '/');
	if (!last || !last[1])
		die("%s: не файл", path);
	*name = xstrdup(last + 1);
	*last = 0;
	int fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	char *save = NULL;
	for (char *t = strtok_r(copy, "/", &save); t; t = strtok_r(NULL, "/", &save)) {
		int nfd = openat(fd, t, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (nfd < 0)
			die("%s: %s (симлинк или нет файла)", path, strerror(errno));
		close(fd);
		fd = nfd;
	}
	/* без O_CLOEXEC: дескриптор наследует bwrap (--ro-bind-fd) */
	int ffd = openat(fd, *name, O_PATH | O_NOFOLLOW);
	if (ffd < 0)
		die("%s: %s (симлинк или нет файла)", path, strerror(errno));
	close(fd);
	free(copy);
	struct stat st;
	if (fstat(ffd, &st) != 0 || !S_ISREG(st.st_mode))
		die("%s: не обычный файл", path);
	return ffd;
}

static bool pre(const unsigned char *h, size_t n, const char *sig, size_t sl)
{
	return n >= sl && memcmp(h, sig, sl) == 0;
}

/* тип по сигнатуре (а не только по расширению): без libmagic вне песочницы */
static const char *kind_of(int fd, const char *name)
{
	/* переоткрытие O_PATH-дескриптора через «магическую» ссылку /proc/self/fd: она ведёт
	 * на тот же объект файла, а не на путь (подмена по пути невозможна). O_NOFOLLOW здесь
	 * нельзя — ядро ответило бы ELOOP */
	char p[64];
	snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
	int rfd = open(p, O_RDONLY | O_CLOEXEC);
	if (rfd < 0)
		die("%s: %s", name, strerror(errno));
	unsigned char h[64];
	ssize_t r = read(rfd, h, sizeof(h));
	close(rfd);
	size_t n = r > 0 ? (size_t)r : 0;
	char ext[16] = "";
	const char *dot = strrchr(name, '.');
	if (dot && strlen(dot + 1) < sizeof(ext))
		for (size_t i = 0; dot[1 + i]; i++)
			ext[i] = (char)(dot[1 + i] >= 'A' && dot[1 + i] <= 'Z' ? dot[1 + i] + 32 : dot[1 + i]);
	bool riff = pre(h, n, "RIFF", 4) && n >= 12;
	if (pre(h, n, "%PDF", 4))
		return "pdf";
	if (pre(h, n, "\x89PNG\r\n\x1a\n", 8) || pre(h, n, "\xff\xd8\xff", 3) || pre(h, n, "GIF87a", 6) ||
	    pre(h, n, "GIF89a", 6) || (riff && !memcmp(h + 8, "WEBP", 4)))
		return "image";
	if ((n >= 8 && !memcmp(h + 4, "ftyp", 4)) || pre(h, n, "\x1a\x45\xdf\xa3", 4) || pre(h, n, "OggS", 4) ||
	    pre(h, n, "fLaC", 4) || pre(h, n, "ID3\x03", 4) || pre(h, n, "ID3\x04", 4) ||
	    (riff && (!memcmp(h + 8, "AVI ", 4) || !memcmp(h + 8, "WAVE", 4))) ||
	    !strcmp(ext, "mp3") || !strcmp(ext, "opus") || !strcmp(ext, "m4a"))
		return "media";
	if (!memchr(h, 0, n))
		return "text";
	die("%s: неизвестный тип — откройте вручную в нужной программе с песочницей", name);
}

/* фильтр seccomp в memfd (без возможности исполнения), наследуется bwrap */
static int seccomp_fd(void)
{
	struct bpf_ins prog[SECCOMP_MAX_INS];
	unsigned char bytes[SECCOMP_MAX_INS * 8];
	size_t len = seccomp_bytes(prog, seccomp_build("viewer", prog), bytes);
	int fd = memfd_create("vh-seccomp", MFD_NOEXEC_SEAL);
	if (fd < 0)
		fd = memfd_create("vh-seccomp", 0);
	if (fd < 0 || write(fd, bytes, len) != (ssize_t)len || lseek(fd, 0, SEEK_SET) != 0)
		die("memfd: %s", strerror(errno));
	return fd;
}

int main(int argc, char **argv)
{
	vh_prog = "vh-open";
	bool gpu = false;
	int ai = 1;
	if (argc > 1 && !strcmp(argv[1], "--gpu")) {
		gpu = true;
		ai = 2;
	}
	if (argc - ai != 1) {
		fputs(usage_text, stdout);
		return 2;
	}
	char *path = abspath(argv[ai]), *name;
	int ffd = open_nofollow(path, &name);
	const char *kind = kind_of(ffd, name);
	uid_t uid = getuid();
	char rt[64];
	snprintf(rt, sizeof(rt), "/run/user/%u", uid);
	const char *home = getenv("HOME");
	if (!home || !*home) {
		struct passwd *pw = getpwuid(uid);
		home = pw ? pw->pw_dir : "/";
	}
	char *work = xasprintf("/tmp/vh-open-%u-%d", uid, getpid());
	if (mkdir(work, 0700) != 0)
		die("%s: %s", work, strerror(errno));
	char *wtmp = xasprintf("%s/tmp", work), *whome = xasprintf("%s/home", work), *wrun = xasprintf("%s/run", work);
	if (mkdir(wtmp, 0700) || mkdir(whome, 0700) || mkdir(wrun, 0700))
		die("%s: %s", work, strerror(errno));
	char *target = xasprintf("/input/%s", name);
	char sfd[16], ffds[16];
	snprintf(sfd, sizeof(sfd), "%d", seccomp_fd());
	snprintf(ffds, sizeof(ffds), "%d", ffd);
	const char *lang = getenv("LANG"), *term = getenv("TERM");

	struct strv b = {0};
	const char *base[] = {
		"bwrap",
		"--unshare-all", "--unshare-user", "--disable-userns", "--assert-userns-disabled",
		"--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
		"--ro-bind", "/etc/fonts", "/etc/fonts",
		"--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--ro-bind", "/etc/localtime", "/etc/localtime",
		"--ro-bind-try", "/var/cache/fontconfig", "/var/cache/fontconfig",
		"--proc", "/proc",
		"--ro-bind", "/dev/null", "/proc/interrupts",
		"--ro-bind", "/dev/null", "/proc/softirqs",
		"--ro-bind", "/dev/null", "/proc/stat",
		"--dev", "/dev",
		"--bind", wtmp, "/tmp",
		"--bind", whome, home,
		"--bind", wrun, rt,
		"--ro-bind-fd", ffds, target,
		"--seccomp", sfd,
		"--setenv", "HOME", home, "--setenv", "PATH", "/usr/bin",
		"--setenv", "XDG_RUNTIME_DIR", rt, "--setenv", "LANG", lang && *lang ? lang : "C.UTF-8",
		"--setenv", "GDK_BACKEND", "wayland", "--setenv", "NO_AT_BRIDGE", "1",
		"--setenv", "GSETTINGS_BACKEND", "memory", "--chdir", "/tmp",
	};
	for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); i++)
		strv_add(&b, base[i]);
	char *wl_dst = xasprintf("%s/wayland-0", rt);
	if (strcmp(kind, "text") != 0) {
		if (!path_exists(WL))
			die("нет " WL " — vh-wlfilter не запущен");
		const char *w[] = {"--bind", WL, wl_dst, "--setenv", "WAYLAND_DISPLAY", "wayland-0"};
		for (size_t i = 0; i < 6; i++)
			strv_add(&b, w[i]);
	}
	struct strv cmd = {0};
	bool jit = false;
	if (!strcmp(kind, "pdf")) {
		strv_add(&cmd, "zathura");
	} else if (!strcmp(kind, "image")) {
		strv_add(&cmd, "imv");
	} else if (!strcmp(kind, "media")) {
		char *pdst = xasprintf("%s/pulse/native", rt), *psrv = xasprintf("unix:%s/pulse/native", rt);
		const char *a[] = {"--bind-try", PULSE, pdst, "--setenv", "PULSE_SERVER", psrv};
		for (size_t i = 0; i < 6; i++)
			strv_add(&b, a[i]);
		const char *m[] = {"mpv", "--no-config", "--load-scripts=no", "--ytdl=no", "--osc=no"};
		for (size_t i = 0; i < 5; i++)
			strv_add(&cmd, m[i]);
		if (gpu) {
			const char *g[] = {"--dev-bind-try", "/dev/dri/renderD128", "/dev/dri/renderD128",
					   "--ro-bind", "/sys", "/sys"};
			for (size_t i = 0; i < 6; i++)
				strv_add(&b, g[i]);
			strv_add(&cmd, "--hwdec=vaapi");
		} else {
			strv_add(&cmd, "--vo=wlshm");
			strv_add(&cmd, "--hwdec=no");
		}
		jit = true;                   /* mpv: Lua (возможно LuaJIT) — без MDWE */
	} else {
		const char *t[] = {"--setenv", "LESSSECURE", "1", "--setenv", "LESSHISTFILE", "-",
				   "--setenv", "TERM", term && *term ? term : "xterm"};
		for (size_t i = 0; i < 9; i++)
			strv_add(&b, t[i]);
		strv_add(&cmd, "less");
	}
	strv_add(&cmd, "--");
	strv_add(&cmd, target);
	strv_add(&b, "--");
	for (size_t i = 0; i < cmd.n; i++)
		strv_add(&b, cmd.v[i]);
	/* PR_SET_MDWE(PR_MDWE_REFUSE_EXEC_GAIN): отображение не станет исполняемым после
	 * создания. Наследуется через fork/exec. Не для программ с JIT. */
	if (!jit && prctl(PR_SET_MDWE, 1, 0, 0, 0) != 0)
		warnmsg("PR_SET_MDWE не включён (%s)", strerror(errno));
	execv("/usr/bin/bwrap", b.v);         /* абсолютный путь: PATH не доверяем */
	die("bwrap: %s", strerror(errno));
}
