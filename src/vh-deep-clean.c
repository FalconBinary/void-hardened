/* vh-deep-clean — полная очистка системы: удаляется только ненужное (docs/12, раздел «Очистка»).
 *
 *   doas vh-deep-clean                    план: что удалится и сколько места освободится;
 *                                         ничего не меняет
 *   doas vh-deep-clean --apply [-y]       выполнить; каждая группа — с вопросом [y/N]
 *                  [--user]               плюс мусор пользователей (~/.cache, кэш Firefox, корзина)
 *                  [--only ГРУППА,…]      только эти группы
 *   doas vh-deep-clean restore            вернуть файлы из последнего резерва
 *
 * Группы:
 *   orphans   зависимости, которые больше никому не нужны (xbps-remove -o). Пакеты из
 *             /etc/vh/deep-clean.keep и ядро системы сначала помечаются ручными и остаются.
 *   conf      конфиги без владельца из двух точных источников: *.new-ВЕРСИЯ, которые xbps
 *             оставляет рядом с изменённым конфигом при обновлении, и изменённые конфиги
 *             удалённых пакетов (их conf_files: журнал vh-pkg rm и сироты этого запуска).
 *             Правила «ничей файл в /etc — мусор» нет: там ключи, fstab, файлы самой системы.
 *   services  битые ссылки в /etc/runit/runsvdir/УРОВЕНЬ (пакет сервиса удалён).
 *   kernels   старые ядра — vkpurge (он не трогает работающее ядро и ядра установленных
 *             пакетов; хуки ядра убирают UKI и запись Limine) и каталоги модулей без ядра.
 *   cache     скачанные пакеты в /var/cache/xbps (xbps скачает их снова при надобности).
 *   user      (--user) ~/.cache людей и root, кэш Firefox пользователя браузера (не профиль),
 *             корзина. Удаляется от имени владельца; занятое программами остаётся.
 *
 * Конфиги и ссылки сервисов не удаляются, а переносятся в /var/lib/vh/deep-clean/last
 * (0700); restore возвращает их, следующий --apply удаляет прошлый резерв. Пакеты, ядра и
 * кэши — без резерва: они ставятся или создаются заново. До и после --apply запускается
 * vh-audit: новые [FAIL] печатаются, код выхода 1. Журналы, /etc/vh, ключи, профили и
 * настройки пользователей не трогаются никогда.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "vh.h"

#define BK_DIR "/var/lib/vh/deep-clean"
#define BK_LAST BK_DIR "/last"
#define CONF_LEDGER "/var/lib/vh/removed-conf.list"
#define KEEP_FILE "/etc/vh/deep-clean.keep"
#define AUDIT "/usr/local/sbin/vh-audit"
#define CACHE_DIR "/var/cache/xbps"

enum {
	G_ORPHANS = 1, G_CONF = 2, G_SERVICES = 4, G_KERNELS = 8, G_CACHE = 16, G_USER = 32,
};
static const struct {
	const char *name;
	int bit;
} group_names[] = {
	{"orphans", G_ORPHANS}, {"conf", G_CONF}, {"services", G_SERVICES},
	{"kernels", G_KERNELS}, {"cache", G_CACHE}, {"user", G_USER},
};

static bool apply, yes;
static struct strv keep_pkgs, keep_paths;
static struct kvs env, boot;
static struct strv orphan_conf;          /* conf_files сирот, удалённых в этом запуске */
static long long total;                  /* освобождено (или будет освобождено) байт */
static bool bk_ready;

/* ---------- мелочи ---------- */

static const char *hsize(long long n)
{
	static char b[4][32];
	static int i;
	char *o = b[i++ & 3];
	static const char *const u[] = {"Б", "КБ", "МБ", "ГБ", "ТБ"};
	double v = (double)n;
	int k = 0;
	while (v >= 1024 && k < 4) {
		v /= 1024;
		k++;
	}
	snprintf(o, 32, k ? "%.1f %s" : "%.0f %s", v, u[k]);
	return o;
}

static char *pkgname(const char *pkgver)
{
	const char *d = strrchr(pkgver, '-');
	return d ? xstrndup(pkgver, (size_t)(d - pkgver)) : xstrdup(pkgver);
}

static void section(const char *title)
{
	printf("\n── %s\n", title);
}

/* построчно: каждая строка без пробелов по краям, пустые пропускаются */
#define FOR_LINES(l, text, save)                                                        \
	for (char *save = NULL, *l = strtok_r((text), "\n", &save); l;                  \
	     l = strtok_r(NULL, "\n", &save))                                           \
		if (*(l = strip(l)))

/* ---------- обход каталогов без перехода по симлинкам ---------- */

/* Содержимое каталога dfd: размер на диске, при del — удалить. По симлинкам не идёт,
 * в другие ФС (точки монтирования) не заходит. */
static long long tree(int dfd, bool del, int depth)
{
	struct stat dst;
	if (fstat(dfd, &dst) != 0)
		return 0;
	int d2 = dup(dfd);
	if (d2 < 0)
		return 0;
	DIR *d = fdopendir(d2);
	if (!d) {
		close(d2);
		return 0;
	}
	long long sum = 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		struct stat st;
		if (fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			if (st.st_dev != dst.st_dev || depth > 64)
				continue;
			int sub = openat(dfd, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if (sub < 0)
				continue;
			sum += tree(sub, del, depth + 1);
			close(sub);
			sum += (long long)st.st_blocks * 512;
			if (del)
				unlinkat(dfd, e->d_name, AT_REMOVEDIR);
		} else {
			sum += (long long)st.st_blocks * 512;
			if (del && unlinkat(dfd, e->d_name, 0) != 0 && errno != ENOENT)
				warnmsg("%s: %s", e->d_name, strerror(errno));
		}
	}
	closedir(d);
	return sum;
}

/* один объект name в каталоге dfd: размер; при del — удалить целиком */
static long long entry(int dfd, const char *name, bool del)
{
	struct stat st;
	if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0)
		return 0;
	long long sum = (long long)st.st_blocks * 512;
	if (S_ISDIR(st.st_mode)) {
		int sub = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (sub >= 0) {
			sum += tree(sub, del, 0);
			close(sub);
		}
		if (del && unlinkat(dfd, name, AT_REMOVEDIR) != 0 && errno != ENOENT)
			warnmsg("%s: %s", name, strerror(errno));
	} else if (del && unlinkat(dfd, name, 0) != 0 && errno != ENOENT) {
		warnmsg("%s: %s", name, strerror(errno));
	}
	return sum;
}

/* путь целиком (файл или каталог): размер; при del — удалить */
static long long path_entry(const char *path, bool del)
{
	char *dir = xstrdup(path);
	char *slash = strrchr(dir, '/');
	if (!slash || !slash[1]) {
		free(dir);
		return 0;
	}
	*slash = 0;
	int dfd = open(*dir ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	long long n = 0;
	if (dfd >= 0) {
		n = entry(dfd, slash + 1, del);
		close(dfd);
	}
	free(dir);
	return n;
}

/* каталог rel внутри base, ни один компонент — не симлинк; -1, если нет */
static int open_under(const char *base, const char *rel)
{
	int fd = open(base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	char *copy = xstrdup(rel);
	char *save = NULL;
	for (char *c = strtok_r(copy, "/", &save); c && fd >= 0; c = strtok_r(NULL, "/", &save)) {
		int n = openat(fd, c, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		close(fd);
		fd = n;
	}
	free(copy);
	return fd;
}

/* ---------- процессы ---------- */

static bool proc_comm_running(const char *const names[], size_t n)
{
	DIR *d = opendir("/proc");
	if (!d)
		return false;
	bool found = false;
	struct dirent *e;
	while (!found && (e = readdir(d))) {
		if (e->d_name[0] < '1' || e->d_name[0] > '9')
			continue;
		char p[300], comm[64];
		snprintf(p, sizeof(p), "/proc/%s/comm", e->d_name);
		rd(p, comm, sizeof(comm));
		for (size_t i = 0; i < n; i++)
			if (!strcmp(comm, names[i]))
				found = true;
	}
	closedir(d);
	return found;
}

static bool uid_has_procs(uid_t uid)
{
	DIR *d = opendir("/proc");
	if (!d)
		return false;
	bool found = false;
	struct dirent *e;
	while (!found && (e = readdir(d))) {
		if (e->d_name[0] < '1' || e->d_name[0] > '9')
			continue;
		char p[300];
		snprintf(p, sizeof(p), "/proc/%s/status", e->d_name);
		char *t = read_file(p, NULL);
		const char *u = t ? strstr(t, "\nUid:") : NULL;
		unsigned long r;
		if (u && sscanf(u + 5, "%lu", &r) == 1 && r == uid)
			found = true;
		free(t);
	}
	closedir(d);
	return found;
}

/* все файлы, открытые или отображённые в память процессами */
static void open_paths(struct strv *out)
{
	DIR *d = opendir("/proc");
	if (!d)
		return;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] < '1' || e->d_name[0] > '9')
			continue;
		char p[300], l[4096];
		snprintf(p, sizeof(p), "/proc/%s/fd", e->d_name);
		DIR *fd = opendir(p);
		if (fd) {
			struct dirent *f;
			while ((f = readdir(fd))) {
				char q[600];
				snprintf(q, sizeof(q), "%s/%s", p, f->d_name);
				ssize_t n = readlink(q, l, sizeof(l) - 1);
				if (n > 0 && l[0] == '/') {
					l[n] = 0;
					strv_add(out, l);
				}
			}
			closedir(fd);
		}
		snprintf(p, sizeof(p), "/proc/%s/maps", e->d_name);
		char *m = read_file(p, NULL);
		if (m)
			FOR_LINES(line, m, s1) {
				char *path = strchr(line, '/');
				if (path)
					strv_add(out, path);
			}
		free(m);
	}
	closedir(d);
}

/* path или что-то внутри него открыто процессом */
static bool in_use(const struct strv *used, const char *path)
{
	size_t n = strlen(path);
	for (size_t i = 0; i < used->n; i++)
		if (!strncmp(used->v[i], path, n) && (used->v[i][n] == 0 || used->v[i][n] == '/'))
			return true;
	return false;
}

/* ---------- xbps ---------- */

static bool owned(const char *pattern)
{
	struct buf o = {0};
	run((char *const[]){"xbps-query", "-o", (char *)pattern, NULL}, NULL, 0, &o, NULL);
	bool r = o.p && *strip(o.p);
	buf_free(&o);
	return r;
}

static void conf_files(const char *name, struct strv *out)
{
	struct buf o = {0};
	run((char *const[]){"xbps-query", "-p", "conf_files", (char *)name, NULL}, NULL, 0, &o, NULL);
	if (o.p)
		FOR_LINES(l, o.p, s1)
			if (*l == '/' && !strv_has(out, l))
				strv_add(out, l);
	buf_free(&o);
}

/* сироты: pkgver и установленный размер каждого (xbps-remove -on) */
static size_t orphans(struct strv *pkgvers, long long **sizes)
{
	struct buf o = {0};
	run((char *const[]){"xbps-remove", "-on", NULL}, NULL, 0, &o, NULL);
	if (o.p)
		FOR_LINES(l, o.p, s1) {
			char f0[256], f1[64];
			long long sz = 0;
			if (sscanf(l, "%255s %63s %*s %*s %lld", f0, f1, &sz) >= 2 && !strcmp(f1, "remove")) {
				strv_add(pkgvers, f0);
				*sizes = xrealloc(*sizes, pkgvers->n * sizeof(**sizes));
				(*sizes)[pkgvers->n - 1] = sz;
			}
		}
	buf_free(&o);
	return pkgvers->n;
}

/* ---------- защита путей ---------- */

static bool protected_path(const char *p)
{
	if (startswith(p, "/etc/vh/") || !strcmp(p, "/etc/vh"))
		return true;
	for (size_t i = 0; i < keep_paths.n; i++) {
		size_t n = strlen(keep_paths.v[i]);
		if (!strncmp(p, keep_paths.v[i], n) && (p[n] == 0 || p[n] == '/' || keep_paths.v[i][n - 1] == '/'))
			return true;
	}
	/* файл самой void-hardened (её копия — в /root/vh) */
	static const char *const sfx[] = {"", ".in", ".cin"};
	for (size_t i = 0; i < 3; i++) {
		char *r = xasprintf("/root/vh/rootfs%s%s", p, sfx[i]);
		bool e = path_exists(r);
		free(r);
		if (e)
			return true;
	}
	return false;
}

static void load_keep(void)
{
	char *t = read_file(KEEP_FILE, NULL);
	if (!t)
		return;
	FOR_LINES(l, t, s1) {
		if (*l == '#')
			continue;
		strv_add(*l == '/' ? &keep_paths : &keep_pkgs, l);
	}
	free(t);
}

/* ---------- резерв ---------- */

static void copy_one(const char *src, const char *dst)
{
	struct stat st;
	if (lstat(src, &st) != 0)
		die("%s: %s", src, strerror(errno));
	if (S_ISLNK(st.st_mode)) {
		char l[4096];
		ssize_t n = readlink(src, l, sizeof(l) - 1);
		if (n < 0)
			die("%s: %s", src, strerror(errno));
		l[n] = 0;
		if (symlink(l, dst) != 0)
			die("%s: %s", dst, strerror(errno));
		if (lchown(dst, st.st_uid, st.st_gid) != 0)
			warnmsg("%s: %s", dst, strerror(errno));
		return;
	}
	if (!S_ISREG(st.st_mode))
		die("%s: не обычный файл", src);
	int in = open(src, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (in < 0)
		die("%s: %s", src, strerror(errno));
	int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (out < 0)
		die("%s: %s", dst, strerror(errno));
	char b[65536];
	ssize_t n;
	while ((n = read(in, b, sizeof(b))) > 0)
		if (write(out, b, (size_t)n) != n)
			die("%s: %s", dst, strerror(errno));
	if (n < 0 || fchown(out, st.st_uid, st.st_gid) != 0 || fchmod(out, st.st_mode & 07777) != 0 ||
	    futimens(out, (struct timespec[]){st.st_atim, st.st_mtim}) != 0 || fsync(out) != 0)
		die("%s: %s", dst, strerror(errno));
	close(out);
	close(in);
}

/* переименовать, а между ФС — скопировать и удалить исходный */
static bool move(const char *src, const char *dst)
{
	if (rename(src, dst) == 0)
		return true;
	if (errno != EXDEV) {
		warnmsg("%s: %s", src, strerror(errno));
		return false;
	}
	copy_one(src, dst);
	if (unlink(src) != 0) {
		warnmsg("%s: %s", src, strerror(errno));
		return false;
	}
	return true;
}

static void bk_start(void)
{
	if (bk_ready)
		return;
	mkdirs(BK_DIR, 0700);
	chmod(BK_DIR, 0700);
	if (path_exists(BK_LAST))
		path_entry(BK_LAST, true);
	if (mkdir(BK_LAST, 0700) != 0)
		die("%s: %s", BK_LAST, strerror(errno));
	char when[64];
	time_t t = time(NULL);
	strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S\n", localtime(&t));
	write_atomic(BK_LAST "/when", when, strlen(when), 0600);
	bk_ready = true;
}

/* файл или ссылку — в резерв */
static bool bk_move(const char *path)
{
	bk_start();
	char *dst = xasprintf("%s/root%s", BK_LAST, path);
	char *dir = xstrdup(dst);
	*strrchr(dir, '/') = 0;
	mkdirs(dir, 0700);
	bool ok = move(path, dst);
	free(dir);
	free(dst);
	return ok;
}

static int restored, skipped;

static void restore_walk(const char *bk, const char *target)
{
	DIR *d = opendir(bk);
	if (!d)
		return;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		char *b = xasprintf("%s/%s", bk, e->d_name);
		char *t = xasprintf("%s/%s", target, e->d_name);
		struct stat st;
		if (lstat(b, &st) == 0 && S_ISDIR(st.st_mode)) {
			restore_walk(b, t);
		} else if (path_exists(t)) {
			printf("  уже есть, оставлен в резерве: %s\n", t);
			skipped++;
		} else {
			char *dir = xstrdup(t);
			*strrchr(dir, '/') = 0;
			if (*dir)
				mkdirs(dir, 0755);
			free(dir);
			if (move(b, t)) {
				printf("  вернул %s\n", t);
				restored++;
			} else {
				skipped++;
			}
		}
		free(t);
		free(b);
	}
	closedir(d);
}

static int do_restore(void)
{
	if (!is_dir(BK_LAST "/root"))
		die("резерва нет (%s)", BK_LAST);
	char *when = read_file(BK_LAST "/when", NULL);
	printf("Резерв от %s", when ? when : "?\n");
	free(when);
	restore_walk(BK_LAST "/root", "");
	if (!skipped)
		path_entry(BK_LAST, true);
	printf("Возвращено: %d, оставлено в резерве: %d\n", restored, skipped);
	if (restored)
		puts("Сервисы, вернувшиеся в /etc/runit/runsvdir, runit запустит сам. Проверка: doas vh-audit");
	return skipped ? 1 : 0;
}

/* ---------- группы ---------- */

/* в режиме плана — false; при --apply — вопрос (или -y) */
static bool confirm(const char *q)
{
	if (!apply)
		return false;
	if (!ask(q, yes)) {
		puts("   пропущено");
		return false;
	}
	return true;
}

static void g_orphans(void)
{
	section("orphans: зависимости, которые больше никому не нужны");
	const char *kernel = kv_get(&env, "VH_KERNEL", "");
	struct strv list = {0}, kept = {0};
	long long *sizes = NULL;
	orphans(&list, &sizes);
	/* keep-список и ядро системы — в ручные: тогда xbps не считает сиротами ни их,
	 * ни их зависимости */
	for (size_t i = 0; i < list.n; i++) {
		char *n = pkgname(list.v[i]);
		if (strv_has(&keep_pkgs, n) || (*kernel && !strcmp(n, kernel)))
			strv_take(&kept, n);
		else
			free(n);
	}
	for (size_t i = 0; i < kept.n; i++) {
		printf("   остаётся (deep-clean.keep или ядро системы): %s\n", kept.v[i]);
		if (apply)
			RUN("xbps-pkgdb", "-m", "manual", kept.v[i]);
	}
	if (apply && kept.n) {
		strv_free(&list);
		free(sizes);
		sizes = NULL;
		orphans(&list, &sizes);
	}
	long long sz = 0;
	size_t shown = 0;
	for (size_t i = 0; i < list.n; i++) {
		char *n = pkgname(list.v[i]);
		if (!strv_has(&kept, n)) {      /* в плане keep-пакеты ещё в списке */
			printf("   %s\n", list.v[i]);
			sz += sizes[i];
			shown++;
		}
		free(n);
	}
	if (!shown) {
		puts("   нет");
		goto out;
	}
	printf("   пакетов: %zu, %s; их изменённые конфиги уйдут в резерв (conf)\n", shown, hsize(sz));
	if (!confirm("Удалить эти пакеты?")) {
		if (!apply)
			total += sz;
		goto out;
	}
	for (size_t i = 0; i < list.n; i++) {
		char *n = pkgname(list.v[i]);
		conf_files(n, &orphan_conf);
		free(n);
	}
	if (RUN("xbps-remove", "-oy") != 0)
		warnmsg("xbps-remove -o завершился с ошибкой");
	else
		total += sz;
out:
	free(sizes);
	strv_free(&kept);
	strv_free(&list);
}

/* «.new-ВЕРСИЯ_РЕВИЗИЯ» в конце имени: так xbps кладёт новую версию изменённого конфига */
static bool xbps_new_name(const char *name)
{
	const char *p = NULL;
	for (const char *s = name; (s = strstr(s, ".new-")); s++)
		p = s;
	if (!p || p == name)
		return false;
	p += 5;
	const char *us = strrchr(p, '_');
	if (!us || us == p || !us[1])
		return false;
	for (const char *c = p; c < us; c++)
		if (!(strchr(".+~-", *c) || (*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'z') ||
		      (*c >= 'A' && *c <= 'Z')))
			return false;
	for (const char *c = us + 1; *c; c++)
		if (*c < '0' || *c > '9')
			return false;
	return true;
}

static void find_new(const char *dir, struct strv *out, int depth)
{
	if (depth > 16 || !strcmp(dir, "/etc/vh"))
		return;
	DIR *d = opendir(dir);
	if (!d)
		return;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		char *p = xasprintf("%s/%s", dir, e->d_name);
		struct stat st;
		if (lstat(p, &st) == 0) {
			if (S_ISDIR(st.st_mode))
				find_new(p, out, depth + 1);
			else if ((S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) && xbps_new_name(e->d_name))
				strv_add(out, p);
		}
		free(p);
	}
	closedir(d);
}

static void g_conf(void)
{
	section("conf: конфиги, которые больше ничему не принадлежат (→ резерв)");
	struct strv cand = {0}, why = {0};
	struct strv found = {0};
	find_new("/etc", &found, 0);
	for (size_t i = 0; i < found.n; i++) {
		strv_add(&cand, found.v[i]);
		strv_add(&why, "новая версия конфига от xbps, не применена (действует старая)");
	}
	char *ledger = read_file(CONF_LEDGER, NULL);
	if (ledger)
		FOR_LINES(l, ledger, s1)
			if (*l == '/' && !strv_has(&cand, l)) {
				strv_add(&cand, l);
				strv_add(&why, "конфиг удалённого пакета");
			}
	for (size_t i = 0; i < orphan_conf.n; i++)
		if (!strv_has(&cand, orphan_conf.v[i])) {
			strv_add(&cand, orphan_conf.v[i]);
			strv_add(&why, "конфиг удалённой зависимости");
		}
	struct strv go = {0};
	long long sz = 0;
	for (size_t i = 0; i < cand.n; i++) {
		const char *p = cand.v[i];
		struct stat st;
		if (lstat(p, &st) != 0 || !(S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)))
			continue;
		if (protected_path(p) || owned(p))
			continue;
		printf("   %s  — %s\n", p, why.v[i]);
		strv_add(&go, p);
		sz += (long long)st.st_blocks * 512;
	}
	if (!go.n) {
		puts("   нет");
		if (apply && ledger)
			unlink(CONF_LEDGER);
		goto out;
	}
	printf("   файлов: %zu, %s (вернуть: doas vh-deep-clean restore)\n", go.n, hsize(sz));
	if (!confirm("Убрать в резерв?")) {
		if (!apply)
			total += sz;
		goto out;
	}
	for (size_t i = 0; i < go.n; i++)
		if (!bk_move(go.v[i]))
			sz = 0;
	total += sz;
	unlink(CONF_LEDGER);
out:
	free(ledger);
	strv_free(&go);
	strv_free(&found);
	strv_free(&why);
	strv_free(&cand);
}

static void g_services(void)
{
	section("services: битые ссылки сервисов (→ резерв)");
	struct strv go = {0};
	DIR *d = opendir("/etc/runit/runsvdir");
	struct dirent *e;
	while (d && (e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		char *lvl = xasprintf("/etc/runit/runsvdir/%s", e->d_name);
		struct stat st;
		if (lstat(lvl, &st) == 0 && S_ISDIR(st.st_mode)) {
			DIR *s = opendir(lvl);
			struct dirent *f;
			while (s && (f = readdir(s))) {
				char *p = xasprintf("%s/%s", lvl, f->d_name);
				struct stat ls, ts;
				if (lstat(p, &ls) == 0 && S_ISLNK(ls.st_mode) && stat(p, &ts) != 0 && errno == ENOENT &&
				    !protected_path(p)) {
					char t[4096];
					ssize_t n = readlink(p, t, sizeof(t) - 1);
					t[n > 0 ? n : 0] = 0;
					printf("   %s → %s (нет)\n", p, t);
					strv_take(&go, p);
				} else {
					free(p);
				}
			}
			if (s)
				closedir(s);
		}
		free(lvl);
	}
	if (d)
		closedir(d);
	if (!go.n) {
		puts("   нет");
	} else if (confirm("Убрать ссылки в резерв?")) {
		for (size_t i = 0; i < go.n; i++)
			bk_move(go.v[i]);
	}
	strv_free(&go);
}

static void g_kernels(void)
{
	section("kernels: старые ядра");
	struct utsname u;
	uname(&u);
	if (!owned("/boot/vmlinu[xz]-*")) {
		puts("   установленное ядро не найдено в базе xbps — группа пропущена");
		return;
	}
	struct strv vk = {0}, stale = {0};
	struct buf o = {0};
	run((char *const[]){"vkpurge", "list", NULL}, NULL, 0, &o, NULL);
	if (o.p)
		FOR_LINES(l, o.p, s1)
			if (strcmp(l, u.release) != 0 && !strchr(l, '/'))
				strv_add(&vk, l);
	buf_free(&o);
	long long sz = 0;
	for (size_t i = 0; i < vk.n; i++) {
		char *m = xasprintf("/usr/lib/modules/%s", vk.v[i]);
		long long s = path_entry(m, false);
		static const char *const bf[] = {"/boot/vmlinuz-", "/boot/vmlinux-", "/boot/config-", "/boot/System.map-"};
		for (size_t j = 0; j < 4; j++) {
			char *b = xasprintf("%s%s", bf[j], vk.v[i]);
			s += path_entry(b, false);
			free(b);
		}
		printf("   ядро %s — %s (UKI и запись Limine уберёт хук ядра)\n", vk.v[i], hsize(s));
		sz += s;
		free(m);
	}
	/* каталоги модулей без ядра: остаются после удаления пакета (modules.dep и др.) */
	DIR *d = opendir("/usr/lib/modules");
	struct dirent *e;
	while (d && (e = readdir(d))) {
		const char *v = e->d_name;
		if (v[0] == '.' || !strcmp(v, u.release) || strv_has(&vk, v))
			continue;
		char *a = xasprintf("/boot/vmlinuz-%s", v), *b = xasprintf("/boot/vmlinux-%s", v);
		char *pat = xasprintf("/usr/lib/modules/%s/*", v), *m = xasprintf("/usr/lib/modules/%s", v);
		if (!path_exists(a) && !path_exists(b) && is_dir(m) && !owned(pat)) {
			long long s = path_entry(m, false);
			printf("   %s — каталог модулей без ядра, %s\n", m, hsize(s));
			strv_add(&stale, m);
			sz += s;
		}
		free(m);
		free(pat);
		free(b);
		free(a);
	}
	if (d)
		closedir(d);
	if (!vk.n && !stale.n) {
		puts("   нет (работающее ядро и ядра пакетов не удаляются никогда)");
		goto out;
	}
	printf("   всего %s; работающее ядро %s остаётся\n", hsize(sz), u.release);
	if (!confirm("Удалить старые ядра?")) {
		if (!apply)
			total += sz;
		goto out;
	}
	if (vk.n) {
		bool offline = !strcmp(kv_get(&boot, "KEYS_OFFLINE", "no"), "yes");
		bool keys = false;
		if (offline) {
			if (yes) {
				puts("   ключи Secure Boot на отдельном носителе: без вопросов ядра не удаляются "
				     "(запустите без -y)");
				goto stale;
			}
			printf("Вставьте носитель с ключами Secure Boot и нажмите Enter… ");
			fflush(stdout);
			char line[64];
			if (!fgets(line, sizeof(line), stdin) ||
			    RUN("/usr/local/sbin/vh-keys", "mount") != 0) {
				puts("   носитель не подключён — ядра не удалены");
				goto stale;
			}
			keys = true;
		}
		struct strv a = {0};
		strv_add(&a, "vkpurge");
		strv_add(&a, "rm");
		for (size_t i = 0; i < vk.n; i++)
			strv_add(&a, vk.v[i]);
		if (run(a.v, NULL, 0, NULL, NULL) != 0)
			warnmsg("vkpurge завершился с ошибкой");
		strv_free(&a);
		if (keys)
			RUN("/usr/local/sbin/vh-keys", "umount");
	}
stale:
	for (size_t i = 0; i < stale.n; i++)
		path_entry(stale.v[i], true);
	total += sz;
out:
	strv_free(&stale);
	strv_free(&vk);
}

static void g_cache(void)
{
	section("cache: скачанные пакеты (" CACHE_DIR ")");
	int dfd = open(CACHE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dfd < 0) {
		puts("   нет");
		return;
	}
	struct strv go = {0};
	long long sz = 0;
	int d2 = dup(dfd);
	DIR *d = d2 >= 0 ? fdopendir(d2) : NULL;
	struct dirent *e;
	while (d && (e = readdir(d))) {
		struct stat st;
		if (fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode)) {
			strv_add(&go, e->d_name);
			sz += (long long)st.st_blocks * 512;
		}
	}
	if (d)
		closedir(d);
	if (!go.n) {
		puts("   пусто");
	} else {
		printf("   файлов: %zu, %s (xbps скачает заново, если понадобится)\n", go.n, hsize(sz));
		if (confirm("Очистить кэш?")) {
			for (size_t i = 0; i < go.n; i++)
				entry(dfd, go.v[i], true);
			total += sz;
		} else if (!apply) {
			total += sz;
		}
	}
	strv_free(&go);
	close(dfd);
}

/* что удалить у одного пользователя: каталог rel в home и его записи names */
struct utarget {
	char *rel;
	struct strv names;
	long long size;
};

/* удалить от имени владельца: ошибка в путях пользователя не станет ошибкой root */
static void clear_as(uid_t uid, gid_t gid, const char *home, struct utarget *t, size_t nt)
{
	pid_t pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		if (uid != 0 && (setgroups(0, NULL) != 0 || setresgid(gid, gid, gid) != 0 ||
				 setresuid(uid, uid, uid) != 0 || getuid() != uid))
			_exit(1);
		for (size_t i = 0; i < nt; i++) {
			int fd = open_under(home, t[i].rel);
			if (fd < 0)
				continue;
			for (size_t j = 0; j < t[i].names.n; j++)
				entry(fd, t[i].names.v[j], true);
			close(fd);
		}
		_exit(0);
	}
	int st;
	while (waitpid(pid, &st, 0) < 0)
		if (errno != EINTR)
			die("waitpid: %s", strerror(errno));
}

/* записи каталога rel (кроме занятых программами) — в цель */
static void collect(const char *home, const char *rel, const struct strv *used, struct utarget *t,
		    const char *label)
{
	t->rel = xstrdup(rel);
	t->names = (struct strv){0};
	t->size = 0;
	int fd = open_under(home, rel);
	if (fd < 0)
		return;
	int d2 = dup(fd);
	DIR *d = d2 >= 0 ? fdopendir(d2) : NULL;
	struct dirent *e;
	struct strv busy = {0};
	while (d && (e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		char *full = xasprintf("%s/%s/%s", home, rel, e->d_name);
		if (used && in_use(used, full)) {
			strv_add(&busy, e->d_name);
		} else {
			strv_add(&t->names, e->d_name);
			t->size += entry(fd, e->d_name, false);
		}
		free(full);
	}
	if (d)
		closedir(d);
	close(fd);
	if (t->names.n || busy.n) {
		printf("   %s/%s — %s%s", home, rel, hsize(t->size), label);
		if (busy.n) {
			char *b = strv_join(&busy, ", ");
			printf(" (занято программами, остаётся: %s)", b);
			free(b);
		}
		putchar('\n');
	}
	strv_free(&busy);
}

static void g_user(void)
{
	section("user: мусор пользователей");
	struct strv used = {0};
	open_paths(&used);
	const char *browser = kv_get(&env, "VH_BROWSER_USER", "");
	char *pw = read_file("/etc/passwd", NULL);
	if (!pw)
		die("/etc/passwd: %s", strerror(errno));
	struct {
		uid_t uid;
		gid_t gid;
		char *home;
		struct utarget t[6];
		size_t nt;
	} us[64];
	size_t nu = 0;
	long long sz = 0;
	FOR_LINES(l, pw, s1) {
		char *f[7] = {0};
		char *p = l;
		for (int i = 0; i < 7 && p; i++) {
			f[i] = p;
			p = strchr(p, ':');
			if (p)
				*p++ = 0;
		}
		if (!f[5] || nu >= 64)
			continue;
		unsigned long uid = strtoul(f[2], NULL, 10), gid = strtoul(f[3], NULL, 10);
		bool human = uid >= 1000 && uid < 60000 && startswith(f[5], "/home/");
		bool is_browser = *browser && !strcmp(f[0], browser);
		if (!human && uid != 0 && !is_browser)
			continue;
		if (!is_dir(f[5]))
			continue;
		us[nu].uid = (uid_t)uid;
		us[nu].gid = (gid_t)gid;
		us[nu].home = xstrdup(f[5]);
		us[nu].nt = 0;
		if (is_browser) {
			if (uid_has_procs((uid_t)uid)) {
				printf("   %s: Firefox запущен — кэш браузера пропущен\n", f[0]);
				free(us[nu].home);
				continue;
			}
			static const char *const fx[] = {"trusted/.cache", "trusted/profile/cache2",
							 "trusted/profile/startupCache", "trusted/profile/thumbnails",
							 "trusted/profile/shader-cache"};
			for (size_t i = 0; i < 5; i++)
				collect(us[nu].home, fx[i], NULL, &us[nu].t[us[nu].nt++], " (кэш Firefox)");
		} else {
			collect(us[nu].home, ".cache", &used, &us[nu].t[us[nu].nt++], "");
			collect(us[nu].home, ".local/share/Trash", NULL, &us[nu].t[us[nu].nt++], " (корзина)");
		}
		for (size_t i = 0; i < us[nu].nt; i++)
			sz += us[nu].t[i].size;
		nu++;
	}
	free(pw);
	strv_free(&used);
	if (!sz) {
		puts("   нет");
	} else {
		printf("   всего %s; программы создадут кэш заново\n", hsize(sz));
		if (confirm("Очистить?")) {
			for (size_t i = 0; i < nu; i++)
				clear_as(us[i].uid, us[i].gid, us[i].home, us[i].t, us[i].nt);
			total += sz;
		} else if (!apply) {
			total += sz;
		}
	}
	for (size_t i = 0; i < nu; i++) {
		for (size_t j = 0; j < us[i].nt; j++) {
			free(us[i].t[j].rel);
			strv_free(&us[i].t[j].names);
		}
		free(us[i].home);
	}
}

/* ---------- проверка системы ---------- */

static bool audit(struct strv *fails)
{
	if (!is_regular(AUDIT))
		return false;
	struct buf o = {0};
	run((char *const[]){AUDIT, NULL}, NULL, 0, &o, &o);
	if (o.p)
		FOR_LINES(l, o.p, s1)
			if (startswith(l, "[FAIL]"))
				strv_add(fails, l);
	buf_free(&o);
	return true;
}

/* строки WARNING/ERROR проверки базы пакетов (xbps-pkgdb -a) */
static void pkgdb(struct strv *errs)
{
	struct buf o = {0};
	run((char *const[]){"xbps-pkgdb", "-a", NULL}, NULL, 0, &o, &o);
	if (o.p)
		FOR_LINES(l, o.p, s1)
			strv_add(errs, l);
	buf_free(&o);
}

/* строки из after, которых не было в before; true, если такие есть */
static bool report_new(const struct strv *before, const struct strv *after, const char *title)
{
	size_t fresh = 0;
	for (size_t i = 0; i < after->n; i++)
		if (!strv_has(before, after->v[i])) {
			if (!fresh++)
				printf("!! %s:\n", title);
			printf("   %s\n", after->v[i]);
		}
	return fresh > 0;
}

static _Noreturn void usage(void)
{
	fputs("doas vh-deep-clean                       план (ничего не меняет)\n"
	      "doas vh-deep-clean --apply [-y] [--user] [--only ГРУППА,…]\n"
	      "doas vh-deep-clean restore               вернуть файлы из резерва\n"
	      "группы: orphans conf services kernels cache user\n", stderr);
	exit(2);
}

int main(int argc, char **argv)
{
	vh_prog = "vh-deep-clean";
	setenv("PATH", "/usr/bin", 1);
	umask(022);
	int groups = G_ORPHANS | G_CONF | G_SERVICES | G_KERNELS | G_CACHE;
	bool user = false, restore = false;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!strcmp(a, "restore") && i == 1 && argc == 2) {
			restore = true;
		} else if (!strcmp(a, "--apply")) {
			apply = true;
		} else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) {
			yes = true;
		} else if (!strcmp(a, "--user")) {
			user = true;
		} else if (!strcmp(a, "--only") && i + 1 < argc) {
			groups = 0;
			char *list = xstrdup(argv[++i]);
			char *save = NULL;
			for (char *g = strtok_r(list, ",", &save); g; g = strtok_r(NULL, ",", &save)) {
				size_t k = 0;
				while (k < sizeof(group_names) / sizeof(group_names[0]) && strcmp(g, group_names[k].name))
					k++;
				if (k == sizeof(group_names) / sizeof(group_names[0]))
					usage();
				groups |= group_names[k].bit;
			}
			free(list);
		} else {
			usage();
		}
	}
	if (user)
		groups |= G_USER;
	if (yes && !apply)
		usage();
	if (geteuid() != 0)
		die("запустите: doas vh-deep-clean …");
	if (restore)
		return do_restore();
	static const char *const xbps[] = {"xbps-install", "xbps-remove", "xbps-reconfigure", "xbps-pkgdb",
					   "vkpurge", "vh-update", "vh-pkg"};
	if (proc_comm_running(xbps, sizeof(xbps) / sizeof(xbps[0])))
		die("сейчас работает xbps (установка или обновление) — запустите после него");
	kv_read(&env, "/etc/vh/vh.env", 0);
	kv_read(&boot, "/etc/vh/boot.conf", KV_INLINE);
	load_keep();

	struct strv before = {0}, db_before = {0};
	bool audited = false;
	if (apply) {
		puts("Проверка системы до очистки (vh-audit, xbps-pkgdb)…");
		audited = audit(&before);
		pkgdb(&db_before);
	} else {
		puts("План очистки — ничего не изменено. Выполнить: doas vh-deep-clean --apply");
	}
	if (groups & G_ORPHANS)
		g_orphans();
	if (groups & G_CONF)
		g_conf();
	if (groups & G_SERVICES)
		g_services();
	if (groups & G_KERNELS)
		g_kernels();
	if (groups & G_CACHE)
		g_cache();
	if (groups & G_USER)
		g_user();
	else if (!apply)
		puts("\n(мусор пользователей — ~/.cache, кэш Firefox, корзина — добавляет --user)");

	printf("\n%s: %s\n", apply ? "Освобождено" : "Можно освободить", hsize(total));
	if (!apply)
		return 0;
	int rc = 0;
	struct strv db_after = {0};
	pkgdb(&db_after);
	if (report_new(&db_before, &db_after, "Новые ошибки базы пакетов (xbps-pkgdb -a)"))
		rc = 1;
	if (bk_ready)
		printf("Резерв: %s (вернуть: doas vh-deep-clean restore)\n", BK_LAST);
	if (audited) {
		puts("Проверка системы после очистки (vh-audit)…");
		struct strv after = {0};
		audit(&after);
		if (report_new(&before, &after, "Новые FAIL после очистки")) {
			puts("   Вернуть файлы из резерва: doas vh-deep-clean restore");
			rc = 1;
		} else {
			printf("vh-audit: новых FAIL нет (было и осталось: %zu)\n", after.n);
		}
		strv_free(&after);
	}
	if (!rc)
		puts("Система в порядке.");
	strv_free(&db_after);
	strv_free(&db_before);
	strv_free(&before);
	return rc;
}
