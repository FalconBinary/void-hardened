/* vh-limine-update — пересборка цепочки загрузки на ESP (docs/03-boot.md).
 *
 * 1. Оставляет на ESP KEEP последних UKI (+ UKI работающего ядра), остальные удаляет.
 * 2. Подписывает UKI ключом db (sbctl).
 * 3. Пишет limine.conf: по записи на UKI, путь с хэшем BLAKE2B (Limine сверяет файл).
 * 4. Берёт чистый BOOTX64.EFI из пакета limine, вписывает в него BLAKE2B конфига
 *    (limine enroll-config), подписывает и атомарно заменяет копию на ESP.
 *
 * С Secure Boot и вписанным хэшем Limine проверяет конфиг при каждой загрузке,
 * отключает редактор и требует хэши у всех путей.
 *
 *   vh-limine-update [--new ВЕРСИЯ] [--dry-run]
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "hash.h"
#include "vh.h"

#define ESP "/boot/efi"
#define UKI_DIR ESP "/EFI/void"
#define LIMINE_DIR ESP "/EFI/BOOT"
#define LIMINE_SRC "/usr/share/limine/BOOTX64.EFI"
#define BOOT_CONF "/etc/vh/boot.conf"
#define DB_KEY "/var/lib/sbctl/keys/db/db.key"

struct uki {
	char *name;
	char *ver;         /* «6.18.56_1» — как в имени файла */
	long v[4];
};

/* linux-A.B.C_D.efi → номера версии; false — не UKI */
static bool parse_uki(const char *name, struct uki *u)
{
	if (!startswith(name, "linux-") || !endswith(name, ".efi"))
		return false;
	const char *p = name + 6, *end = name + strlen(name) - 4;
	const char seps[4] = {'.', '.', '_', 0};
	for (int i = 0; i < 4; i++) {
		const char *q = p;
		while (q < end && *q >= '0' && *q <= '9')
			q++;
		if (q == p || q - p > 9)
			return false;
		u->v[i] = strtol(p, NULL, 10);
		if (i < 3 && (q >= end || *q != seps[i]))
			return false;
		if (i == 3 && q != end)
			return false;
		p = q + 1;
	}
	u->name = xstrdup(name);
	u->ver = xstrndup(name + 6, (size_t)(end - name - 6));
	return true;
}

static int cmp_uki_desc(const void *a, const void *b)
{
	const struct uki *x = a, *y = b;
	for (int i = 0; i < 4; i++)
		if (x->v[i] != y->v[i])
			return x->v[i] < y->v[i] ? 1 : -1;
	return -strcmp(x->name, y->name);
}

static bool secure_boot_enabled(void)
{
	glob_t g;
	bool on = false;
	if (glob("/sys/firmware/efi/efivars/SecureBoot-*", 0, NULL, &g) == 0) {
		size_t n;
		char *d = read_file(g.gl_pathv[0], &n);
		on = d && n > 4 && d[4] == 1;
		free(d);
		globfree(&g);
	}
	return on;
}

static bool is_mount(const char *path)
{
	struct stat a, b;
	char *parent = xasprintf("%s/..", path);
	bool r = lstat(path, &a) == 0 && !S_ISLNK(a.st_mode) && lstat(parent, &b) == 0 &&
		 (a.st_dev != b.st_dev || a.st_ino == b.st_ino);
	free(parent);
	return r;
}

static void sign(const char *path, bool dry, bool offline)
{
	if (!path_exists(DB_KEY)) {
		if (offline)
			die("носитель с ключом не подключён (" DB_KEY ") — подпись невозможна.\n"
			    "  Подключите его и повторите: doas vh-keys mount && doas xbps-reconfigure -f "
			    "<пакет ядра>; затем doas vh-keys umount (docs/13, sb-offline-keys)");
		if (secure_boot_enabled())
			die("Secure Boot включён, а ключа " DB_KEY " нет: неподписанную UKI прошивка не "
			    "загрузит. limine.conf не изменён — загрузится прежнее ядро");
		printf("  ключей Secure Boot ещё нет (" DB_KEY ") — %s не подписан\n", path);
		return;
	}
	if (dry) {
		printf("  + sbctl sign %s\n", path);
		return;
	}
	struct buf out = {0}, err = {0};
	if (run((char *const[]){"sbctl", "sign", (char *)path, NULL}, NULL, 0, &out, &err) != 0)
		die("sbctl sign %s: %s%s", path, out.p, err.p);
	buf_free(&out);
	buf_free(&err);
}

static void copy_file(const char *src, const char *dst)
{
	size_t n;
	char *d = read_file(src, &n);
	if (!d)
		die("%s: %s", src, strerror(errno));
	int fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
	if (fd < 0)
		die("%s: %s", dst, strerror(errno));
	for (size_t off = 0; off < n;) {
		ssize_t w = write(fd, d + off, n - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			die("%s: %s", dst, strerror(errno));
		}
		off += (size_t)w;
	}
	if (close(fd) != 0)
		die("%s: %s", dst, strerror(errno));
	free(d);
}

static void replace_atomic(const char *src, const char *dst)
{
	size_t n;
	char *d = read_file(src, &n);
	if (!d)
		die("%s: %s", src, strerror(errno));
	write_atomic(dst, d, n, 0644);
	free(d);
}

static _Noreturn void usage(void)
{
	fputs("vh-limine-update [--new ВЕРСИЯ] [--dry-run]\n", stderr);
	exit(2);
}

int main(int argc, char **argv)
{
	vh_prog = "vh-limine-update";
	setenv("PATH", "/usr/bin", 1);
	const char *newver = NULL;
	bool dry = false;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dry-run") == 0)
			dry = true;
		else if (strcmp(argv[i], "--new") == 0 && i + 1 < argc)
			newver = argv[++i];
		else if (startswith(argv[i], "--new="))
			newver = argv[i] + 6;
		else
			usage();
	}

	if (!is_mount(ESP))
		die(ESP " не смонтирован — подпись отменена (UKI не должна лечь на корень)");
	struct kvs conf = {0};
	kv_set(&conf, "KEEP", "2");
	kv_set(&conf, "TIMEOUT", "1");
	kv_set(&conf, "KEYS_OFFLINE", "no");
	kv_read(&conf, BOOT_CONF, 0);
	long keep_n = kv_int(&conf, "KEEP", "2"), timeout = kv_int(&conf, "TIMEOUT", "1");
	if (keep_n < 1 || keep_n > 5 || timeout < 0 || timeout > 30)
		die("неверные KEEP/TIMEOUT в " BOOT_CONF);
	bool offline = strcmp(kv_get(&conf, "KEYS_OFFLINE", "no"), "yes") == 0;

	struct uki *ukis = NULL;
	size_t n = 0;
	DIR *d = opendir(UKI_DIR);
	for (struct dirent *e; d && (e = readdir(d));) {
		struct uki u;
		if (parse_uki(e->d_name, &u)) {
			ukis = xrealloc(ukis, (n + 1) * sizeof(*ukis));
			ukis[n++] = u;
		} else if (endswith(e->d_name, ".efi")) {
			printf("  внимание: незнакомый файл " UKI_DIR "/%s — не трогаю\n", e->d_name);
		}
	}
	if (d)
		closedir(d);
	if (!n)
		die("в " UKI_DIR " нет UKI");
	qsort(ukis, n, sizeof(*ukis), cmp_uki_desc);
	if (newver) {
		bool found = false;
		for (size_t i = 0; i < n; i++)
			found |= strcmp(ukis[i].ver, newver) == 0;
		if (!found)
			die("UKI для %s не создана — смотрите вывод dracut выше", newver);
	}

	/* keep[]: индексы в ukis */
	size_t keep[6], nk = 0;
	for (size_t i = 0; i < n && nk < (size_t)keep_n; i++)
		keep[nk++] = i;
	struct utsname un;
	uname(&un);
	for (size_t i = 0; i < n; i++)
		if (strcmp(ukis[i].ver, un.release) == 0) {
			bool kept = false;
			for (size_t j = 0; j < nk; j++)
				kept |= keep[j] == i;
			if (!kept)
				keep[nk++] = i;  /* ядро, на котором работаем, не удаляем никогда */
		}

	/* Сначала проверка и подпись, потом удаление: сбой подписи оставляет ESP как был
	 * (прежний limine.conf ссылается на прежние, подписанные UKI). */
	if (offline && newver && !dry) {
		char *path = xasprintf(UKI_DIR "/linux-%s.efi", newver);
		if (run((char *const[]){"/usr/local/sbin/vh-uki-verify", path, (char *)newver, NULL},
			NULL, 0, NULL, NULL) != 0)
			die("проверка входных данных UKI не пройдена — подпись отменена (docs/13)");
		free(path);
	}
	for (size_t j = 0; j < nk; j++) {
		char *path = xasprintf(UKI_DIR "/%s", ukis[keep[j]].name);
		sign(path, dry, offline);
		free(path);
	}
	for (size_t i = 0; i < n; i++) {
		bool kept = false;
		for (size_t j = 0; j < nk; j++)
			kept |= keep[j] == i;
		if (kept)
			continue;
		printf("  удаляю устаревшую UKI %s\n", ukis[i].name);
		char *path = xasprintf(UKI_DIR "/%s", ukis[i].name);
		if (!dry && unlink(path) != 0)
			die("%s: %s", path, strerror(errno));
		free(path);
	}

	struct buf c = {0};
	buf_addf(&c, "# Сгенерировано vh-limine-update — не редактировать вручную:\n"
		     "# хэш этого файла вписан в BOOTX64.EFI, любая правка = отказ загрузки.\n"
		     "timeout: %ld\neditor_enabled: no\nhash_mismatch_panic: yes\nverbose: no\n", timeout);
	for (size_t j = 0; j < nk; j++) {
		const struct uki *u = &ukis[keep[j]];
		char *path = xasprintf(UKI_DIR "/%s", u->name);
		char h[129];
		if (blake2b_file(path, h) != 0)
			die("%s: %s", path, strerror(errno));
		buf_addf(&c, "\n/Void Linux %s%s\n    protocol: efi\n    path: boot():/EFI/void/%s#%s\n",
			 u->ver, j > 0 ? " (предыдущее ядро)" : "", u->name, h);
		free(path);
	}
	char conf_hash[129];
	blake2b_hex(c.p, c.len, conf_hash);

	if (newver && !dry && path_exists("/etc/vh/totp.conf")) {
		/* optional/tpm2-totp: новая UKI меняет PCR 4 — при следующей загрузке initramfs
		 * предложит перезапечатать секрет (флаг: только факт наличия файла) */
		mkdirs("/var/lib/vh", 0700);
		int fd = open("/var/lib/vh/totp-reseal", O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (fd >= 0)
			close(fd);
		puts("  tpm2-totp: при следующей загрузке код один раз не совпадёт — перезапечатайте (RESEAL)");
	}

	if (dry) {
		printf("%s\n", c.p);
		printf("  + limine enroll-config BOOTX64.EFI %s\n", conf_hash);
		return 0;
	}

	mkdirs(LIMINE_DIR, 0755);
	char td[] = "/tmp/vh-limine.XXXXXX";
	if (!mkdtemp(td))
		die("mkdtemp: %s", strerror(errno));
	char *cfg_tmp = xasprintf("%s/limine.conf", td), *efi_tmp = xasprintf("%s/BOOTX64.EFI", td);
	int fd = open(cfg_tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0 || write(fd, c.p, c.len) != (ssize_t)c.len || close(fd) != 0)
		die("%s: %s", cfg_tmp, strerror(errno));
	copy_file(LIMINE_SRC, efi_tmp);   /* чистая копия: подпись и старый хэш не наследуются */
	struct buf out = {0}, err = {0};
	if (run((char *const[]){"limine", "enroll-config", efi_tmp, conf_hash, NULL}, NULL, 0, &out, &err) != 0) {
		unlink(cfg_tmp);
		unlink(efi_tmp);
		rmdir(td);
		die("limine enroll-config: %s%s", out.p, err.p);
	}
	sign(efi_tmp, false, offline);
	/* Порядок важен: сначала конфиг, потом загрузчик. Сбой между ними даёт
	 * «хэш не совпал» (отказ загрузки, но не обход проверки); повторный запуск чинит. */
	replace_atomic(cfg_tmp, LIMINE_DIR "/limine.conf");
	replace_atomic(efi_tmp, LIMINE_DIR "/BOOTX64.EFI");
	unlink(cfg_tmp);
	unlink(efi_tmp);
	rmdir(td);
	sync();
	printf("  limine.conf: %zu записей, хэш конфига %.16s… вписан в Limine\n", nk, conf_hash);
	return 0;
}
