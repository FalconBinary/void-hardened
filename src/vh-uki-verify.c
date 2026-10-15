/* vh-uki-verify — проверка входных данных UKI перед подписью (optional/sb-offline-keys).
 *
 * Ключ db на офлайн-носителе не спасает, если root-руткит подменил то, из чего собирается
 * UKI (модули и конфиги dracut, cmdline, хуки kernel.d): при обновлении вы сами подпишете
 * его образ. Поэтому до подписи:
 *
 *   1. xbps-pkgdb — файлы пакетов, из которых собирается UKI, совпадают с базой xbps;
 *   2. хэши файлов НЕ из пакетов, влияющих на сборку, — с эталоном на носителе ключа
 *      (включая скрытые файлы; симлинк — по его цели);
 *   3. секция .cmdline новой UKI — побайтно с эталоном на носителе, .uname — с версией;
 *   4. содержимое initramfs (секция .initrd) — с прошлой одобренной UKI: новые, удалённые
 *      и изменённые файлы показываются, админ подтверждает их вручную.
 *
 * Эталоны лежат на носителе с ключом (REF), а не на корневой ФС: руткит работающей
 * системы не перепишет их без носителя. Остаточный риск: руткит, перехвативший саму
 * проверку или sbctl, её обойдёт — полностью закрывает только подпись из live-флешки.
 *
 *   vh-uki-verify UKI ВЕРСИЯ     — проверить (вызывает vh-limine-update перед подписью)
 *   vh-uki-verify --init [UKI]   — записать эталоны с текущей системы (после чистой установки)
 */
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hash.h"
#include "vh.h"

#define REF "/run/vh-keys/ref"

static const char *const pkgs[] = {
	"dracut", "dracut-uefi", "systemd-boot-efistub", "cryptsetup", "intel-ucode",
	"linux-firmware-intel", "tpm2-tools", "tpm2-totp", "limine", "sbctl", "eudev", "kmod",
};
static const char *const inputs[] = {
	"/etc/dracut.conf", "/etc/dracut.conf.d", "/etc/default/dracut-uefi-hook",
	"/etc/kernel.d", "/etc/vh/boot.conf", "/etc/vh/vh.env", "/usr/local/sbin/vh-limine-update",
	"/usr/local/sbin/vh-uki-verify", "/usr/local/lib/dracut", "/etc/modprobe.d",
};

static const char usage_text[] =
	"vh-uki-verify UKI ВЕРСИЯ     — проверить (вызывает vh-limine-update перед подписью)\n"
	"vh-uki-verify --init [UKI]   — записать эталоны с текущей системы (после чистой установки)\n";

/* список «имя → значение» (хэш или описание) */
struct ent {
	char *name, *val;
	size_t seq;
};
struct list {
	struct ent *e;
	size_t n, cap;
};

static void list_add(struct list *l, char *name, char *val)
{
	if (l->n == l->cap) {
		l->cap = l->cap ? l->cap * 2 : 256;
		l->e = xrealloc(l->e, l->cap * sizeof(*l->e));
	}
	/* имя попадает в файл эталона построчно: управляющие символы — «?» */
	for (char *p = name; *p; p++)
		if ((unsigned char)*p < 0x20 || *p == 0x7F)
			*p = '?';
	l->e[l->n] = (struct ent){name, val, l->n};
	l->n++;
}

static int cmp_ent(const void *a, const void *b)
{
	const struct ent *x = a, *y = b;
	int c = strcmp(x->name, y->name);
	return c ? c : (x->seq < y->seq ? -1 : 1);
}

/* сортировка по имени; из повторов остаётся последний (как в словаре) */
static void list_finish(struct list *l)
{
	if (l->n > 1)
		qsort(l->e, l->n, sizeof(*l->e), cmp_ent);
	size_t w = 0;
	for (size_t i = 0; i < l->n; i++) {
		if (i + 1 < l->n && strcmp(l->e[i].name, l->e[i + 1].name) == 0)
			continue;
		l->e[w++] = l->e[i];
	}
	l->n = w;
}

static const char *list_get(const struct list *l, const char *name)
{
	size_t lo = 0, hi = l->n;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		int c = strcmp(l->e[mid].name, name);
		if (c == 0)
			return l->e[mid].val;
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

static void read_list(const char *path, struct list *l)
{
	char *text = read_file(path, NULL);
	if (text) {
		char *save = NULL;
		for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
			char *sep = strstr(line, "  ");
			if (!sep)
				list_add(l, xstrdup(""), xstrdup(line));
			else
				list_add(l, xstrdup(sep + 2), xstrndup(line, (size_t)(sep - line)));
		}
		free(text);
	}
	list_finish(l);
}

static void write_list(const char *path, const struct list *l)
{
	struct buf b = {0};
	buf_adds(&b, "");
	for (size_t i = 0; i < l->n; i++)
		buf_addf(&b, "%s  %s\n", l->e[i].val, l->e[i].name);
	write_atomic(path, b.p, b.len, 0600);
	buf_free(&b);
}

/* ---------------------------------------------------------------- входные файлы сборки */
static struct list *walk_out;

static void add_file(const char *f, const struct stat *st)
{
	if (endswith(f, ".vh-orig") || endswith(f, ".new"))
		return;
	if (S_ISLNK(st->st_mode)) {
		char t[PATH_MAX];
		ssize_t n = readlink(f, t, sizeof(t) - 1);
		t[n < 0 ? 0 : n] = 0;
		list_add(walk_out, xstrdup(f), xasprintf("-> %s", t));
	} else if (S_ISREG(st->st_mode)) {
		char h[65];
		if (sha256_file(f, h) != 0)
			die("%s: %s", f, strerror(errno));
		list_add(walk_out, xstrdup(f), xstrdup(h));
	}
}

static int walk_cb(const char *f, const struct stat *st, int type, struct FTW *ftw)
{
	(void)ftw;
	if (type == FTW_F || type == FTW_SL)
		add_file(f, st);
	return 0;
}

static void input_hashes(struct list *l)
{
	walk_out = l;
	for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
		struct stat st;
		if (lstat(inputs[i], &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode))
			nftw(inputs[i], walk_cb, 16, FTW_PHYS);
		else
			add_file(inputs[i], &st);
	}
	list_finish(l);
}

/* ---------------------------------------------------------------- PE и initramfs */
struct section {
	char name[9];
	const unsigned char *p;
	size_t n;
};

static uint32_t le32(const unsigned char *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint16_t le16(const unsigned char *p) { return (uint16_t)(p[0] | p[1] << 8); }

/* секции PE-файла без binutils; data остаётся в памяти до выхода */
static size_t pe_sections(const char *path, struct section *out, size_t max)
{
	size_t len;
	unsigned char *d = (unsigned char *)read_file(path, &len);
	if (!d)
		die("%s: %s", path, strerror(errno));
	if (len < 0x40 || d[0] != 'M' || d[1] != 'Z')
		die("%s: не PE-файл", path);
	size_t pe = le32(d + 0x3C);
	if (pe > len || len - pe < 24 || memcmp(d + pe, "PE\0\0", 4) != 0)
		die("%s: нет сигнатуры PE", path);
	size_t nsec = le16(d + pe + 6), opt = le16(d + pe + 20);
	size_t off = pe + 24 + opt, n = 0;
	for (size_t i = 0; i < nsec && n < max; i++) {
		if (off + i * 40 + 40 > len)
			die("%s: заголовки секций за концом файла", path);
		const unsigned char *h = d + off + i * 40;
		uint32_t vsize = le32(h + 8), rsize = le32(h + 16), rptr = le32(h + 20);
		size_t sz = vsize ? (vsize < rsize ? vsize : rsize) : rsize;
		if (rptr > len)
			rptr = (uint32_t)len;
		if (sz > len - rptr)
			sz = len - rptr;
		memcpy(out[n].name, h, 8);
		out[n].name[8] = 0;
		out[n].p = d + rptr;
		out[n].n = sz;
		n++;
	}
	return n;
}

static const struct section *section(const struct section *s, size_t n, const char *name)
{
	for (size_t i = 0; i < n; i++)
		if (strcmp(s[i].name, name) == 0)
			return &s[i];
	return NULL;
}

static size_t rstrip0(const unsigned char *p, size_t n)
{
	while (n && p[n - 1] == 0)
		n--;
	return n;
}

static bool hex8(const unsigned char *p, uint32_t *v)
{
	*v = 0;
	for (int i = 0; i < 8; i++) {
		int c = p[i], x = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
				  c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
		if (x < 0)
			return false;
		*v = *v << 4 | (uint32_t)x;
	}
	return true;
}

static bool is_cpio(const unsigned char *p, size_t left)
{
	return left >= 6 && (memcmp(p, "070701", 6) == 0 || memcmp(p, "070702", 6) == 0);
}

/* архив newc: регулярный файл → sha256, симлинк → «-> цель», прочее → «mode …» */
static size_t parse_cpio(const unsigned char *b, size_t len, size_t off, struct list *l, const char *prefix)
{
	while (off <= len && len - off >= 110 && is_cpio(b + off, len - off)) {
		uint32_t f[13];
		for (int i = 0; i < 13; i++)
			if (!hex8(b + off + 6 + 8 * i, &f[i]))
				die("initramfs: плохой заголовок cpio на смещении %zu", off);
		uint32_t mode = f[1], fsize = f[6], nsize = f[11];
		size_t name_off = off + 110;
		if (nsize > len - name_off)
			die("initramfs: имя за концом архива");
		char *name = xstrndup((const char *)b + name_off, nsize ? strnlen((const char *)b + name_off, nsize - 1) : 0);
		off = (name_off + nsize + 3) & ~(size_t)3;
		if (off > len)
			off = len;
		size_t bl = fsize < len - off ? fsize : len - off;
		const unsigned char *body = b + off;
		off = (off + fsize + 3) & ~(size_t)3;
		if (strcmp(name, "TRAILER!!!") == 0) {
			free(name);
			break;
		}
		char *val;
		if ((mode & 0170000) == 0100000) {
			char h[65];
			sha256_hex(body, bl, h);
			val = xstrdup(h);
		} else if ((mode & 0170000) == 0120000) {
			val = xasprintf("-> %.*s", (int)bl, (const char *)body);
		} else {
			val = xasprintf("mode %o", mode);
		}
		list_add(l, xasprintf("%s%s", prefix, name), val);
		free(name);
	}
	return off;
}

/* все файлы initramfs: ранний cpio (микрокод) + сжатый основной */
static void initrd_files(const unsigned char *blob, size_t len, struct list *l)
{
	size_t off = 0;
	while (off < len) {
		if (is_cpio(blob + off, len - off)) {
			off = parse_cpio(blob, len, off, l, "early:");
			while (off < len && blob[off] == 0)
				off++;
			continue;
		}
		static const unsigned char zstd[] = {0x28, 0xb5, 0x2f, 0xfd}, lz4l[] = {0x02, 0x21, 0x4c, 0x18},
					   lz4f[] = {0x04, 0x22, 0x4d, 0x18};
		char *tool;
		if (len - off >= 4 && memcmp(blob + off, zstd, 4) == 0)
			tool = "zstd";
		else if (len - off >= 4 && (memcmp(blob + off, lz4l, 4) == 0 || memcmp(blob + off, lz4f, 4) == 0))
			tool = "lz4";
		else
			die("неизвестный формат initramfs на смещении %zu", off);
		struct buf raw = {0};
		if (run((char *const[]){tool, "-dcq", NULL}, blob + off, len - off, &raw, NULL) != 0)
			die("%s -dcq: ошибка распаковки initramfs", tool);
		parse_cpio((const unsigned char *)raw.p, raw.len, 0, l, "");
		buf_free(&raw);
		break;
	}
	list_finish(l);
}

static bool confirm(const char *prompt)
{
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty)
		return false;
	fprintf(tty, "%s Введите «да»: ", prompt);
	fflush(tty);
	char line[64];
	bool ok = fgets(line, sizeof(line), tty) && strcmp(strip(line), "да") == 0;
	fclose(tty);
	return ok;
}

static void init(const char *uki)
{
	mkdirs(REF, 0700);
	struct list in = {0};
	input_hashes(&in);
	write_list(REF "/inputs.sha256", &in);
	if (uki) {
		struct section s[96];
		size_t n = pe_sections(uki, s, 96);
		const struct section *c = section(s, n, ".cmdline"), *i = section(s, n, ".initrd");
		if (!c || !i)
			die("%s: нет секций .cmdline и .initrd", uki);
		write_atomic(REF "/cmdline", c->p, rstrip0(c->p, c->n), 0600);
		struct list ir = {0};
		initrd_files(i->p, i->n, &ir);
		write_list(REF "/initrd.sha256", &ir);
	}
	printf("эталоны записаны в " REF "\n");
}

static void verify(const char *uki, const char *version)
{
	if (!is_dir(REF))
		die("нет эталонов " REF " — носитель с ключом не подключён (doas vh-keys mount)");
	int bad = 0;
	struct strv pk = {0};
	for (size_t i = 0; i < sizeof(pkgs) / sizeof(pkgs[0]); i++) {
		struct buf o = {0};
		if (run((char *const[]){"xbps-query", (char *)pkgs[i], NULL}, NULL, 0, &o, &o) == 0)
			strv_add(&pk, pkgs[i]);
		buf_free(&o);
	}
	struct kvs env = {0};
	kv_read(&env, "/etc/vh/vh.env", 0);
	const char *kernel = kv_get(&env, "VH_KERNEL", "");
	if (*kernel)
		strv_add(&pk, kernel);
	char *all = strv_join(&pk, " ");
	printf("1. xbps-pkgdb: %s\n", all);
	free(all);
	for (size_t i = 0; i < pk.n; i++) {
		struct buf o = {0}, e = {0};
		if (run((char *const[]){"xbps-pkgdb", pk.v[i], NULL}, NULL, 0, &o, &e) != 0) {
			printf("   ✗ %s: %s %s\n", pk.v[i], strip(o.p), strip(e.p));
			bad++;
		}
		buf_free(&o);
		buf_free(&e);
	}
	puts("2. файлы сборки не из пакетов — с эталоном на носителе");
	struct list ref = {0}, cur = {0};
	read_list(REF "/inputs.sha256", &ref);
	input_hashes(&cur);
	for (size_t i = 0, j = 0; i < ref.n || j < cur.n;) {
		int c = i >= ref.n ? 1 : j >= cur.n ? -1 : strcmp(ref.e[i].name, cur.e[j].name);
		if (c < 0) {
			printf("   ✗ удалён: %s\n", ref.e[i++].name);
			bad++;
		} else if (c > 0) {
			printf("   ✗ новый: %s\n", cur.e[j++].name);
			bad++;
		} else {
			if (strcmp(ref.e[i].val, cur.e[j].val) != 0) {
				printf("   ✗ изменён: %s\n", cur.e[j].name);
				bad++;
			}
			i++;
			j++;
		}
	}
	struct section s[96];
	size_t ns = pe_sections(uki, s, 96);
	puts("3. .cmdline и .uname новой UKI");
	size_t wl;
	char *want = read_file(REF "/cmdline", &wl);
	if (!want)
		die(REF "/cmdline: %s", strerror(errno));
	const struct section *c = section(s, ns, ".cmdline");
	size_t gl = c ? rstrip0(c->p, c->n) : 0;
	if (gl != wl || (gl && memcmp(c->p, want, gl) != 0)) {
		printf("   ✗ cmdline отличается от эталона:\n     было:  %s\n     стало: %.*s\n", want,
		       (int)gl, c ? (const char *)c->p : "");
		bad++;
	}
	const struct section *u = section(s, ns, ".uname");
	char *uname = u ? xstrndup((const char *)u->p, rstrip0(u->p, u->n)) : xstrdup("");
	char *ubase = xstrndup(uname, strcspn(uname, "_")), *vbase = xstrndup(version, strcspn(version, "_"));
	if (*version && !startswith(version, ubase) && !startswith(uname, vbase)) {
		printf("   ✗ .uname «%s» не соответствует версии пакета %s\n", uname, version);
		bad++;
	}
	if (bad)
		die("расхождений: %d. Если изменения ваши и осознанные — обновите эталоны: "
		    "doas vh-uki-verify --init (с подключённым носителем)", bad);
	puts("4. содержимое initramfs против прошлой одобренной UKI");
	const struct section *ir = section(s, ns, ".initrd");
	if (!ir)
		die("%s: нет секции .initrd", uki);
	struct list old = {0}, now = {0};
	read_list(REF "/initrd.sha256", &old);
	initrd_files(ir->p, ir->n, &now);
	struct strv added = {0}, removed = {0}, changed = {0};
	for (size_t i = 0; i < now.n; i++) {
		const char *o = list_get(&old, now.e[i].name);
		if (!o)
			strv_add(&added, now.e[i].name);
		else if (strcmp(o, now.e[i].val) != 0)
			strv_add(&changed, now.e[i].name);
	}
	for (size_t i = 0; i < old.n; i++)
		if (!list_get(&now, old.e[i].name))
			strv_add(&removed, old.e[i].name);
	size_t mods = 0, shown = 0;
	struct strv *ac[2] = {&added, &changed};
	for (int k = 0; k < 2; k++)
		for (size_t i = 0; i < ac[k]->n; i++)
			mods += strstr(ac[k]->v[i], "/lib/modules/") != NULL;
	printf("   добавлено %zu, удалено %zu, изменено %zu (из них модули ядра: %zu)\n",
	       added.n, removed.n, changed.n, mods);
	for (int k = 0; k < 2; k++)
		for (size_t i = 0; i < ac[k]->n && shown < 200; i++)
			if (!strstr(ac[k]->v[i], "/lib/modules/")) {
				printf("   ± %s\n", ac[k]->v[i]);
				shown++;
			}
	for (size_t i = 0; i < removed.n && i < 50; i++)
		printf("   − %s\n", removed.v[i]);
	fflush(stdout);
	if ((added.n || removed.n || changed.n) &&
	    !confirm("Изменения initramfs ожидаемы для этого обновления (новое ядро, микрокод, dracut)?"))
		die("изменения initramfs не подтверждены — подпись отменена");
	write_list(REF "/initrd.sha256", &now);
	puts("   эталон initramfs обновлён");
}

int main(int argc, char **argv)
{
	vh_prog = "vh-uki-verify";
	setenv("PATH", "/usr/bin", 1);
	if (geteuid() != 0)
		die("нужен root");
	if (argc >= 2 && strcmp(argv[1], "--init") == 0)
		init(argc > 2 ? argv[2] : NULL);
	else if (argc == 3)
		verify(argv[1], argv[2]);
	else {
		fputs(usage_text, stdout);
		return 2;
	}
	return 0;
}
