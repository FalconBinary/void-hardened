/* void-hardened: общие функции инструментов на C (vh.h). */
#include "vh.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

const char *vh_prog = "vh";

static void vmsg(FILE *f, const char *fmt, va_list ap)
{
	fprintf(f, "%s: ", vh_prog);
	vfprintf(f, fmt, ap);
	fputc('\n', f);
	fflush(f);
}

void die(const char *fmt, ...)
{
	va_list ap;
	fflush(stdout);
	va_start(ap, fmt);
	vmsg(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

void warnmsg(const char *fmt, ...)
{
	va_list ap;
	fflush(stdout);
	va_start(ap, fmt);
	vmsg(stderr, fmt, ap);
	va_end(ap);
}

void logmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vmsg(stdout, fmt, ap);
	va_end(ap);
}

void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("нет памяти");
	return p;
}

void *xcalloc(size_t n, size_t sz)
{
	void *p = calloc(n ? n : 1, sz ? sz : 1);
	if (!p)
		die("нет памяти");
	return p;
}

void *xrealloc(void *p, size_t n)
{
	p = realloc(p, n ? n : 1);
	if (!p)
		die("нет памяти");
	return p;
}

char *xstrdup(const char *s)
{
	return xstrndup(s, strlen(s));
}

char *xstrndup(const char *s, size_t n)
{
	char *p = xmalloc(n + 1);
	memcpy(p, s, n);
	p[n] = 0;
	return p;
}

char *xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *p;
	va_start(ap, fmt);
	if (vasprintf(&p, fmt, ap) < 0)
		die("нет памяти");
	va_end(ap);
	return p;
}

void buf_reserve(struct buf *b, size_t n)
{
	if (n > SIZE_MAX - b->len - 1)
		die("нет памяти");
	if (b->len + n + 1 <= b->cap)
		return;
	size_t cap = b->cap ? b->cap : 256;
	while (cap < b->len + n + 1)
		cap = cap > SIZE_MAX / 2 ? b->len + n + 1 : cap * 2;
	b->p = xrealloc(b->p, cap);
	b->cap = cap;
}

void buf_add(struct buf *b, const void *d, size_t n)
{
	buf_reserve(b, n);
	if (n)
		memcpy(b->p + b->len, d, n);
	b->len += n;
	b->p[b->len] = 0;
}

void buf_adds(struct buf *b, const char *s)
{
	buf_add(b, s, strlen(s));
}

void buf_addf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0)
		die("формат");
	buf_reserve(b, (size_t)n);
	va_start(ap, fmt);
	vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap);
	va_end(ap);
	b->len += (size_t)n;
}

void buf_free(struct buf *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

void strv_take(struct strv *s, char *str)
{
	if (s->n + 1 >= s->cap) {
		s->cap = s->cap ? s->cap * 2 : 16;
		s->v = xrealloc(s->v, s->cap * sizeof(char *));
	}
	s->v[s->n++] = str;
	s->v[s->n] = NULL;
}

void strv_add(struct strv *s, const char *str)
{
	strv_take(s, xstrdup(str));
}

bool strv_has(const struct strv *s, const char *str)
{
	for (size_t i = 0; i < s->n; i++)
		if (strcmp(s->v[i], str) == 0)
			return true;
	return false;
}

static int cmp_str(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

void strv_sort(struct strv *s)
{
	if (s->n > 1)
		qsort(s->v, s->n, sizeof(char *), cmp_str);
}

void strv_free(struct strv *s)
{
	for (size_t i = 0; i < s->n; i++)
		free(s->v[i]);
	free(s->v);
	s->v = NULL;
	s->n = s->cap = 0;
}

char *strv_join(const struct strv *s, const char *sep)
{
	struct buf b = {0};
	buf_adds(&b, "");
	for (size_t i = 0; i < s->n; i++) {
		if (i)
			buf_adds(&b, sep);
		buf_adds(&b, s->v[i]);
	}
	return b.p;
}

bool startswith(const char *s, const char *prefix)
{
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

bool endswith(const char *s, const char *suffix)
{
	size_t a = strlen(s), b = strlen(suffix);
	return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

bool is_space(int c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

char *strip(char *s)
{
	while (is_space((unsigned char)*s))
		s++;
	size_t n = strlen(s);
	while (n && is_space((unsigned char)s[n - 1]))
		s[--n] = 0;
	return s;
}

char *read_file(const char *path, size_t *len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	struct buf b = {0};
	buf_reserve(&b, 4096);
	for (;;) {
		buf_reserve(&b, 65536);
		ssize_t r = read(fd, b.p + b.len, b.cap - b.len - 1);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			close(fd);
			buf_free(&b);
			errno = e;
			return NULL;
		}
		if (r == 0)
			break;
		b.len += (size_t)r;
	}
	close(fd);
	b.p[b.len] = 0;
	if (len)
		*len = b.len;
	return b.p;
}

const char *rd(const char *path, char *out, size_t sz)
{
	out[0] = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return out;
	ssize_t r;
	do
		r = read(fd, out, sz - 1);
	while (r < 0 && errno == EINTR);
	close(fd);
	if (r < 0)
		r = 0;
	out[r] = 0;
	char *s = strip(out);
	if (s != out)
		memmove(out, s, strlen(s) + 1);
	return out;
}

bool write_str(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	size_t n = strlen(s);
	ssize_t w = write(fd, s, n);
	int e = errno;
	close(fd);
	errno = e;
	return w == (ssize_t)n;
}

void write_atomic(const char *path, const void *data, size_t len, mode_t mode)
{
	char *tmp = xasprintf("%s.new", path);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
	if (fd < 0)
		die("%s: %s", tmp, strerror(errno));
	const char *p = data;
	while (len) {
		ssize_t w = write(fd, p, len);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			die("%s: %s", tmp, strerror(errno));
		}
		p += w;
		len -= (size_t)w;
	}
	if (fchmod(fd, mode) != 0 || fsync(fd) != 0 || close(fd) != 0)
		die("%s: %s", tmp, strerror(errno));
	if (rename(tmp, path) != 0)
		die("%s: %s", path, strerror(errno));
	free(tmp);
}

bool path_exists(const char *path)
{
	struct stat st;
	return lstat(path, &st) == 0;
}

bool is_regular(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool is_dir(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

void mkdirs(const char *path, mode_t mode)
{
	char *p = xstrdup(path);
	for (char *s = p + 1; *s; s++) {
		if (*s != '/')
			continue;
		*s = 0;
		if (mkdir(p, 0755) != 0 && errno != EEXIST)
			die("%s: %s", p, strerror(errno));
		*s = '/';
	}
	if (mkdir(p, mode) != 0 && errno != EEXIST)
		die("%s: %s", p, strerror(errno));
	free(p);
}

void kv_set(struct kvs *c, const char *k, const char *v)
{
	for (size_t i = 0; i < c->n; i++)
		if (strcmp(c->k[i], k) == 0) {
			free(c->v[i]);
			c->v[i] = xstrdup(v);
			return;
		}
	c->k = xrealloc(c->k, (c->n + 1) * sizeof(char *));
	c->v = xrealloc(c->v, (c->n + 1) * sizeof(char *));
	c->k[c->n] = xstrdup(k);
	c->v[c->n] = xstrdup(v);
	c->n++;
}

void kv_read(struct kvs *c, const char *path, int flags)
{
	char *text = read_file(path, NULL);
	if (!text)
		return;
	char *save = NULL;
	for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (flags & KV_INLINE) {
			char *h = strchr(line, '#');
			if (h)
				*h = 0;
		}
		line = strip(line);
		if (!*line || *line == '#')
			continue;
		char *eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = 0;
		char *k = strip(line), *v = strip(eq + 1);
		while (*v == '"')
			v++;
		size_t n = strlen(v);
		while (n && v[n - 1] == '"')
			v[--n] = 0;
		kv_set(c, k, v);
	}
	free(text);
}

const char *kv_get(const struct kvs *c, const char *k, const char *def)
{
	for (size_t i = 0; i < c->n; i++)
		if (strcmp(c->k[i], k) == 0)
			return c->v[i];
	return def;
}

long kv_int(const struct kvs *c, const char *k, const char *def)
{
	const char *s = kv_get(c, k, def);
	char *end;
	errno = 0;
	long v = strtol(s, &end, 10);
	while (is_space((unsigned char)*end))
		end++;
	if (errno || end == s || *end)
		die("%s=%s: нужно целое число", k, s);
	return v;
}

void close_fds_from(int from)
{
#ifdef SYS_close_range
	if (syscall(SYS_close_range, (unsigned)from, ~0U, 0) == 0)
		return;
#endif
	long max = sysconf(_SC_OPEN_MAX);
	for (long fd = from; fd < (max > 0 ? max : 1024); fd++)
		close((int)fd);
}

/* дочитать/дописать каналы, пока все не закрыты */
static void pump(int in_fd, const char *in, size_t inlen, int out_fd, struct buf *out,
		 int err_fd, struct buf *err)
{
	size_t in_off = 0;
	if (in_fd >= 0 && inlen == 0) {
		close(in_fd);
		in_fd = -1;
	}
	while (in_fd >= 0 || out_fd >= 0 || err_fd >= 0) {
		struct pollfd p[3] = {
			{.fd = in_fd, .events = POLLOUT},
			{.fd = out_fd, .events = POLLIN},
			{.fd = err_fd, .events = POLLIN},
		};
		if (poll(p, 3, -1) < 0) {
			if (errno == EINTR)
				continue;
			die("poll: %s", strerror(errno));
		}
		if (in_fd >= 0 && p[0].revents) {
			ssize_t w = write(in_fd, in + in_off, inlen - in_off);
			if (w > 0)
				in_off += (size_t)w;
			if (w < 0 && errno != EINTR && errno != EAGAIN)
				in_off = inlen;     /* EPIPE: программа не читает stdin */
			if (in_off == inlen) {
				close(in_fd);
				in_fd = -1;
			}
		}
		int *fds[2] = {&out_fd, &err_fd};
		struct buf *bufs[2] = {out, err};
		for (int i = 0; i < 2; i++) {
			if (*fds[i] < 0 || !p[i + 1].revents)
				continue;
			buf_reserve(bufs[i], 65536);
			ssize_t r = read(*fds[i], bufs[i]->p + bufs[i]->len, 65536);
			if (r > 0) {
				bufs[i]->len += (size_t)r;
				bufs[i]->p[bufs[i]->len] = 0;
			} else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
				close(*fds[i]);
				*fds[i] = -1;
			}
		}
	}
}

int run(char *const argv[], const void *in, size_t inlen, struct buf *out, struct buf *err)
{
	int pin[2] = {-1, -1}, pout[2] = {-1, -1}, perr[2] = {-1, -1};
	if ((in && pipe2(pin, O_CLOEXEC)) || (out && pipe2(pout, O_CLOEXEC)) ||
	    (err && pipe2(perr, O_CLOEXEC)))
		die("pipe: %s", strerror(errno));
	if (out)
		buf_adds(out, "");
	if (err)
		buf_adds(err, "");
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		signal(SIGPIPE, SIG_DFL);
		if ((in && dup2(pin[0], 0) < 0) || (out && dup2(pout[1], 1) < 0) ||
		    (err && dup2(perr[1], 2) < 0))
			_exit(127);
		execvp(argv[0], argv);
		dprintf(2, "%s: %s: %s\n", vh_prog, argv[0], strerror(errno));
		_exit(127);
	}
	if (in)
		close(pin[0]);
	if (out)
		close(pout[1]);
	if (err)
		close(perr[1]);
	void (*old)(int) = signal(SIGPIPE, SIG_IGN);
	pump(pin[1], in, inlen, pout[0], out, perr[0], err);
	signal(SIGPIPE, old);
	int st;
	while (waitpid(pid, &st, 0) < 0)
		if (errno != EINTR)
			die("waitpid: %s", strerror(errno));
	if (WIFEXITED(st))
		return WEXITSTATUS(st);
	return 128 + WTERMSIG(st);
}

/* «да» на вопрос: y, yes, д, да в любом регистре */
bool ask(const char *question, bool yes)
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
