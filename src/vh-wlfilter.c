/* vh-wlfilter — фильтрующий Wayland-прокси для песочниц (docs/08).
 *
 * В mango нет протокола security-context-v1: любой клиент основного сокета видит
 * screencopy, data-control (буфер обмена), virtual-keyboard, input-method,
 * layer-shell и т. п. Этот прокси слушает отдельный сокет для песочниц и
 * показывает клиенту только разрешённые глобальные объекты (белый список —
 * строже чёрного списка security-context). Кроме того он:
 *   * не даёт привязать скрытый объект, угадав его номер (соединение рвётся);
 *   * помечает окна песочницы: app_id «vh-sandbox.…», заголовок «[песочница] …» —
 *     подделать это клиент не может, правила mango опираются на app_id;
 *   * отбрасывает запросы на полноэкранный режим (поддельный экран блокировки).
 *
 * Данные клиента — недоверенные (браузер мог быть взломан): каждое чтение поля
 * проверяет границы сообщения, любая ошибка разбора рвёт только это соединение.
 *
 * Запускается в сеансе повседневного пользователя (exec-once в mango).
 * Сокет: /run/vh-sandbox/wayland (каталог user:browser 2750, сокет 0660).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "vh.h"

#define LISTEN "/run/vh-sandbox/wayland"
#define MAX_FDS 28            /* столько fd libwayland передаёт за один sendmsg */
#define MAX_MSG 4096          /* предел размера сообщения в libwayland */
#define HIGH_WATER (1u << 20) /* перестаём читать источник, если очередь получателя больше */
#define RECV_SIZE 65536

/* Белый список глобальных объектов. Всё прочее клиент песочницы просто не видит. */
static const char *const allowed[] = {
	"wl_compositor", "wl_subcompositor", "wl_shm", "wl_seat", "wl_output",
	"wl_data_device_manager",          /* копирование/вставка (буфер отдаётся окну в фокусе) */
	"wl_drm",                          /* устаревший путь mesa к render node */
	"xdg_wm_base", "zxdg_decoration_manager_v1", "org_kde_kwin_server_decoration_manager",
	"zxdg_output_manager_v1",
	"zwp_linux_dmabuf_v1", "wp_linux_drm_syncobj_manager_v1",
	"wp_viewporter", "wp_fractional_scale_manager_v1", "wp_presentation",
	"wp_single_pixel_buffer_manager_v1", "wp_cursor_shape_manager_v1",
	"wp_color_manager_v1", "wp_color_representation_manager_v1",
	"wp_content_type_manager_v1", "wp_tearing_control_manager_v1", "wp_alpha_modifier_v1",
	"wp_fifo_manager_v1", "wp_commit_timing_manager_v1",
	"zwp_pointer_gestures_v1", "zwp_relative_pointer_manager_v1",
	"zwp_pointer_constraints_v1", "zwp_tablet_manager_v2",
	"zwp_text_input_manager_v3",       /* ввод через IME в поля браузера (не input-method!) */
	"zwp_idle_inhibit_manager_v1",     /* видео не даёт экрану гаснуть (docs/05 — цена) */
};
#define N_ALLOWED (sizeof(allowed) / sizeof(allowed[0]))
/* Для справки — что скрывается (неполный список, скрывается ВСЁ вне allowed):
 * zwlr_screencopy_manager_v1, ext_image_copy_capture_manager_v1, zwlr_export_dmabuf_manager_v1,
 * zwlr_data_control_manager_v1, ext_data_control_manager_v1, zwp_primary_selection_device_manager_v1,
 * zwp_virtual_keyboard_manager_v1, zwlr_virtual_pointer_manager_v1, zwp_input_method_manager_v2,
 * zwlr_layer_shell_v1, ext_session_lock_manager_v1, zwlr_foreign_toplevel_manager_v1,
 * ext_foreign_toplevel_list_v1, zwlr_gamma_control_manager_v1, zwlr_output_power_manager_v1,
 * zwlr_output_manager_v1, wp_drm_lease_device_v1, zwp_keyboard_shortcuts_inhibit_manager_v1,
 * ext_idle_notifier_v1, xdg_activation_v1, zxdg_exporter_v2, ext_workspace_manager_v1. */

#define TITLE_PREFIX "[песочница] "
#define APPID_PREFIX "vh-sandbox"

/* коды запросов и событий (wayland.xml, xdg-shell.xml) */
#define WL_DISPLAY_GET_REGISTRY 1
#define WL_DISPLAY_DELETE_ID 1        /* событие */
#define WL_REGISTRY_BIND 0
#define WL_REGISTRY_GLOBAL 0          /* событие */
#define WL_REGISTRY_GLOBAL_REMOVE 1   /* событие */
#define XDG_WM_BASE_GET_XDG_SURFACE 2
#define XDG_SURFACE_GET_TOPLEVEL 1
#define XDG_TOPLEVEL_SET_TITLE 2
#define XDG_TOPLEVEL_SET_APP_ID 3
#define XDG_TOPLEVEL_SET_FULLSCREEN 11

/* ---------------------------------------------------------------- таблица uint32 → int */
/* Открытая адресация; номера объектов выбирает клиент — размер не ограничен заранее. */
struct imap {
	uint32_t *key;
	int32_t *val;
	uint8_t *st;          /* 0 пусто, 1 занято, 2 удалено */
	size_t cap, used, tomb;
};

static size_t ihash(uint32_t k, size_t cap)
{
	uint64_t h = (uint64_t)k * 0x9E3779B97F4A7C15ull;
	return (size_t)(h >> 32) & (cap - 1);
}

static void imap_put(struct imap *m, uint32_t k, int32_t v);

static void imap_grow(struct imap *m)
{
	struct imap old = *m;
	m->cap = old.cap ? old.cap * 2 : 16;
	if (old.cap && old.used * 4 < old.cap)  /* много удалённых — пересобрать того же размера */
		m->cap = old.cap;
	m->key = xcalloc(m->cap, sizeof(uint32_t));
	m->val = xcalloc(m->cap, sizeof(int32_t));
	m->st = xcalloc(m->cap, 1);
	m->used = m->tomb = 0;
	for (size_t i = 0; i < old.cap; i++)
		if (old.st[i] == 1)
			imap_put(m, old.key[i], old.val[i]);
	free(old.key);
	free(old.val);
	free(old.st);
}

static long imap_find(const struct imap *m, uint32_t k)
{
	if (!m->cap)
		return -1;
	for (size_t i = ihash(k, m->cap), n = 0; n < m->cap; i = (i + 1) & (m->cap - 1), n++) {
		if (m->st[i] == 0)
			return -1;
		if (m->st[i] == 1 && m->key[i] == k)
			return (long)i;
	}
	return -1;
}

static void imap_put(struct imap *m, uint32_t k, int32_t v)
{
	long f = imap_find(m, k);
	if (f >= 0) {
		m->val[f] = v;
		return;
	}
	if ((m->used + m->tomb + 1) * 2 > m->cap)
		imap_grow(m);
	size_t i = ihash(k, m->cap);
	while (m->st[i] == 1)
		i = (i + 1) & (m->cap - 1);
	if (m->st[i] == 2)
		m->tomb--;
	m->st[i] = 1;
	m->key[i] = k;
	m->val[i] = v;
	m->used++;
}

static bool imap_has(const struct imap *m, uint32_t k)
{
	return imap_find(m, k) >= 0;
}

static int32_t imap_get(const struct imap *m, uint32_t k, int32_t def)
{
	long f = imap_find(m, k);
	return f >= 0 ? m->val[f] : def;
}

static bool imap_del(struct imap *m, uint32_t k)
{
	long f = imap_find(m, k);
	if (f < 0)
		return false;
	m->st[f] = 2;
	m->used--;
	m->tomb++;
	return true;
}

static void imap_free(struct imap *m)
{
	free(m->key);
	free(m->val);
	free(m->st);
	memset(m, 0, sizeof(*m));
}

/* ---------------------------------------------------------------- соединения */
struct chunk {
	struct chunk *next;
	size_t len, off;
	int nfds;
	int fds[MAX_FDS];
	char data[];
};

struct conn;

/* Одно направление: сокет, входной буфер, очередь на отправку. */
struct side {
	struct conn *conn;
	int fd;
	struct buf in;            /* хвост незавершённого сообщения */
	int *fds;                 /* fd, полученные и ещё не отправленные дальше */
	size_t nfds, capfds;
	struct chunk *head, *tail;
	size_t out_bytes;
	uint32_t ev;              /* события в epoll; 0 — не зарегистрирован */
};

struct conn {
	struct side c, s;         /* c — клиент песочницы, s — композитор */
	struct imap registries, wm_bases, xdg_surfaces, toplevels;
	struct imap names;        /* номер глобала → индекс в allowed (только разрешённые) */
	bool closed;
	struct conn *next_dead;
};

static int epfd, lsock;
static char upstream[sizeof(((struct sockaddr_un *)0)->sun_path)];
static struct conn *dead;

/* ошибка разбора: текст для журнала; NULL — всё в порядке */
typedef const char *perr;

static uint32_t get32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, 4);         /* порядок байт хоста, как в libwayland */
	return v;
}

static void put32(struct buf *b, uint32_t v)
{
	buf_add(b, &v, 4);
}

/* строка Wayland: длина с нулём, байты, выравнивание до 4 */
static perr get_string(const uint8_t *body, size_t blen, size_t off, const uint8_t **s,
		       size_t *slen, size_t *next)
{
	if (off > blen || blen - off < 4)
		return "короткое сообщение";
	uint64_t n = get32(body + off);
	if (n == 0 || off + 4 + n > blen)
		return "плохая строка";
	*s = body + off + 4;
	*slen = (size_t)n - 1;
	*next = off + 4 + (size_t)((n + 3) & ~3ull);
	return NULL;
}

static void put_string(struct buf *b, const char *s, size_t n)
{
	static const char zero[4];
	put32(b, (uint32_t)(n + 1));
	buf_add(b, s, n);
	buf_add(b, zero, 1 + (4 - (n + 1) % 4) % 4);
}

static perr message(struct buf *out, uint32_t obj, uint32_t op, const struct buf *payload)
{
	size_t size = 8 + payload->len;
	if (size > MAX_MSG)
		return "сообщение слишком длинное";
	put32(out, obj);
	put32(out, (uint32_t)(size << 16) | op);
	buf_add(out, payload->p, payload->len);
	return NULL;
}

/* UTF-8 с заменой ошибок на U+FFFD (одна замена на максимальную неверную часть) */
static size_t utf8_next(const uint8_t *s, size_t n, uint32_t *cp)
{
	uint8_t c = s[0], lo = 0x80, hi = 0xBF;
	int need;
	uint32_t v;
	if (c < 0x80) {
		*cp = c;
		return 1;
	}
	if (c >= 0xC2 && c <= 0xDF) {
		need = 1;
		v = c & 0x1F;
	} else if (c >= 0xE0 && c <= 0xEF) {
		need = 2;
		v = c & 0x0F;
		if (c == 0xE0)
			lo = 0xA0;
		if (c == 0xED)
			hi = 0x9F;
	} else if (c >= 0xF0 && c <= 0xF4) {
		need = 3;
		v = c & 0x07;
		if (c == 0xF0)
			lo = 0x90;
		if (c == 0xF4)
			hi = 0x8F;
	} else {
		*cp = 0xFFFD;
		return 1;
	}
	size_t i = 1;
	for (int k = 0; k < need; k++, i++) {
		if (i >= n || s[i] < lo || s[i] > hi) {
			*cp = 0xFFFD;
			return i;
		}
		lo = 0x80;
		hi = 0xBF;
		v = v << 6 | (s[i] & 0x3F);
	}
	*cp = v;
	return i;
}

static void utf8_put(struct buf *b, uint32_t cp)
{
	char o[4];
	size_t n;
	if (cp < 0x80) {
		o[0] = (char)cp;
		n = 1;
	} else if (cp < 0x800) {
		o[0] = (char)(0xC0 | cp >> 6);
		o[1] = (char)(0x80 | (cp & 0x3F));
		n = 2;
	} else if (cp < 0x10000) {
		o[0] = (char)(0xE0 | cp >> 12);
		o[1] = (char)(0x80 | (cp >> 6 & 0x3F));
		o[2] = (char)(0x80 | (cp & 0x3F));
		n = 3;
	} else {
		o[0] = (char)(0xF0 | cp >> 18);
		o[1] = (char)(0x80 | (cp >> 12 & 0x3F));
		o[2] = (char)(0x80 | (cp >> 6 & 0x3F));
		o[3] = (char)(0x80 | (cp & 0x3F));
		n = 4;
	}
	buf_add(b, o, n);
}

/* Непечатные символы: управляющие, форматирующие (в том числе bidi и нулевой ширины),
 * разделители кроме пробела, частные и заведомо неназначенные — как isprintable(). */
static bool printable(uint32_t c)
{
	static const uint32_t bad[][2] = {
		{0x00, 0x1F}, {0x7F, 0xA0}, {0xAD, 0xAD}, {0x600, 0x605}, {0x61C, 0x61C},
		{0x6DD, 0x6DD}, {0x70F, 0x70F}, {0x890, 0x891}, {0x8E2, 0x8E2}, {0x1680, 0x1680},
		{0x180E, 0x180E}, {0x2000, 0x200F}, {0x2028, 0x202F}, {0x205F, 0x2064},
		{0x2066, 0x206F}, {0x3000, 0x3000}, {0xD800, 0xF8FF}, {0xFDD0, 0xFDEF},
		{0xFEFF, 0xFEFF}, {0xFFF0, 0xFFFB}, {0x110BD, 0x110BD}, {0x110CD, 0x110CD},
		{0x13430, 0x1343F}, {0x1BCA0, 0x1BCA3}, {0x1D173, 0x1D17A}, {0x40000, 0xDFFFF},
		{0xE0000, 0xE00FF}, {0xE01F0, 0x10FFFF},
	};
	if ((c & 0xFFFE) == 0xFFFE)   /* U+xFFFE, U+xFFFF — не символы */
		return false;
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		if (c >= bad[i][0] && c <= bad[i][1])
			return false;
	return true;
}

/* Только печатные символы, не больше limit: app_id и заголовок не должны ломать правила mango. */
static void clean(struct buf *out, const uint8_t *s, size_t n, size_t limit)
{
	size_t i = 0, kept = 0;
	while (i < n && kept < limit) {
		uint32_t cp;
		i += utf8_next(s + i, n - i, &cp);
		if (!printable(cp))
			continue;
		utf8_put(out, cp);
		kept++;
	}
}

#define NEED(len) do { if (blen < (len)) return "короткое сообщение"; } while (0)

/* --- разбор сообщений клиента (запросы) */
static perr request(struct conn *k, const uint8_t *msg, size_t size, struct buf *out)
{
	uint32_t obj = get32(msg), op = get32(msg + 4) & 0xFFFF;
	const uint8_t *body = msg + 8;
	size_t blen = size - 8;
	perr e;

	if (obj == 1 && op == WL_DISPLAY_GET_REGISTRY) {
		NEED(4);
		imap_put(&k->registries, get32(body), 1);
	} else if (imap_has(&k->registries, obj) && op == WL_REGISTRY_BIND) {
		NEED(4);
		uint32_t name = get32(body);
		const uint8_t *iface;
		size_t ilen, o;
		if ((e = get_string(body, blen, 4, &iface, &ilen, &o)))
			return e;
		if (o > blen || blen - o < 8)
			return "короткое сообщение";
		uint32_t new_id = get32(body + o + 4);
		int32_t idx = imap_get(&k->names, name, -1);
		if (idx < 0 || strlen(allowed[idx]) != ilen || memcmp(allowed[idx], iface, ilen) != 0)
			return "попытка привязать скрытый объект";
		if (strcmp(allowed[idx], "xdg_wm_base") == 0)
			imap_put(&k->wm_bases, new_id, 1);
	} else if (imap_has(&k->wm_bases, obj) && op == XDG_WM_BASE_GET_XDG_SURFACE) {
		NEED(4);
		imap_put(&k->xdg_surfaces, get32(body), 1);
	} else if (imap_has(&k->xdg_surfaces, obj) && op == XDG_SURFACE_GET_TOPLEVEL) {
		NEED(4);
		uint32_t new_id = get32(body);
		imap_put(&k->toplevels, new_id, 1);
		/* сразу пометить окно: даже если клиент не задаст app_id, правило mango сработает */
		buf_add(out, msg, size);
		struct buf p = {0};
		put_string(&p, APPID_PREFIX, strlen(APPID_PREFIX));
		e = message(out, new_id, XDG_TOPLEVEL_SET_APP_ID, &p);
		buf_free(&p);
		return e;
	} else if (imap_has(&k->toplevels, obj)) {
		if (op == XDG_TOPLEVEL_SET_FULLSCREEN)
			return NULL;       /* полноэкранный режим — только привязкой mango (docs/08) */
		if (op == XDG_TOPLEVEL_SET_TITLE || op == XDG_TOPLEVEL_SET_APP_ID) {
			const uint8_t *s;
			size_t slen, o;
			if ((e = get_string(body, blen, 0, &s, &slen, &o)))
				return e;
			struct buf t = {0}, p = {0};
			if (op == XDG_TOPLEVEL_SET_TITLE) {
				buf_adds(&t, TITLE_PREFIX);
				clean(&t, s, slen, 200);
			} else {
				buf_adds(&t, APPID_PREFIX ".");
				clean(&t, s, slen, 100);
			}
			put_string(&p, t.p, t.len);
			e = message(out, obj, op, &p);
			buf_free(&t);
			buf_free(&p);
			return e;
		}
	}
	buf_add(out, msg, size);
	return NULL;
}

/* --- разбор сообщений композитора (события) */
static perr event(struct conn *k, const uint8_t *msg, size_t size, struct buf *out)
{
	uint32_t obj = get32(msg), op = get32(msg + 4) & 0xFFFF;
	const uint8_t *body = msg + 8;
	size_t blen = size - 8;
	perr e;

	if (imap_has(&k->registries, obj)) {
		if (op == WL_REGISTRY_GLOBAL) {
			NEED(4);
			uint32_t name = get32(body);
			const uint8_t *iface;
			size_t ilen, o;
			if ((e = get_string(body, blen, 4, &iface, &ilen, &o)))
				return e;
			int32_t idx = -1;
			for (size_t i = 0; i < N_ALLOWED; i++)
				if (strlen(allowed[i]) == ilen && memcmp(allowed[i], iface, ilen) == 0)
					idx = (int32_t)i;
			if (idx < 0)
				return NULL;      /* скрытый глобал: клиент о нём не узнает */
			imap_put(&k->names, name, idx);
		} else if (op == WL_REGISTRY_GLOBAL_REMOVE) {
			NEED(4);
			if (!imap_del(&k->names, get32(body)))
				return NULL;
		}
	} else if (obj == 1 && op == WL_DISPLAY_DELETE_ID) {
		NEED(4);
		uint32_t oid = get32(body);
		imap_del(&k->registries, oid);
		imap_del(&k->wm_bases, oid);
		imap_del(&k->xdg_surfaces, oid);
		imap_del(&k->toplevels, oid);
	}
	buf_add(out, msg, size);
	return NULL;
}

/* разобрать все целые сообщения из in; хвост остаётся в in */
static perr filter(struct conn *k, bool from_client, struct buf *in, struct buf *out)
{
	size_t off = 0;
	perr e = NULL;
	while (in->len - off >= 8) {
		const uint8_t *m = (const uint8_t *)in->p + off;
		uint32_t size = get32(m + 4) >> 16;
		if (size < 8 || size % 4 || size > MAX_MSG) {
			e = from_client ? "плохой размер запроса" : "плохой размер события";
			break;
		}
		if (in->len - off < size)
			break;
		e = from_client ? request(k, m, size, out) : event(k, m, size, out);
		if (e)
			break;
		off += size;
	}
	memmove(in->p, in->p + off, in->len - off);
	in->len -= off;
	return e;
}

static void close_conn(struct conn *k)
{
	if (k->closed)
		return;
	k->closed = true;
	struct side *sides[2] = {&k->c, &k->s};
	for (int i = 0; i < 2; i++) {
		struct side *s = sides[i];
		for (size_t j = 0; j < s->nfds; j++)
			close(s->fds[j]);
		s->nfds = 0;
		for (struct chunk *c = s->head, *n; c; c = n) {
			n = c->next;
			for (int j = 0; j < c->nfds; j++)
				close(c->fds[j]);
			free(c);
		}
		s->head = s->tail = NULL;
		if (s->fd >= 0)
			close(s->fd);    /* закрытие снимает fd и с epoll */
		s->fd = -1;
	}
	k->next_dead = dead;
	dead = k;
}

static void free_conn(struct conn *k)
{
	buf_free(&k->c.in);
	buf_free(&k->s.in);
	free(k->c.fds);
	free(k->s.fds);
	imap_free(&k->registries);
	imap_free(&k->wm_bases);
	imap_free(&k->xdg_surfaces);
	imap_free(&k->toplevels);
	imap_free(&k->names);
	free(k);
}

/* регистрация событий с учётом очередей (обратное давление) */
static void update(struct conn *k)
{
	if (k->closed)
		return;
	struct side *pair[2][2] = {{&k->c, &k->s}, {&k->s, &k->c}};
	for (int i = 0; i < 2; i++) {
		struct side *s = pair[i][0], *other = pair[i][1];
		uint32_t ev = 0;
		if (other->out_bytes < HIGH_WATER)
			ev |= EPOLLIN;
		if (s->head)
			ev |= EPOLLOUT;
		if (ev == s->ev)
			continue;
		struct epoll_event e = {.events = ev, .data.ptr = s};
		int op = ev == 0 ? EPOLL_CTL_DEL : s->ev == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
		if (epoll_ctl(epfd, op, s->fd, &e) != 0)
			die("epoll_ctl: %s", strerror(errno));
		s->ev = ev;
	}
}

static void enqueue(struct side *dst, const char *data, size_t len, const int *fds, int nfds)
{
	struct chunk *c = xmalloc(sizeof(*c) + len);
	c->next = NULL;
	c->len = len;
	c->off = 0;
	c->nfds = nfds;
	if (nfds)
		memcpy(c->fds, fds, (size_t)nfds * sizeof(int));
	memcpy(c->data, data, len);
	if (dst->tail)
		dst->tail->next = c;
	else
		dst->head = c;
	dst->tail = c;
	dst->out_bytes += len;
}

/* отправить очередь; false — соединение разорвано */
static bool flush(struct side *dst)
{
	while (dst->head) {
		struct chunk *c = dst->head;
		struct iovec iov = {.iov_base = c->data + c->off, .iov_len = c->len - c->off};
		union {
			char b[CMSG_SPACE(MAX_FDS * sizeof(int))];
			struct cmsghdr align;
		} ctl;
		struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1};
		if (c->nfds) {
			memset(&ctl, 0, sizeof(ctl));
			mh.msg_control = ctl.b;
			mh.msg_controllen = CMSG_SPACE((size_t)c->nfds * sizeof(int));
			struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
			cm->cmsg_level = SOL_SOCKET;
			cm->cmsg_type = SCM_RIGHTS;
			cm->cmsg_len = CMSG_LEN((size_t)c->nfds * sizeof(int));
			memcpy(CMSG_DATA(cm), c->fds, (size_t)c->nfds * sizeof(int));
		}
		ssize_t n = sendmsg(dst->fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				break;
			close_conn(dst->conn);
			return false;
		}
		for (int j = 0; j < c->nfds; j++)
			close(c->fds[j]);
		c->nfds = 0;              /* fd ушли с первой частью */
		dst->out_bytes -= (size_t)n;
		c->off += (size_t)n;
		if (c->off == c->len) {
			dst->head = c->next;
			if (!dst->head)
				dst->tail = NULL;
			free(c);
		}
	}
	update(dst->conn);
	return true;
}

static void readable(struct side *src)
{
	struct conn *k = src->conn;
	bool from_client = src == &k->c;
	struct side *dst = from_client ? &k->s : &k->c;
	static char data[RECV_SIZE];
	union {
		char b[CMSG_SPACE(MAX_FDS * sizeof(int))];
		struct cmsghdr align;
	} ctl;
	struct iovec iov = {.iov_base = data, .iov_len = sizeof(data)};
	struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl.b,
			    .msg_controllen = sizeof(ctl.b)};
	ssize_t n = recvmsg(src->fd, &mh, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		close_conn(k);
		return;
	}
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
		if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS)
			continue;
		size_t cnt = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		if (!cnt)
			continue;
		if (src->nfds + cnt > src->capfds) {
			src->capfds = src->nfds + cnt + 32;
			src->fds = xrealloc(src->fds, src->capfds * sizeof(int));
		}
		memcpy(src->fds + src->nfds, CMSG_DATA(cm), cnt * sizeof(int));
		src->nfds += cnt;
	}
	if (mh.msg_flags & MSG_CTRUNC) {
		warnmsg("клиент отключён: больше %d fd за раз", MAX_FDS);
		close_conn(k);
		return;
	}
	if (n == 0) {
		close_conn(k);
		return;
	}
	buf_add(&src->in, data, (size_t)n);
	struct buf out = {0};
	perr e = filter(k, from_client, &src->in, &out);
	if (e) {
		warnmsg("клиент отключён: %s", e);
		buf_free(&out);
		close_conn(k);
		return;
	}
	if (out.len == 0) {
		buf_free(&out);
		if (src->nfds > 4 * MAX_FDS) {
			warnmsg("клиент отключён: слишком много fd без данных");
			close_conn(k);
		}
		return;
	}
	/* fd уходят не позже сообщения, которому принадлежат: всё накопленное — сейчас.
	 * libwayland принимает не больше 28 fd за recvmsg — делим по 28, каждую
	 * порцию с хотя бы одним байтом (поток байтов можно резать где угодно). */
	size_t pos = 0, fpos = 0;
	while (src->nfds - fpos > MAX_FDS && out.len - pos > 1) {
		enqueue(dst, out.p + pos, 1, src->fds + fpos, MAX_FDS);
		pos++;
		fpos += MAX_FDS;
	}
	enqueue(dst, out.p + pos, out.len - pos, src->fds + fpos, (int)(src->nfds - fpos));
	src->nfds = 0;
	buf_free(&out);
	flush(dst);
}

static void accept_client(void)
{
	int c = accept4(lsock, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (c < 0)
		return;
	int up = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un sa = {.sun_family = AF_UNIX};
	memcpy(sa.sun_path, upstream, strlen(upstream) + 1);
	if (up < 0 || connect(up, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    fcntl(up, F_SETFL, O_NONBLOCK) != 0) {
		warnmsg("нет связи с композитором: %s", strerror(errno));
		if (up >= 0)
			close(up);
		close(c);
		return;
	}
	struct conn *k = xcalloc(1, sizeof(*k));
	k->c.conn = k->s.conn = k;
	k->c.fd = c;
	k->s.fd = up;
	update(k);
}

static void on_term(int sig)
{
	(void)sig;
	_exit(0);
}

int main(void)
{
	vh_prog = "vh-wlfilter";
	signal(SIGTERM, on_term);
	signal(SIGPIPE, SIG_IGN);
	const char *rt = getenv("XDG_RUNTIME_DIR");
	const char *disp = getenv("WAYLAND_DISPLAY");
	if (!rt || !*rt)
		die("нет XDG_RUNTIME_DIR");
	if (!disp || !*disp)
		disp = "wayland-0";
	int n = disp[0] == '/' ? snprintf(upstream, sizeof(upstream), "%s", disp)
			       : snprintf(upstream, sizeof(upstream), "%s/%s", rt, disp);
	if (n < 0 || (size_t)n >= sizeof(upstream))
		die("слишком длинный путь сокета композитора");

	if (unlink(LISTEN) != 0 && errno != ENOENT)
		die("%s: %s", LISTEN, strerror(errno));
	lsock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_un sa = {.sun_family = AF_UNIX, .sun_path = LISTEN};
	mode_t old = umask(0117);
	if (lsock < 0 || bind(lsock, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		die("%s: %s", LISTEN, strerror(errno));
	umask(old);
	if (chmod(LISTEN, 0660) != 0 || listen(lsock, 8) != 0)
		die("%s: %s", LISTEN, strerror(errno));
	epfd = epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event le = {.events = EPOLLIN, .data.ptr = NULL};
	if (epfd < 0 || epoll_ctl(epfd, EPOLL_CTL_ADD, lsock, &le) != 0)
		die("epoll: %s", strerror(errno));
	warnmsg("слушаю %s → %s", LISTEN, upstream);

	for (;;) {
		struct epoll_event evs[64];
		int ne = epoll_wait(epfd, evs, 64, -1);
		if (ne < 0) {
			if (errno == EINTR)
				continue;
			die("epoll_wait: %s", strerror(errno));
		}
		for (int i = 0; i < ne; i++) {
			struct side *s = evs[i].data.ptr;
			if (!s) {
				accept_client();
				continue;
			}
			if (s->conn->closed)
				continue;
			uint32_t ev = evs[i].events;
			if ((ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)) && s->head && !flush(s))
				continue;
			if ((ev & (EPOLLIN | EPOLLERR | EPOLLHUP)) && !s->conn->closed && (s->ev & EPOLLIN))
				readable(s);
		}
		/* память закрытых соединений — после пачки: в ней могли быть их события */
		while (dead) {
			struct conn *k = dead;
			dead = k->next_dead;
			free_conn(k);
		}
	}
}
