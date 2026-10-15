/* void-hardened: общие функции инструментов на C (src/README.md).
 * Только libc: строки, файлы, конфиги KEY=VALUE и запуск программ без шелла. */
#ifndef VH_H
#define VH_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define VH_PRINTF(a, b) __attribute__((format(printf, a, b)))

/* имя программы для сообщений: «vh-pkg: …» */
extern const char *vh_prog;

_Noreturn void die(const char *fmt, ...) VH_PRINTF(1, 2);
void warnmsg(const char *fmt, ...) VH_PRINTF(1, 2);   /* в stderr с префиксом */
void logmsg(const char *fmt, ...) VH_PRINTF(1, 2);    /* в stdout с префиксом (журнал сервиса) */

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *xasprintf(const char *fmt, ...) VH_PRINTF(1, 2);

/* растущий буфер; p всегда завершён нулём (данные могут содержать нули) */
struct buf {
	char *p;
	size_t len, cap;
};
void buf_add(struct buf *b, const void *d, size_t n);
void buf_adds(struct buf *b, const char *s);
void buf_addf(struct buf *b, const char *fmt, ...) VH_PRINTF(2, 3);
void buf_reserve(struct buf *b, size_t n);
void buf_free(struct buf *b);

/* список строк */
struct strv {
	char **v;
	size_t n, cap;
};
void strv_add(struct strv *s, const char *str);       /* копия */
void strv_take(struct strv *s, char *str);            /* без копии */
bool strv_has(const struct strv *s, const char *str);
void strv_sort(struct strv *s);
void strv_free(struct strv *s);
char *strv_join(const struct strv *s, const char *sep);

bool startswith(const char *s, const char *prefix);
bool endswith(const char *s, const char *suffix);
char *strip(char *s);                                  /* пробелы с краёв, на месте */
bool is_space(int c);

/* весь файл в память (+ завершающий ноль); NULL и errno при ошибке */
char *read_file(const char *path, size_t *len);
/* файл sysfs/proc одной строкой без пробелов по краям; "" при ошибке */
const char *rd(const char *path, char *out, size_t sz);
/* запись строки в файл (sysfs); false при ошибке, errno сохраняется */
bool write_str(const char *path, const char *s);
/* атомарная замена: path.new → fsync → rename */
void write_atomic(const char *path, const void *data, size_t len, mode_t mode);
bool path_exists(const char *path);                    /* lexists: и битый симлинк */
bool is_regular(const char *path);                     /* по симлинку, как os.path.isfile */
bool is_dir(const char *path);
void mkdirs(const char *path, mode_t mode);            /* как mkdir -p */

/* конфиги KEY=VALUE. KV_INLINE: «#» до конца строки — комментарий;
 * без него комментарий — только строка, начинающаяся с «#». Кавычки " снимаются. */
enum { KV_INLINE = 1 };
struct kvs {
	char **k, **v;
	size_t n;
};
void kv_read(struct kvs *c, const char *path, int flags);
void kv_set(struct kvs *c, const char *k, const char *v);
const char *kv_get(const struct kvs *c, const char *k, const char *def);
long kv_int(const struct kvs *c, const char *k, const char *def);  /* die при мусоре */

/* Запуск программы без шелла (execvp, PATH процесса).
 * in != NULL — передать на stdin; out/err != NULL — собрать вывод, иначе наследовать.
 * Возвращает код выхода, 128+сигнал или 127, если программа не запустилась. */
int run(char *const argv[], const void *in, size_t inlen, struct buf *out, struct buf *err);
#define RUN(...) run((char *const[]){__VA_ARGS__, NULL}, NULL, 0, NULL, NULL)

/* вопрос [y/N]: true на y, yes, д, да (любой регистр); yes — не спрашивать */
bool ask(const char *question, bool yes);

/* закрыть все fd ≥ from (перед exec программы с меньшими правами) */
void close_fds_from(int from);

#endif
