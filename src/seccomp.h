/* void-hardened: генератор фильтров seccomp-BPF (seccomp.c). */
#ifndef VH_SECCOMP_H
#define VH_SECCOMP_H

#include <stddef.h>
#include <stdint.h>

/* инструкция classic BPF в формате ядра (struct sock_filter) */
struct bpf_ins {
	uint16_t code;
	uint8_t jt, jf;
	uint32_t k;
};

#define SECCOMP_MAX_INS 256

/* собрать фильтр: kind — "browser" или "viewer"; возвращает число инструкций, 0 — нет такого */
size_t seccomp_build(const char *kind, struct bpf_ins *out);
/* программа в байтах для bwrap --seccomp (8 байт на инструкцию, little-endian) */
size_t seccomp_bytes(const struct bpf_ins *prog, size_t n, unsigned char *out);
/* проверка обоих фильтров встроенным интерпретатором; возвращает число ошибок */
int seccomp_selftest(void);

#endif
