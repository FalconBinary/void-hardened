/* void-hardened: SHA-256 и BLAKE2b-512 без внешних библиотек (hash.c). */
#ifndef VH_HASH_H
#define VH_HASH_H

#include <stddef.h>
#include <stdint.h>

struct sha256 {
	uint32_t h[8];
	uint64_t len;
	unsigned char blk[64];
	size_t n;
};
void sha256_init(struct sha256 *c);
void sha256_update(struct sha256 *c, const void *data, size_t len);
void sha256_final(struct sha256 *c, unsigned char out[32]);

struct blake2b {
	uint64_t h[8], t[2];
	unsigned char blk[128];
	size_t n;
};
void blake2b_init(struct blake2b *c);          /* 512 бит, без ключа — формат Limine */
void blake2b_update(struct blake2b *c, const void *data, size_t len);
void blake2b_final(struct blake2b *c, unsigned char out[64]);

/* hex в out (2*n+1 байт) */
void hex(const unsigned char *d, size_t n, char *out);
/* хэш файла в hex; 0 — успех, -1 и errno — ошибка чтения */
int sha256_file(const char *path, char out[65]);
int blake2b_file(const char *path, char out[129]);
void sha256_hex(const void *data, size_t len, char out[65]);
void blake2b_hex(const void *data, size_t len, char out[129]);

#endif
