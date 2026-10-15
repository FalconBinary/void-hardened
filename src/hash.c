/* void-hardened: SHA-256 (FIPS 180-4) и BLAKE2b-512 (RFC 7693).
 * Проверяются тестовыми векторами в tests/c/run.sh против hashlib. */
#include "hash.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* ---------------------------------------------------------------- SHA-256 */
static const uint32_t K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror32(uint32_t x, int n) { return x >> n | x << (32 - n); }

static void sha256_block(struct sha256 *c, const unsigned char *p)
{
	uint32_t w[64], a, b, d, e, f, g, h, cc, t1, t2;
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (int i = 0; i < 64; i++) {
		t1 = h + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
		t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

void sha256_init(struct sha256 *c)
{
	static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
				       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	memcpy(c->h, iv, sizeof(iv));
	c->len = 0;
	c->n = 0;
}

void sha256_update(struct sha256 *c, const void *data, size_t len)
{
	const unsigned char *p = data;
	c->len += len;
	while (len) {
		size_t k = 64 - c->n < len ? 64 - c->n : len;
		memcpy(c->blk + c->n, p, k);
		c->n += k;
		p += k;
		len -= k;
		if (c->n == 64) {
			sha256_block(c, c->blk);
			c->n = 0;
		}
	}
}

void sha256_final(struct sha256 *c, unsigned char out[32])
{
	uint64_t bits = c->len * 8;
	unsigned char pad = 0x80, zero = 0;
	sha256_update(c, &pad, 1);
	while (c->n != 56)
		sha256_update(c, &zero, 1);
	unsigned char l[8];
	for (int i = 0; i < 8; i++)
		l[i] = (unsigned char)(bits >> (56 - 8 * i));
	sha256_update(c, l, 8);
	for (int i = 0; i < 8; i++)
		for (int b = 0; b < 4; b++)
			out[4 * i + b] = (unsigned char)(c->h[i] >> (24 - 8 * b));
}

/* ---------------------------------------------------------------- BLAKE2b */
static const uint64_t B2IV[8] = {
	0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
	0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};

static const uint8_t SIGMA[12][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static uint64_t ror64(uint64_t x, int n) { return x >> n | x << (64 - n); }

#define G(a, b, c, d, x, y) do { \
	v[a] = v[a] + v[b] + (x); v[d] = ror64(v[d] ^ v[a], 32); \
	v[c] = v[c] + v[d];       v[b] = ror64(v[b] ^ v[c], 24); \
	v[a] = v[a] + v[b] + (y); v[d] = ror64(v[d] ^ v[a], 16); \
	v[c] = v[c] + v[d];       v[b] = ror64(v[b] ^ v[c], 63); \
} while (0)

static void blake2b_compress(struct blake2b *c, const unsigned char *p, int last)
{
	uint64_t m[16], v[16];
	for (int i = 0; i < 16; i++) {
		m[i] = 0;
		for (int b = 0; b < 8; b++)
			m[i] |= (uint64_t)p[8 * i + b] << (8 * b);
	}
	for (int i = 0; i < 8; i++) {
		v[i] = c->h[i];
		v[i + 8] = B2IV[i];
	}
	v[12] ^= c->t[0];
	v[13] ^= c->t[1];
	if (last)
		v[14] = ~v[14];
	for (int r = 0; r < 12; r++) {
		const uint8_t *s = SIGMA[r];
		G(0, 4, 8, 12, m[s[0]], m[s[1]]);
		G(1, 5, 9, 13, m[s[2]], m[s[3]]);
		G(2, 6, 10, 14, m[s[4]], m[s[5]]);
		G(3, 7, 11, 15, m[s[6]], m[s[7]]);
		G(0, 5, 10, 15, m[s[8]], m[s[9]]);
		G(1, 6, 11, 12, m[s[10]], m[s[11]]);
		G(2, 7, 8, 13, m[s[12]], m[s[13]]);
		G(3, 4, 9, 14, m[s[14]], m[s[15]]);
	}
	for (int i = 0; i < 8; i++)
		c->h[i] ^= v[i] ^ v[i + 8];
}

void blake2b_init(struct blake2b *c)
{
	memcpy(c->h, B2IV, sizeof(B2IV));
	c->h[0] ^= 0x01010000ull ^ 64;   /* fanout 1, depth 1, без ключа, 64 байта */
	c->t[0] = c->t[1] = 0;
	c->n = 0;
}

void blake2b_update(struct blake2b *c, const void *data, size_t len)
{
	const unsigned char *p = data;
	while (len) {
		if (c->n == 128) {           /* полный блок сжимаем, только если за ним есть данные */
			c->t[0] += 128;
			if (c->t[0] < 128)
				c->t[1]++;
			blake2b_compress(c, c->blk, 0);
			c->n = 0;
		}
		size_t k = 128 - c->n < len ? 128 - c->n : len;
		memcpy(c->blk + c->n, p, k);
		c->n += k;
		p += k;
		len -= k;
	}
}

void blake2b_final(struct blake2b *c, unsigned char out[64])
{
	c->t[0] += c->n;
	if (c->t[0] < c->n)
		c->t[1]++;
	memset(c->blk + c->n, 0, 128 - c->n);
	blake2b_compress(c, c->blk, 1);
	for (int i = 0; i < 64; i++)
		out[i] = (unsigned char)(c->h[i / 8] >> (8 * (i % 8)));
}

/* ---------------------------------------------------------------- обёртки */
void hex(const unsigned char *d, size_t n, char *out)
{
	static const char x[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[2 * i] = x[d[i] >> 4];
		out[2 * i + 1] = x[d[i] & 15];
	}
	out[2 * n] = 0;
}

void sha256_hex(const void *data, size_t len, char out[65])
{
	struct sha256 c;
	unsigned char d[32];
	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, d);
	hex(d, 32, out);
}

void blake2b_hex(const void *data, size_t len, char out[129])
{
	struct blake2b c;
	unsigned char d[64];
	blake2b_init(&c);
	blake2b_update(&c, data, len);
	blake2b_final(&c, d);
	hex(d, 64, out);
}

static int hash_fd(const char *path, void (*upd)(void *, const void *, size_t), void *ctx)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	static unsigned char b[1 << 20];
	for (;;) {
		ssize_t r = read(fd, b, sizeof(b));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			close(fd);
			errno = e;
			return -1;
		}
		if (r == 0)
			break;
		upd(ctx, b, (size_t)r);
	}
	close(fd);
	return 0;
}

static void sha_upd(void *c, const void *d, size_t n) { sha256_update(c, d, n); }
static void b2_upd(void *c, const void *d, size_t n) { blake2b_update(c, d, n); }

int sha256_file(const char *path, char out[65])
{
	struct sha256 c;
	unsigned char d[32];
	sha256_init(&c);
	if (hash_fd(path, sha_upd, &c) != 0)
		return -1;
	sha256_final(&c, d);
	hex(d, 32, out);
	return 0;
}

int blake2b_file(const char *path, char out[129])
{
	struct blake2b c;
	unsigned char d[64];
	blake2b_init(&c);
	if (hash_fd(path, b2_upd, &c) != 0)
		return -1;
	blake2b_final(&c, d);
	hex(d, 64, out);
	return 0;
}
