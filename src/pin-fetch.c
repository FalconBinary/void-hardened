/* pin-fetch — корневой сертификат УЦ сервера TLS для пиннинга (optional/dns-pin, docs/13).
 *
 *   pin-fetch АДРЕС ПОРТ ИМЯ [ALPN]   → PEM корня цепочки на stdout, сводка на stderr
 *
 * Цепочка проверяется системным хранилищем УЦ и именем сервера; в пин берётся её корень
 * (якорь доверия): смена промежуточного сертификата у провайдера пин не ломает, а любой
 * другой из ~150 корневых УЦ перестаёт подходить. Запускается от пользователя сервиса
 * (_unbound, chrony), которому файрвол и так разрешает этот порт.
 */
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "hash.h"
#include "vh.h"

#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define TIMEOUT 15

static _Noreturn void tls_die(const char *what)
{
	unsigned long e = ERR_get_error();
	die("%s: %s", what, e ? ERR_reason_error_string(e) : "ошибка TLS");
}

static int connect_to(const char *addr, const char *port)
{
	struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICSERV}, *res;
	int r = getaddrinfo(addr, port, &hints, &res);
	if (r)
		die("%s: %s", addr, gai_strerror(r));
	int fd = -1;
	for (struct addrinfo *a = res; a; a = a->ai_next) {
		fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
		if (fd < 0)
			continue;
		struct timeval tv = {.tv_sec = TIMEOUT};
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));   /* и для connect */
		if (connect(fd, a->ai_addr, a->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0)
		die("%s:%s: нет соединения", addr, port);
	return fd;
}

int main(int argc, char **argv)
{
	vh_prog = "pin-fetch";
	if (argc != 4 && argc != 5) {
		fputs("pin-fetch АДРЕС ПОРТ ИМЯ [ALPN]\n", stderr);
		return 2;
	}
	const char *addr = argv[1], *port = argv[2], *name = argv[3], *alpn = argc > 4 ? argv[4] : NULL;
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
	    SSL_CTX_load_verify_locations(ctx, CAFILE, NULL) != 1)
		tls_die("контекст TLS");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL *ssl = SSL_new(ctx);
	if (!ssl || !SSL_set_tlsext_host_name(ssl, name) || !SSL_set1_host(ssl, name))
		tls_die("имя сервера");
	if (alpn) {
		size_t l = strlen(alpn);
		if (l == 0 || l > 255)
			die("ALPN: неверная длина");
		unsigned char proto[256];
		proto[0] = (unsigned char)l;
		memcpy(proto + 1, alpn, l);
		if (SSL_set_alpn_protos(ssl, proto, (unsigned)l + 1) != 0)
			tls_die("ALPN");
	}
	int fd = connect_to(addr, port);
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) != 1 || SSL_get_verify_result(ssl) != X509_V_OK)
		tls_die("рукопожатие TLS (цепочка или имя не проверены)");
	STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
	int n = chain ? sk_X509_num(chain) : 0;
	if (n < 1)
		die("нет проверенной цепочки");
	X509 *root = sk_X509_value(chain, n - 1);
	unsigned char *der = NULL;
	int dl = i2d_X509(root, &der);
	if (dl <= 0)
		tls_die("DER");
	char h[65];
	sha256_hex(der, (size_t)dl, h);
	fprintf(stderr, "%s (%s:%s): цепочка %d серт., корень SHA256 ", name, addr, port, n);
	for (int i = 0; i < 32; i++)
		fprintf(stderr, "%s%c%c", i ? ":" : "", h[2 * i] - (h[2 * i] >= 'a' ? 32 : 0),
			h[2 * i + 1] - (h[2 * i + 1] >= 'a' ? 32 : 0));
	fputc('\n', stderr);
	if (!PEM_write_X509(stdout, root) || fflush(stdout) != 0)
		die("запись PEM");
	OPENSSL_free(der);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(fd);
	return 0;
}
