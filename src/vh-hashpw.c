/* vh-hashpw — хэш пароля yescrypt через libcrypt (libxcrypt) — только для автотестов в VM.
 * chpasswd из shadow 4.8.1 не умеет yescrypt.
 *   printf '%s' ПАРОЛЬ | vh-hashpw [cost]  → $y$...
 * На реальной машине пароли задаются интерактивно командой passwd. */
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vh.h"

int main(int argc, char **argv)
{
	vh_prog = "vh-hashpw";
	long cost = argc > 1 ? strtol(argv[1], NULL, 10) : 7;
	char pw[1024];
	size_t n = fread(pw, 1, sizeof(pw) - 1, stdin);
	pw[n] = 0;
	const char *salt = crypt_gensalt("$y$", (unsigned long)cost, NULL, 0);
	const char *h = salt ? crypt(pw, salt) : NULL;
	explicit_bzero(pw, sizeof(pw));
	if (!h || strncmp(h, "$y$", 3) != 0)
		die("libcrypt не вернул yescrypt");
	puts(h);
	return 0;
}
