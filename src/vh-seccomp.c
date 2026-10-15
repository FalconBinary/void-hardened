/* vh-seccomp — фильтр seccomp-BPF для песочниц (docs/08, docs/13).
 *
 *   vh-seccomp browser > filter.bpf   — песочница браузера (browser-sandbox)
 *   vh-seccomp viewer  > filter.bpf   — просмотрщики (vh-open, optional/viewers)
 *   vh-seccomp --selftest
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "seccomp.h"
#include "vh.h"

int main(int argc, char **argv)
{
	vh_prog = "vh-seccomp";
	const char *kind = argc > 1 ? argv[1] : "";
	if (strcmp(kind, "--selftest") == 0)
		return seccomp_selftest() ? 1 : 0;
	struct bpf_ins prog[SECCOMP_MAX_INS];
	size_t n = seccomp_build(kind, prog);
	if (!n) {
		fputs("vh-seccomp browser|viewer > filter.bpf | --selftest\n", stderr);
		return 2;
	}
	unsigned char out[SECCOMP_MAX_INS * 8];
	size_t len = seccomp_bytes(prog, n, out);
	if (fwrite(out, 1, len, stdout) != len || fflush(stdout) != 0)
		die("запись: ошибка вывода");
	return 0;
}
