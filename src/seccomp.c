/* void-hardened: генератор фильтров seccomp-BPF для песочниц (docs/08, docs/13).
 *
 * Программа classic BPF собирается здесь и передаётся в bwrap --seccomp FD. Фильтр
 * применяется после сборки песочницы, наследуется всеми потомками и не снимается.
 *
 * Порядок инструкций — ради кэша seccomp ядра: сначала архитектура и бит x32, затем
 * вызовы с проверкой аргументов и запрещённые, всё прочее — безусловный ALLOW без
 * чтения аргументов: такие вызовы ядро кэширует и BPF для них не запускает.
 * Переходы задаются метками и считаются ассемблером; seccomp_selftest() прогоняет оба
 * фильтра через встроенный интерпретатор BPF на наборе вызовов с ожидаемым результатом. */
#include "seccomp.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "vh.h"

#define AUDIT_ARCH_X86_64 0xC000003Eu
#define X32_BIT 0x40000000u
#define RET_ALLOW 0x7FFF0000u
#define RET_KILL 0x80000000u
#define ERRNO(e) (0x00050000u | (e))
#define EPERM_ 1u
#define ENOSYS_ 38u
#define EAFNOSUPPORT_ 97u

/* номера системных вызовов x86_64 */
enum {
	NR_read = 0, NR_write = 1, NR_mmap = 9, NR_socket = 41, NR_socketpair = 53,
	NR_setsockopt = 54, NR_clone = 56, NR_ptrace = 101, NR_syslog = 103,
	NR_personality = 135, NR_vhangup = 153, NR_modify_ldt = 154, NR_pivot_root = 155,
	NR_chroot = 161, NR_acct = 163, NR_mount = 165, NR_umount2 = 166, NR_swapon = 167,
	NR_swapoff = 168, NR_iopl = 172, NR_ioperm = 173, NR_init_module = 175,
	NR_delete_module = 176, NR_quotactl = 179, NR_kexec_load = 246, NR_add_key = 248,
	NR_request_key = 249, NR_keyctl = 250, NR_unshare = 272, NR_perf_event_open = 298,
	NR_open_by_handle_at = 304, NR_setns = 308, NR_process_vm_readv = 310,
	NR_process_vm_writev = 311, NR_finit_module = 313, NR_kexec_file_load = 320,
	NR_bpf = 321, NR_userfaultfd = 323, NR_io_uring_setup = 425, NR_io_uring_enter = 426,
	NR_io_uring_register = 427, NR_open_tree = 428, NR_move_mount = 429, NR_fsopen = 430,
	NR_fsconfig = 431, NR_fsmount = 432, NR_fspick = 433, NR_clone3 = 435,
	NR_mount_setattr = 442,
};

#define CLONE_NEW_MASK 0x7E020000u   /* NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET */
#define AF_UNIX_ 1u
#define AF_INET_ 2u
#define AF_INET6_ 10u
#define AF_NETLINK_ 16u
#define IPPROTO_TCP_ 6u
#define IPPROTO_UDP_ 17u
#define NETLINK_ROUTE_ 0u
#define SOL_SOCKET_ 1u
#define SOL_TCP_ 6u
#define TCP_ULP_ 31u                  /* kTLS и прочие ULP — поверхность ядра */
#define SO_ATTACH_FILTER_ 26u
#define SO_ATTACH_BPF_ 50u
#define SO_ATTACH_REUSEPORT_CBPF_ 51u /* cBPF/eBPF на сокете без привилегий */
#define SO_ATTACH_REUSEPORT_EBPF_ 52u

static const unsigned deny_common[] = {
	NR_perf_event_open, NR_bpf, NR_userfaultfd, NR_add_key, NR_request_key, NR_keyctl,
	NR_kexec_load, NR_kexec_file_load, NR_io_uring_setup, NR_io_uring_enter,
	NR_io_uring_register, NR_modify_ldt, NR_mount, NR_umount2, NR_pivot_root, NR_fsopen,
	NR_fsconfig, NR_fsmount, NR_fspick, NR_move_mount, NR_open_tree, NR_mount_setattr,
	NR_ptrace, NR_process_vm_readv, NR_process_vm_writev, NR_init_module, NR_finit_module,
	NR_delete_module, NR_iopl, NR_ioperm, NR_open_by_handle_at, NR_chroot, NR_acct,
	NR_swapon, NR_swapoff, NR_syslog, NR_vhangup, NR_quotactl, NR_unshare, NR_setns,
};

#define LD 0x20
#define JEQ 0x15
#define JGE 0x35
#define JSET 0x45
#define RET 0x06

/* метки; L_NEXT — «следующая инструкция» */
enum { L_NEXT, L_KILL, L_ENOSYS, L_EPERM, L_EAFNO, L_ALLOW, L_DENY, L_C3, L_SP, L_T,
       L_INET, L_NL, L_SO, L_SOL, L_MAX };

/* мини-ассемблер classic BPF: переходы — по меткам */
struct as {
	struct { uint16_t op; int jt, jf; uint32_t k; } code[SECCOMP_MAX_INS];
	size_t n;
	int labels[L_MAX];
};

static void emit(struct as *a, uint16_t op, uint32_t k, int jt, int jf)
{
	if (a->n >= SECCOMP_MAX_INS)
		die("seccomp: слишком длинная программа");
	a->code[a->n].op = op;
	a->code[a->n].k = k;
	a->code[a->n].jt = jt;
	a->code[a->n].jf = jf;
	a->n++;
}

static void label(struct as *a, int l) { a->labels[l] = (int)a->n; }
static void ld_nr(struct as *a) { emit(a, LD, 0, L_NEXT, L_NEXT); }
static void ld_arch(struct as *a) { emit(a, LD, 4, L_NEXT, L_NEXT); }
static void ld_arg(struct as *a, int i) { emit(a, LD, 16 + 8 * (uint32_t)i, L_NEXT, L_NEXT); } /* младшие 32 бита args[i] */
static void jmp(struct as *a, uint16_t op, uint32_t k, int jt, int jf) { emit(a, op, k, jt, jf); }
static void ret(struct as *a, uint32_t k) { emit(a, RET, k, L_NEXT, L_NEXT); }

static uint8_t off(const struct as *a, size_t i, int l)
{
	if (l == L_NEXT)
		return 0;
	int d = a->labels[l] - (int)i - 1;
	if (a->labels[l] < 0 || d < 0 || d > 255)
		die("seccomp: переход к метке %d из %zu: %d", l, i, d);
	return (uint8_t)d;
}

static size_t assemble(const struct as *a, struct bpf_ins *out)
{
	for (size_t i = 0; i < a->n; i++) {
		out[i].code = a->code[i].op;
		out[i].jt = off(a, i, a->code[i].jt);
		out[i].jf = off(a, i, a->code[i].jf);
		out[i].k = a->code[i].k;
	}
	return a->n;
}

static void as_init(struct as *a)
{
	memset(a, 0, sizeof(*a));
	for (int i = 0; i < L_MAX; i++)
		a->labels[i] = -1;
}

static void header(struct as *a)
{
	ld_arch(a);
	jmp(a, JEQ, AUDIT_ARCH_X86_64, L_NEXT, L_KILL);
	ld_nr(a);
	jmp(a, JGE, X32_BIT, L_ENOSYS, L_NEXT);
}

static void tail(struct as *a, bool allow_ptrace)
{
	/* clone: без флагов CLONE_NEW* (новые namespace) */
	jmp(a, JEQ, NR_clone, L_NEXT, L_C3);
	ld_arg(a, 0);
	jmp(a, JSET, CLONE_NEW_MASK, L_EPERM, L_ALLOW);
	/* clone3: флаги в структуре по указателю — BPF их не видит. ENOSYS: glibc откатится на clone */
	label(a, L_C3);
	jmp(a, JEQ, NR_clone3, L_ENOSYS, L_NEXT);
	/* personality: только 0 и запрос текущего значения (READ_IMPLIES_EXEC, ADDR_NO_RANDOMIZE — нет) */
	jmp(a, JEQ, NR_personality, L_NEXT, L_DENY);
	ld_arg(a, 0);
	jmp(a, JEQ, 0, L_ALLOW, L_NEXT);
	jmp(a, JEQ, 0xFFFFFFFFu, L_ALLOW, L_EPERM);
	label(a, L_DENY);
	for (size_t i = 0; i < sizeof(deny_common) / sizeof(deny_common[0]); i++) {
		/* ptrace Firefox нужен для своих процессов (профилировщик, отчёты о зависаниях) */
		if (allow_ptrace && deny_common[i] == NR_ptrace)
			continue;
		jmp(a, JEQ, deny_common[i], L_EPERM, L_NEXT);
	}
	label(a, L_ALLOW);
	ret(a, RET_ALLOW);
	label(a, L_EPERM);
	ret(a, ERRNO(EPERM_));
	label(a, L_ENOSYS);
	ret(a, ERRNO(ENOSYS_));
	label(a, L_EAFNO);
	ret(a, ERRNO(EAFNOSUPPORT_));
	label(a, L_KILL);
	ret(a, RET_KILL);
}

static void socketpair_unix(struct as *a, int nxt)
{
	jmp(a, JEQ, NR_socketpair, L_NEXT, nxt);
	ld_arg(a, 0);
	jmp(a, JEQ, AF_UNIX_, L_ALLOW, L_EAFNO);
}

static size_t viewer(struct bpf_ins *out)
{
	struct as a;
	as_init(&a);
	header(&a);
	jmp(&a, JEQ, NR_socket, L_NEXT, L_SP);
	ld_arg(&a, 0);
	jmp(&a, JEQ, AF_UNIX_, L_ALLOW, L_EAFNO);
	label(&a, L_SP);
	socketpair_unix(&a, L_T);
	label(&a, L_T);
	tail(&a, false);
	return assemble(&a, out);
}

/* AF_UNIX; AF_INET/INET6 только TCP и UDP (закрывает MPTCP, SCTP, UDP-Lite, сырые);
 * AF_NETLINK только NETLINK_ROUTE (без NETLINK_NETFILTER — nf_tables, класс
 * CVE-2024-1086); socketpair — AF_UNIX; setsockopt без TCP_ULP и BPF на сокете. */
static size_t browser(struct bpf_ins *out)
{
	struct as a;
	as_init(&a);
	header(&a);
	jmp(&a, JEQ, NR_socket, L_NEXT, L_SP);
	ld_arg(&a, 0);
	jmp(&a, JEQ, AF_UNIX_, L_ALLOW, L_NEXT);
	jmp(&a, JEQ, AF_INET_, L_INET, L_NEXT);
	jmp(&a, JEQ, AF_INET6_, L_INET, L_NEXT);
	jmp(&a, JEQ, AF_NETLINK_, L_NL, L_EAFNO);
	label(&a, L_INET);
	ld_arg(&a, 2);
	jmp(&a, JEQ, 0, L_ALLOW, L_NEXT);
	jmp(&a, JEQ, IPPROTO_TCP_, L_ALLOW, L_NEXT);
	jmp(&a, JEQ, IPPROTO_UDP_, L_ALLOW, L_EAFNO);
	label(&a, L_NL);
	ld_arg(&a, 2);
	jmp(&a, JEQ, NETLINK_ROUTE_, L_ALLOW, L_EAFNO);
	label(&a, L_SP);
	socketpair_unix(&a, L_SO);
	label(&a, L_SO);
	jmp(&a, JEQ, NR_setsockopt, L_NEXT, L_T);
	ld_arg(&a, 1);
	jmp(&a, JEQ, SOL_TCP_, L_NEXT, L_SOL);
	ld_arg(&a, 2);
	jmp(&a, JEQ, TCP_ULP_, L_EPERM, L_ALLOW);
	label(&a, L_SOL);
	jmp(&a, JEQ, SOL_SOCKET_, L_NEXT, L_ALLOW);
	ld_arg(&a, 2);
	jmp(&a, JEQ, SO_ATTACH_FILTER_, L_EPERM, L_NEXT);
	jmp(&a, JEQ, SO_ATTACH_BPF_, L_EPERM, L_NEXT);
	jmp(&a, JEQ, SO_ATTACH_REUSEPORT_CBPF_, L_EPERM, L_NEXT);
	jmp(&a, JEQ, SO_ATTACH_REUSEPORT_EBPF_, L_EPERM, L_ALLOW);
	label(&a, L_T);
	tail(&a, true);
	return assemble(&a, out);
}

size_t seccomp_build(const char *kind, struct bpf_ins *out)
{
	if (strcmp(kind, "browser") == 0)
		return browser(out);
	if (strcmp(kind, "viewer") == 0)
		return viewer(out);
	return 0;
}

size_t seccomp_bytes(const struct bpf_ins *prog, size_t n, unsigned char *out)
{
	for (size_t i = 0; i < n; i++) {
		unsigned char *p = out + 8 * i;
		p[0] = (unsigned char)(prog[i].code & 0xFF);
		p[1] = (unsigned char)(prog[i].code >> 8);
		p[2] = prog[i].jt;
		p[3] = prog[i].jf;
		for (int b = 0; b < 4; b++)
			p[4 + b] = (unsigned char)(prog[i].k >> (8 * b));
	}
	return 8 * n;
}

/* интерпретатор classic BPF для проверки фильтра (только используемые инструкции);
 * данные — struct seccomp_data: nr, arch, ip, args[6] */
static uint32_t run_bpf(const struct bpf_ins *prog, size_t n, uint32_t nr, const uint64_t args[6],
			uint32_t arch)
{
	unsigned char data[64] = {0};
	for (int b = 0; b < 4; b++) {
		data[b] = (unsigned char)(nr >> (8 * b));
		data[4 + b] = (unsigned char)(arch >> (8 * b));
	}
	for (int i = 0; i < 6; i++)
		for (int b = 0; b < 8; b++)
			data[16 + 8 * i + b] = (unsigned char)(args[i] >> (8 * b));
	size_t pc = 0;
	uint32_t acc = 0;
	for (;;) {
		if (pc >= n)
			die("seccomp: выход за конец программы");
		const struct bpf_ins *in = &prog[pc];
		if (in->code == LD) {
			if (in->k > sizeof(data) - 4)
				die("seccomp: чтение за пределами seccomp_data");
			acc = (uint32_t)data[in->k] | (uint32_t)data[in->k + 1] << 8 |
			      (uint32_t)data[in->k + 2] << 16 | (uint32_t)data[in->k + 3] << 24;
			pc++;
		} else if (in->code == RET) {
			return in->k;
		} else {
			bool cond = in->code == JEQ ? acc == in->k :
				    in->code == JGE ? acc >= in->k : (acc & in->k) != 0;
			pc += 1 + (cond ? in->jt : in->jf);
		}
	}
}

struct tcase {
	const char *name;
	uint32_t nr;
	uint64_t args[3];
	uint32_t want;
};

#define A RET_ALLOW
#define P ERRNO(EPERM_)
#define N ERRNO(ENOSYS_)
#define F ERRNO(EAFNOSUPPORT_)

static const struct tcase browser_cases[] = {
	{"socket(AF_UNIX)", NR_socket, {AF_UNIX_, 1, 0}, A},
	{"socket(AF_INET, TCP)", NR_socket, {AF_INET_, 1, IPPROTO_TCP_}, A},
	{"socket(AF_INET, 0)", NR_socket, {AF_INET_, 2, 0}, A},
	{"socket(AF_INET6, UDP)", NR_socket, {AF_INET6_, 2, IPPROTO_UDP_}, A},
	{"socket(AF_INET, MPTCP)", NR_socket, {AF_INET_, 1, 262}, F},
	{"socket(AF_INET, SCTP)", NR_socket, {AF_INET_, 1, 132}, F},
	{"socket(AF_NETLINK, ROUTE)", NR_socket, {AF_NETLINK_, 3, NETLINK_ROUTE_}, A},
	{"socket(AF_NETLINK, NETFILTER)", NR_socket, {AF_NETLINK_, 3, 12}, F},
	{"socket(AF_PACKET)", NR_socket, {17, 3, 0}, F},
	{"socket(AF_ALG)", NR_socket, {38, 5, 0}, F},
	{"socketpair(AF_UNIX)", NR_socketpair, {AF_UNIX_, 1, 0}, A},
	{"socketpair(AF_INET)", NR_socketpair, {AF_INET_, 1, 0}, F},
	{"setsockopt(SOL_TCP, TCP_NODELAY)", NR_setsockopt, {3, SOL_TCP_, 1}, A},
	{"setsockopt(SOL_TCP, TCP_ULP)", NR_setsockopt, {3, SOL_TCP_, TCP_ULP_}, P},
	{"setsockopt(SOL_SOCKET, SO_RCVBUF)", NR_setsockopt, {3, SOL_SOCKET_, 8}, A},
	{"setsockopt(SO_ATTACH_FILTER)", NR_setsockopt, {3, SOL_SOCKET_, 26}, P},
	{"setsockopt(SO_ATTACH_BPF)", NR_setsockopt, {3, SOL_SOCKET_, 50}, P},
	{"setsockopt(SO_ATTACH_REUSEPORT_CBPF)", NR_setsockopt, {3, SOL_SOCKET_, 51}, P},
	{"setsockopt(SO_ATTACH_REUSEPORT_EBPF)", NR_setsockopt, {3, SOL_SOCKET_, 52}, P},
	{"setsockopt(SO_DETACH_REUSEPORT_BPF 68)", NR_setsockopt, {3, SOL_SOCKET_, 68}, A},
	{"setsockopt(IPPROTO_IP)", NR_setsockopt, {3, 0, 1}, A},
	{"clone(обычный поток)", NR_clone, {0x3D0F00}, A},
	{"clone(CLONE_NEWUSER)", NR_clone, {0x10000000 | 17}, P},
	{"clone3", NR_clone3, {0}, N},
	{"personality(0)", NR_personality, {0}, A},
	{"personality(запрос)", NR_personality, {0xFFFFFFFF}, A},
	{"personality(READ_IMPLIES_EXEC)", NR_personality, {0x0400000}, P},
	{"ptrace", NR_ptrace, {0}, A},
	{"mount", NR_mount, {0}, P},
	{"unshare", NR_unshare, {0}, P},
	{"keyctl", NR_keyctl, {0}, P},
	{"bpf", NR_bpf, {0}, P},
	{"io_uring_setup", NR_io_uring_setup, {0}, P},
	{"perf_event_open", NR_perf_event_open, {0}, P},
	{"read", NR_read, {0}, A},
	{"mmap", NR_mmap, {0}, A},
	{"x32 read", X32_BIT | NR_read, {0}, N},
};

static const struct tcase viewer_cases[] = {
	{"socket(AF_UNIX)", NR_socket, {AF_UNIX_, 1, 0}, A},
	{"socket(AF_INET)", NR_socket, {AF_INET_, 1, 6}, F},
	{"socketpair(AF_UNIX)", NR_socketpair, {AF_UNIX_, 1, 0}, A},
	{"clone(CLONE_NEWNET)", NR_clone, {0x40000000 | 17}, P},
	{"clone3", NR_clone3, {0}, N},
	{"ptrace", NR_ptrace, {0}, P},
	{"setns", NR_setns, {0}, P},
	{"personality(ADDR_NO_RANDOMIZE)", NR_personality, {0x0040000}, P},
	{"write", NR_write, {0}, A},
};

int seccomp_selftest(void)
{
	static const struct {
		const char *kind;
		const struct tcase *cases;
		size_t n;
	} sets[] = {
		{"browser", browser_cases, sizeof(browser_cases) / sizeof(browser_cases[0])},
		{"viewer", viewer_cases, sizeof(viewer_cases) / sizeof(viewer_cases[0])},
	};
	int bad = 0;
	for (size_t s = 0; s < 2; s++) {
		struct bpf_ins prog[SECCOMP_MAX_INS];
		size_t n = seccomp_build(sets[s].kind, prog);
		const uint64_t zero[6] = {0};
		if (run_bpf(prog, n, 0, zero, 0x40000003u) != RET_KILL) {   /* i386 */
			printf("FAIL %s: чужая архитектура не убивается\n", sets[s].kind);
			bad++;
		}
		for (size_t i = 0; i < sets[s].n; i++) {
			const struct tcase *c = &sets[s].cases[i];
			uint64_t args[6] = {c->args[0], c->args[1], c->args[2], 0, 0, 0};
			uint32_t got = run_bpf(prog, n, c->nr, args, AUDIT_ARCH_X86_64);
			if (got != c->want) {
				printf("FAIL %s: %s: %#x, ожидалось %#x\n", sets[s].kind, c->name, got, c->want);
				bad++;
			}
		}
		printf("%s: %zu инструкций, %zu проверок\n", sets[s].kind, n, sets[s].n + 1);
	}
	if (bad)
		printf("selftest: ошибок %d\n", bad);
	else
		printf("selftest: OK\n");
	return bad;
}
