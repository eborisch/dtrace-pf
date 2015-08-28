/*-
 * Test 0034:	BPF_ALU+BPF_MUL+BPF_K
 *
 * $FreeBSD: release/10.1.0/tools/regression/bpf/bpf_filter/tests/test0034.h 182393 2008-08-28 18:38:55Z jkim $
 */

/* BPF program */
struct bpf_insn pc[] = {
	BPF_STMT(BPF_LD+BPF_IMM, 0xdead),
	BPF_STMT(BPF_ALU+BPF_MUL+BPF_K, 0xc0de),
	BPF_STMT(BPF_RET+BPF_A, 0),
};

/* Packet */
u_char	pkt[] = {
	0x00,
};

/* Packet length seen on wire */
u_int	wirelen =	sizeof(pkt);

/* Packet length passed on buffer */
u_int	buflen =	sizeof(pkt);

/* Invalid instruction */
int	invalid =	0;

/* Expected return value */
u_int	expect =	0xa7c2da06;

/* Expected signal */
int	expect_signal =	0;