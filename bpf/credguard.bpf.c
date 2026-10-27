// SPDX-License-Identifier: GPL-2.0
/*
 * CredGuard eBPF programs.
 *
 *  tcp_sendmsg (kprobe)   - MONITOR: every send to the metadata service
 *                           169.254.169.254 is captured with the sending
 *                           process + the first bytes of the HTTP request,
 *                           so user space can tell a harmless lookup from a
 *                           credential grab.
 *
 *  cgroup/connect4        - ENFORCE: when enforce mode is on, a connect() to
 *                           the metadata service from a non-allowlisted
 *                           process is denied in real time.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "../src/credguard.h"

char LICENSE[] SEC("license") = "GPL";

/* 169.254.169.254 in network byte order */
#define META_IP bpf_htonl(0xA9FEA9FE)

/* PID namespace of the user-space daemon (set from the skeleton before load).
 * On WSL and inside containers the kernel's global PID differs from the PID the
 * daemon sees in /proc, so we translate into the daemon's namespace. */
const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;

static __always_inline __u32 cur_tgid(void)
{
	if (pidns_dev && pidns_ino) {
		struct bpf_pidns_info ns = {};
		if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)) == 0)
			return ns.tgid;
	}
	return bpf_get_current_pid_tgid() >> 32;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* single-entry config: index 0 = enforce flag (0 monitor, 1 enforce) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cfg SEC(".maps");

/* comm -> 1 for processes allowed to reach the metadata service in enforce mode */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, __u8);
} allowlist SEC(".maps");

static __always_inline int enforce_on(void)
{
	__u32 k = 0, *v = bpf_map_lookup_elem(&cfg, &k);
	return v && *v;
}

static __always_inline int is_allowlisted(char *comm)
{
	__u8 *v = bpf_map_lookup_elem(&allowlist, comm);
	return v != 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(cg_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	if (daddr != META_IP)
		return 0;

	/* Only the outbound request to the service (port 80). This skips the
	 * service's own response packets, whose socket carries an ephemeral port. */
	__u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (dport != 80)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = cur_tgid();
	e->uid = bpf_get_current_uid_gid();
	e->daddr = daddr;
	e->dport = dport;
	e->action = ACT_OBSERVE;
	e->payload_len = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memset(e->payload, 0, sizeof(e->payload));

	/* Pull the first bytes of the request out of the msghdr iterator.
	 * The numeric value of ITER_UBUF can differ between kernel versions (it is
	 * 5 on 6.6), so resolve it with a CO-RE enum relocation, not a constant. */
	const void *base = NULL;
	__u8 itype = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (itype == bpf_core_enum_value(enum iter_type, ITER_UBUF))
		base = BPF_CORE_READ(msg, msg_iter.ubuf);
	else
		base = BPF_CORE_READ(msg, msg_iter.__iov, iov_base);

	if (base) {
		long n = bpf_probe_read_user(e->payload, sizeof(e->payload) - 1, base);
		if (n == 0)
			e->payload_len = sizeof(e->payload) - 1;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_ip4 != META_IP)
		return 1; /* not metadata traffic: allow */

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	if (is_allowlisted(comm))
		return 1; /* trusted caller (e.g. aws cli): allow */

	if (!enforce_on())
		return 1; /* monitor mode: let tcp_sendmsg produce the alert */

	/* enforce mode: report the block and deny the connection */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		/* bpf_get_ns_current_pid_tgid is not available in this program type,
		 * so use the raw tgid here; user space still has the comm for context. */
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->uid = bpf_get_current_uid_gid();
		e->daddr = ctx->user_ip4;
		e->dport = bpf_ntohs(ctx->user_port);
		e->action = ACT_BLOCKED;
		e->payload_len = 0;
		__builtin_memcpy(e->comm, comm, sizeof(e->comm));
		__builtin_memset(e->payload, 0, sizeof(e->payload));
		bpf_ringbuf_submit(e, 0);
	}
	return 0; /* deny */
}
