// SPDX-License-Identifier: GPL-2.0
/*
 * CredGuard user-space daemon.
 *
 *  - loads and attaches the eBPF programs (bpf/credguard.bpf.c)
 *  - reads events from the ring buffer
 *  - classifies each metadata access (harmless lookup vs credential grab)
 *  - resolves the process executable path and applies a path allowlist
 *  - prints a structured JSON alert per event
 *
 * Usage: sudo ./credguard [--enforce] [--cgroup /sys/fs/cgroup]
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "credguard.h"
#include "credguard.skel.h"

/* Executables trusted to reach the metadata service (matched by real path). */
static const char *ALLOW_PATHS[] = {
	"/usr/bin/aws",
	"/usr/bin/amazon-ssm-agent",
	"/usr/bin/cloudwatch-agent",
};
/* comm names mirrored into the kernel allowlist used by the enforce hook. */
static const char *ALLOW_COMMS[] = { "aws", "amazon-ssm-agen", "cloudwatch-agen" };

static volatile sig_atomic_t stop;
static void on_sigint(int s) { (void)s; stop = 1; }

static const char *IAM_CREDS = "security-credentials/";

/* Pull the request line / path out of the captured HTTP bytes (best effort). */
static void http_path(const char *buf, int len, char *out, int outsz)
{
	out[0] = '\0';
	/* find first space (after the method), copy until the next space */
	int i = 0;
	while (i < len && buf[i] != ' ' && buf[i] != '\0') i++;
	if (i >= len) return;
	i++;
	int j = 0;
	while (i < len && buf[i] != ' ' && buf[i] != '\r' && buf[i] != '\0' && j < outsz - 1)
		out[j++] = buf[i++];
	out[j] = '\0';
}

/* Resolve /proc/<pid>/exe to the real executable path. */
static void exe_path(unsigned pid, char *out, int outsz)
{
	char link[64];
	snprintf(link, sizeof(link), "/proc/%u/exe", pid);
	ssize_t n = readlink(link, out, outsz - 1);
	if (n < 0) { snprintf(out, outsz, "(exited)"); return; }
	out[n] = '\0';
}

static int path_allowlisted(const char *exe)
{
	for (size_t i = 0; i < sizeof(ALLOW_PATHS) / sizeof(ALLOW_PATHS[0]); i++)
		if (strcmp(exe, ALLOW_PATHS[i]) == 0)
			return 1;
	return 0;
}

static void now_iso(char *out, int outsz)
{
	struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm; gmtime_r(&ts.tv_sec, &tm);
	strftime(out, outsz, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* minimal JSON string escaper for the short paths we print */
static void json_escape(const char *in, char *out, int outsz)
{
	int j = 0;
	for (int i = 0; in[i] && j < outsz - 2; i++) {
		char c = in[i];
		if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = c; }
		else if (c >= 0x20)        { out[j++] = c; }
	}
	out[j] = '\0';
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx; (void)len;
	const struct event *e = data;

	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &e->daddr, ip, sizeof(ip));

	char exe[256]; exe_path(e->pid, exe, sizeof(exe));

	char path[128] = "";
	if (e->payload_len)
		http_path(e->payload, e->payload_len, path, sizeof(path));

	int is_cred = e->payload_len && strstr(e->payload, IAM_CREDS) != NULL;
	int allowed = path_allowlisted(exe);

	const char *verdict, *severity, *detail;
	if (e->action == ACT_BLOCKED) {
		verdict = "BLOCKED"; severity = "critical";
		detail  = "metadata access denied in enforce mode (process not on allowlist)";
	} else if (allowed) {
		verdict = "ALLOW"; severity = "info";
		detail  = "metadata access by allowlisted executable";
	} else if (is_cred) {
		verdict = "ALERT"; severity = "critical";
		detail  = "process requested IAM credentials from the metadata service";
	} else {
		verdict = "ALERT"; severity = "low";
		detail  = "process accessed the metadata service";
	}

	char ts[32]; now_iso(ts, sizeof(ts));
	char exe_j[512], path_j[260];
	json_escape(exe, exe_j, sizeof(exe_j));
	json_escape(path, path_j, sizeof(path_j));

	printf("{\"ts\":\"%s\",\"verdict\":\"%s\",\"severity\":\"%s\",\"technique\":\"T1552.005\","
	       "\"process\":\"%s\",\"pid\":%u,\"uid\":%u,\"exe\":\"%s\",\"dest\":\"%s:%u\","
	       "\"http_path\":\"%s\",\"detail\":\"%s\"}\n",
	       ts, verdict, severity, e->comm, e->pid, e->uid, exe_j, ip, e->dport,
	       path_j, detail);
	fflush(stdout);
	return 0;
}

static int libbpf_quiet(enum libbpf_print_level lvl, const char *f, va_list a)
{
	if (lvl == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, f, a);
}

static struct { int enforce; const char *cgroup; } opts = { 0, "/sys/fs/cgroup" };

static const struct argp_option options[] = {
	{ "enforce", 'e', 0, 0, "Block non-allowlisted metadata access (default: monitor)", 0 },
	{ "cgroup", 'c', "PATH", 0, "cgroup v2 mount to attach enforce hook (default /sys/fs/cgroup)", 0 },
	{ 0 },
};
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	(void)state;
	switch (key) {
	case 'e': opts.enforce = 1; break;
	case 'c': opts.cgroup = arg; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static const struct argp argp = { options, parse_opt, 0,
	"CredGuard - runtime cloud credential-theft detector (demo).", 0, 0, 0 };

int main(int argc, char **argv)
{
	argp_parse(&argp, argc, argv, 0, 0, 0);
	libbpf_set_print(libbpf_quiet);

	struct credguard_bpf *skel = credguard_bpf__open();
	if (!skel) { fprintf(stderr, "failed to open BPF object\n"); return 1; }

	/* Tell the kernel which PID namespace to report PIDs in, so they match the
	 * /proc view the daemon resolves (matters on WSL and inside containers). */
	struct stat ns;
	if (stat("/proc/self/ns/pid", &ns) == 0) {
		skel->rodata->pidns_dev = ns.st_dev;
		skel->rodata->pidns_ino = ns.st_ino;
	}

	if (credguard_bpf__load(skel)) {
		fprintf(stderr, "failed to load BPF object\n");
		credguard_bpf__destroy(skel); return 1;
	}

	/* push config + allowlist into the maps before attaching */
	__u32 k = 0, enforce = opts.enforce;
	bpf_map__update_elem(skel->maps.cfg, &k, sizeof(k), &enforce, sizeof(enforce), 0);
	for (size_t i = 0; i < sizeof(ALLOW_COMMS) / sizeof(ALLOW_COMMS[0]); i++) {
		char comm[TASK_COMM_LEN] = {0};
		strncpy(comm, ALLOW_COMMS[i], sizeof(comm) - 1);
		__u8 one = 1;
		bpf_map__update_elem(skel->maps.allowlist, comm, sizeof(comm), &one, sizeof(one), 0);
	}

	/* attach the kprobe */
	if (credguard_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach kprobe\n");
		credguard_bpf__destroy(skel); return 1;
	}

	/* attach the cgroup/connect4 program to the cgroup v2 root */
	int cg_fd = open(opts.cgroup, O_RDONLY);
	struct bpf_link *cg_link = NULL;
	if (cg_fd >= 0) {
		cg_link = bpf_program__attach_cgroup(skel->progs.cg_connect4, cg_fd);
		if (!cg_link)
			fprintf(stderr, "warning: could not attach connect4 enforce hook\n");
	} else {
		fprintf(stderr, "warning: could not open cgroup %s\n", opts.cgroup);
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
						  handle_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "failed to create ring buffer\n"); goto cleanup; }

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	fprintf(stderr, "[credguard] running in %s mode. watching 169.254.169.254 . Ctrl-C to stop.\n",
		opts.enforce ? "ENFORCE" : "MONITOR");

	while (!stop) {
		int err = ring_buffer__poll(rb, 200);
		if (err < 0 && err != -EINTR) { fprintf(stderr, "poll error %d\n", err); break; }
	}

	fprintf(stderr, "\n[credguard] shutting down.\n");
	ring_buffer__free(rb);
cleanup:
	if (cg_link) bpf_link__destroy(cg_link);
	if (cg_fd >= 0) close(cg_fd);
	credguard_bpf__destroy(skel);
	return 0;
}
