# CredGuard — Cloud Credential Protection Agent (Demo)

A runtime security agent that detects, and optionally blocks, **cloud credential
theft** on a workload — at the Linux kernel level, using **eBPF** and **C**.

This repository is the **Stage 0–2 demo** of the larger CredGuard project. It
reproduces the core of the **Capital One (2019)** breach in a safe local lab and
shows CredGuard catching it:

> An attacker exploits a Server-Side Request Forgery (SSRF) bug in a web app to
> reach the cloud **instance metadata service** at `169.254.169.254` and steal
> the machine's IAM credentials. CredGuard sees the exact process making that
> request, in real time, and can block it.

Everything here runs **locally** (a mock metadata service, no real AWS, no real
credentials). It was built and tested on **Kali/Debian under WSL2**, kernel 6.6.

---

## What the demo shows

| Mode | What happens | CredGuard verdict |
|------|--------------|-------------------|
| **monitor** | The SSRF attack steals the IAM credentials (succeeds). A harmless `instance-id` lookup is also made. | `instance-id` → **ALERT / low**. Credential grab → **ALERT / critical**, naming the exact process, PID, UID, executable path and HTTP request. |
| **enforce** | The SSRF credential theft is **blocked in real time**. A legitimate allowlisted tool (`aws`) still reaches the metadata service. | Attack → **BLOCKED / critical**. `aws` → **ALLOW / info**. |

CredGuard's edge over cloud-native tools (e.g. GuardDuty): it names **which
process on which machine** touched the credential, at the moment of theft —
not minutes later, after the stolen key is used elsewhere.

---

## Architecture

```
   attacker ──SSRF──>  vulnerable app ──HTTP GET──>  169.254.169.254  (mock metadata service)
                           (python3)                       │
                                                           │  the request is what CredGuard inspects
                    ┌──────────────────────────────────────┴───────────────────────┐
   KERNEL (eBPF, C) │  kprobe/tcp_sendmsg   : capture process + HTTP request bytes   │
                    │  cgroup/connect4      : deny the connection in enforce mode    │
                    └──────────────────────────────┬───────────────────────────────┘
                                                    │  events via ring buffer
   USER SPACE (C)   ┌──────────────────────────────┴───────────────────────────────┐
                    │  credguard daemon: classify (harmless vs credential grab),    │
                    │  resolve /proc/<pid>/exe, apply path allowlist, emit JSON      │
                    └───────────────────────────────────────────────────────────────┘
```

- **`bpf/credguard.bpf.c`** — the eBPF programs (kernel side), built with libbpf + CO-RE.
- **`src/credguard.c`** — the user-space daemon that loads them and raises alerts.
- **`src/credguard.h`** — the event struct shared between kernel and user space.
- **`lab/`** — the mock metadata service, the vulnerable app, and the attack script.
- **`demo.sh`** — one command that runs the whole story.

### How the detection works
1. A kprobe on `tcp_sendmsg` fires on every TCP send. CredGuard keeps only sends
   whose destination is `169.254.169.254:80` (the metadata service).
2. It reads the first bytes of the HTTP request out of the kernel socket buffer.
   `/latest/meta-data/instance-id` is harmless; `/…/iam/security-credentials/…`
   is a credential grab.
3. It records the process (PID, UID, name) and, in user space, resolves the real
   executable path from `/proc/<pid>/exe` and checks it against an allowlist.
4. In **enforce** mode, a `cgroup/connect4` program denies the `connect()` to the
   metadata service for any process not on the allowlist.

> **Note (WSL / containers):** the kernel's global PID differs from the PID the
> daemon sees in `/proc`. CredGuard uses `bpf_get_ns_current_pid_tgid()` to report
> PIDs in the daemon's own namespace, so `/proc/<pid>/exe` resolves correctly.

---

## Requirements

- Linux with a modern kernel (**5.8+**) that has **BTF** (`/sys/kernel/btf/vmlinux`)
  and `CONFIG_BPF_SYSCALL`, `CONFIG_CGROUP_BPF`. Ubuntu 22.04/24.04 or Kali work;
  WSL2's kernel 6.6 works.
- Root (eBPF loading needs privileges).
- Packages: `clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev gcc make iproute2 curl python3`.

Install them with:
```bash
sudo bash scripts/setup_deps.sh
```

---

## Build

```bash
make
```
Produces `build/credguard`.

## Run the demo

```bash
sudo ./demo.sh monitor   # detect the theft (attack succeeds, CredGuard alerts)
sudo ./demo.sh enforce   # block the theft in real time (allowlisted tool still works)
```

Each run brings the lab up, starts the agent, performs the attack, prints the
JSON alerts, and tears everything down.

See **[DEMO.md](DEMO.md)** for the live two-terminal version and a presenter script.

---

## Mapping to MITRE ATT&CK
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API (the IMDS theft).
- **T1552.001** — Unsecured Credentials: Credentials in Files (next stage: `~/.aws/credentials`).

## Scope and honest limitations
- This is a **lab demo**: a mock metadata service and a deliberately vulnerable app.
  Nothing here is a real credential or a real AWS call.
- CredGuard does **not** fix the SSRF bug; it stops the bug from yielding credentials.
- A root attacker can try to disable any host agent — this shares that limitation.
- The `cgroup/connect4` enforce hook allowlists by process name (`comm`); the
  detection path allowlists by executable **path** (stronger). Production use
  would unify these.
- Not yet covered (future stages): credential **files**, `/proc/<pid>/environ`
  theft, Kubernetes pod attribution, and CloudTrail "used-elsewhere" correlation.

## Repository layout
```
credguard-demo/
├── bpf/        eBPF kernel programs + generated vmlinux.h
├── src/        user-space daemon (C) + shared header
├── lab/        mock metadata service, vulnerable app, attack script
├── scripts/    dependency setup
├── Makefile
├── demo.sh     one-command scripted demo
├── README.md
└── DEMO.md     presenter guide
```
