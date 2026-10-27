# CredGuard — Presenter Guide

A 4–6 minute live demo. Two ways to run it: the **one-command** version (safest
for submission) and the **two-terminal live** version (most convincing).

---

## 0. One-time setup (do this before the presentation)

Open the Kali terminal as **root**:
```bash
wsl -d kali-linux -u root
cd "/mnt/e/SEM 5/Projects/Problem solving using c/credguard-demo"
sudo bash scripts/setup_deps.sh   # only needed the first time
make
```
You should see `build/credguard` created, with no errors.

---

## Option A — One command (recommended for the submission)

```bash
sudo ./demo.sh monitor
```
Then:
```bash
sudo ./demo.sh enforce
```

Each prints a labelled walk-through: lab up → agent starts → attack → alerts.

---

## Option B — Live, two terminals (most convincing)

**Terminal 1 — start the lab and the agent (monitor mode):**
```bash
cd "/mnt/e/SEM 5/Projects/Problem solving using c/credguard-demo"
sudo ip addr add 169.254.169.254/32 dev lo
sudo python3 lab/mock_imds.py &        # mock metadata service
python3 lab/ssrf_app.py &              # vulnerable app
sudo ./build/credguard                 # <- watch this window; leave it running
```

**Terminal 2 — be the attacker:**
```bash
cd "/mnt/e/SEM 5/Projects/Problem solving using c/credguard-demo"

# 1) harmless request through the SSRF bug
bash lab/attack.sh benign
#    -> Terminal 1 shows: ALERT / low  (instance-id)

# 2) the Capital One move: steal IAM credentials through the SSRF bug
bash lab/attack.sh steal
#    -> Terminal 1 shows: ALERT / critical, naming python3 + the exact request
```

**Show blocking:** stop the agent in Terminal 1 (Ctrl-C) and restart it with
`sudo ./build/credguard --enforce`. Run `bash lab/attack.sh steal` again in
Terminal 2 — it now fails with *Operation not permitted*, and Terminal 1 logs
**BLOCKED**.

**Clean up:**
```bash
sudo pkill -f mock_imds; pkill -f ssrf_app
sudo ip addr del 169.254.169.254/32 dev lo
```

---

## What to say (talking points)

1. **The incident.** "In 2019, Capital One lost 100M+ records. An SSRF bug let an
   attacker reach the cloud metadata service at 169.254.169.254 and steal the
   server's IAM credentials, then used them from outside to read S3."

2. **The gap.** "Cloud tools like GuardDuty notice the stolen key *being used*
   elsewhere, minutes later. They can't tell you which process stole it. That's
   the gap CredGuard fills."

3. **Point at the critical alert.** "CredGuard runs in the kernel with eBPF. The
   moment the credentials are requested, it names the process — `python3`, this
   PID, this executable, requesting `/iam/security-credentials/`. Detection
   latency is milliseconds, not minutes."

4. **The harmless one.** "Note it didn't cry wolf on the `instance-id` lookup —
   that's low severity. It reads the actual request to tell a credential grab
   from a harmless one."

5. **Enforcement.** "In enforce mode the theft is blocked outright, while a
   legitimate allowlisted tool — the AWS CLI — still reaches the metadata
   service. Real teams start in monitor mode, then switch on enforcement."

6. **Why C.** "The detection has to run inside the kernel, where eBPF programs
   are written in C and the user-space loader uses libbpf — also C. This is the
   same stack behind production tools like Falco and Cilium Tetragon."

---

## Expected output (reference)

Monitor mode, the two alerts:
```json
{"verdict":"ALERT","severity":"low","process":"python3","exe":"/usr/bin/python3.14","http_path":"/latest/meta-data/instance-id", ...}
{"verdict":"ALERT","severity":"critical","process":"python3","exe":"/usr/bin/python3.14","http_path":"/latest/meta-data/iam/security-credentials/credguard-demo-role", ...}
```
Enforce mode:
```json
{"verdict":"BLOCKED","severity":"critical","process":"python3","detail":"metadata access denied in enforce mode (process not on allowlist)"}
{"verdict":"ALLOW","severity":"info","process":"aws","exe":"/usr/bin/aws","http_path":"/latest/meta-data/instance-id"}
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `failed to load BPF object` | Kernel lacks BTF/BPF. Confirm `ls /sys/kernel/btf/vmlinux`. Use Ubuntu 22.04+/Kali. Run as root. |
| `(no alerts captured)` | Make sure you ran with `sudo`. Rebuild with `make`. |
| Attack prints `Connection refused` | The mock metadata service isn't up — the one-command `demo.sh` handles this for you; in the two-terminal version start `mock_imds.py` first. |
| `RTNETLINK answers: File exists` on `ip addr add` | Harmless — the address is already on `lo`. |
| Enforce blocks everything to 169.254.169.254 | Expected: only allowlisted process names (`aws`, SSM, CloudWatch) are permitted. |
