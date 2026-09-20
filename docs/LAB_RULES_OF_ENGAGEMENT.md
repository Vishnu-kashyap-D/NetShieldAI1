# NetShield AI — Rules of Engagement for VM-Lab Live-Capture Testing

**Purpose:** to generate *real* attack traffic against NetShield AI safely — so the pipeline can be validated on genuinely captured traffic (`backend/scripts/live_capture_feed.py`), not only on CICIDS2017 replays — without ever putting a real network, a real person or a real system at risk.

**Who this binds:** everyone on the team who runs an attack tool or captures traffic for this project.

> **How to read this document.** Rules **R1–R4** write down the practice the team already follows. Everything under **"Proposed additions"** and the checklists is new wording that turns that practice into something repeatable — **confirm or edit it** so this page matches what the team really does before it is cited in the report.

---

## 1. The lab

| Element | Rule |
|---|---|
| **Hypervisor** | VirtualBox, on one team member's machine |
| **Machines** | An **attacker VM** and a **victim VM** — both isolated from everything else |
| **Network** | A **host-only** network shared by exactly those VMs (and the host) — nothing else attached |
| **Capture** | `tcpdump -i <iface> -w capture.pcap` **on the victim VM**; the `.pcap` is copied out with `scp` and converted on the host with `live_capture_feed.py` |
| **Detection** | Runs on the host (backend + models). It only ever *reads* the captured file; it never touches the lab network |

---

## 2. The rules

### R1 — Host-only network, always
The lab VMs talk **only** to each other (and the host) over the VirtualBox **host-only** adapter. Never *Bridged*, never *Internal-to-a-real-LAN*, never a second adapter that reaches anything else. Attack traffic must have nowhere to go except the victim VM.

### R2 — No NAT during attack runs
A NAT adapter gives a VM a route to the internet. **Disable it before any attack tool is started**, and keep it off until the run is finished and the tool has stopped. If a package must be installed, do that first, with the attacker tools *not* running, then remove the NAT adapter, *then* run attacks.

### R3 — Isolated VMs
The attacker and victim VMs are dedicated to this lab and kept isolated from everything else, so whatever happens inside them stays inside them.

### R4 — Real tools, no real malware
Traffic comes from **standard, publicly-available testing tools** (for example `hping3` for floods, `hydra` for login brute-forcing, port scanners) pointed at the **victim VM's** services. **No real malware**: no botnet clients, ransomware, in-the-wild exploits or other malicious samples are downloaded, built or run.

---

## 3. Proposed additions (confirm)

### R5 — Scope: exactly two targets
Attack tools may be pointed **only** at the victim VM's host-only address. Not the host machine (which runs the backend and database), not the college/home network, not any address on the internet — even "just to test". Before each run, write the victim IP down and check the tool's target argument against it.

### R6 — VM hygiene
The VMs hold no personal accounts, files or credentials; shared folders, shared clipboard and drag-and-drop are off during a run; and a clean **snapshot** exists so each VM can be reverted after testing.

### R7 — Bounded, supervised runs
Runs are short and attended: set explicit limits (packet count or duration, thread count) up front; a person is watching; **stop immediately** if anything unexpected happens (see §5). No unattended or scheduled attacks.

### R8 — Handle captures as data, not as trusted files
`.pcap` files contain only lab-generated traffic, but are still treated carefully: stored under the git-ignored `captures/` folder (never committed), and copied out of the VM with `scp` from the *victim to the host* only. They are converted and scored offline; nothing from a capture is executed.

### R9 — Nothing leaves the lab
No lab traffic, credentials or capture files are posted to public places (issues, chat, slides) without checking they contain nothing but synthetic lab data. Screenshots for the report show the dashboard, not raw payloads.

### R10 — Authority
The lab exists to test **our own** software on **our own** machines, agreed by the team. Nobody may use these tools or techniques against a system they do not own, even for demonstration, and none of this is a licence to.

---

## 4. Procedure

**Before a run** (all must be true)
- [ ] Both VMs restored from the clean snapshot (or known-good state)
- [ ] Only the **host-only** adapter is enabled on both VMs — **NAT off** (R1, R2)
- [ ] No shared folders / shared clipboard / drag-and-drop enabled (R6)
- [ ] Victim IP noted; target argument checked against it (R5)
- [ ] Limits chosen (count / duration / threads) (R7)
- [ ] `tcpdump` capturing on the victim

**During**
- One tool at a time, one person driving, one watching the clock.

**After**
- [ ] Attack tool stopped; capture stopped
- [ ] `capture.pcap` copied victim → host with `scp`; stored in `captures/`
- [ ] Ingest with `python backend/scripts/live_capture_feed.py <pcap>`; note the source name used
- [ ] VMs reverted to snapshot or shut down; NAT stays off until the next planned install
- [ ] Record: date, tool, target, limits, what NetShield reported (for the report)

---

## 5. Stop conditions

Stop the attack tool and disconnect the VM's network adapter **immediately** if:
- any VM shows a route to something other than the host-only network (e.g. it can reach the internet);
- the host machine, not the victim VM, shows signs of being the target;
- a tool behaves in an unexpected way (runs away, ignores its limits);
- anyone is unsure the rules are being followed.

Then: revert the VM, work out what happened, and update this page before running again.

---

## 6. What this lab does *not* validate

Traffic from `hping3` / `hydra` is real but **synthetic in style** — it is not the same as real-world attackers, and it differs from CICIDS2017's capture conditions, so a model verdict on it says little about production performance. During earlier runs such tool traffic was seen classified as *Malware Traffic* rather than the category the tool implies; the anomaly gate still fired, so this is a **labelling** weakness (planned: an "unknown" rejection option), not an evasion. Report lab results as *feasibility evidence*, not accuracy figures.
