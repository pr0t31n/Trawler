<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Trawler

Passive pcap-based traffic analyser for the pr0t31n toolkit. Surfaces
DNS / TLS / DHCP / cleartext-protocol risks from packet captures, in
three modes:

- **Targeted / External-only** (default with `--target`): catalogues what
  a specific target IP exposes to public peers — hardcoded resolvers,
  cleartext DNS, TLS posture, mTLS client-cert leaks, DHCP disclosure.
- **Targeted / External + Internal** (`--target` + `--include-internal`):
  additionally applies internal-network rules — SMBv1, LLMNR / NBT-NS,
  SSDP, mDNS, LLDP topology, ARP anomalies, cleartext FTP / Telnet,
  SNMPv1/v2c communities, HTTP Basic Auth, LDAP bind without TLS.
- **Hunt mode** (`--hunt`, or omit `--target`): threat-hunting mode —
  auto-discovers every unique IP in the capture and runs ALL rules
  (external + internal) against each. Designed for network threat hunting
  where you want to scan all traffic for malicious, suspicious, or
  plaintext activity without knowing which IPs to focus on.
- **Ignore filter** (`--ignore <IP>` / `--ignore-file <path>`): excludes
  all traffic to/from specified IPs from the ledger before any rules run.
  Essential for passive recon where the testing server's scan traffic
  (nmap probes, etc.) would generate false findings. Ignored IPs are also
  excluded from auto-discovered targets in hunt mode and from explicit
  target lists. Multiple `--ignore` flags can be combined.

Findings emit in the universal Scattershot3/Crucible schema and slot
straight into Crucible's Findings + Traffic tabs and evidence
viewer, Prometheus's `UniversalParser`, and Bastion's ingest.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/trawler)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- Multi-format capture support — `.pcap` / `.pcapng` / `.cap` / `.ntar` /
  `.erf` / `.snoop` / `*.gz` — anything `editcap` can read is normalised
  to `.pcapng` before analysis.
- Single-pass `tshark` field extraction → all check rules run on the same
  in-memory ledger, so a 100 MB capture analyses in seconds rather than
  re-running tshark per check.
- Per-target peer rollup — for each analysed IP, builds external + internal
  peer lists with byte counts, ports, protocols, SNIs and finding counts.
- Universal output layout (`meta.json`, `findings.{json,csv}`,
  `summary.json`, `targets.json`, `traffic.json`, `inventory/`, `evidence/`).
- Runs under Crucible (`CRUCIBLE_MANAGED=1`) and emits the standard
  `__CRUCIBLE_LOG__:` / `__CRUCIBLE_STATUS__:` / `__CRUCIBLE_TARGET__:` /
  `__CRUCIBLE_PORT__:` protocol tokens for live UI updates.

## Requirements

- Python 3.10+
- Wireshark CLI tools (`tshark`, `editcap`, `capinfos`) — installed by
  `install.py` automatically on Debian/Ubuntu/Kali (apt), macOS (brew),
  Windows (choco), and the major RPM distros (dnf/yum) + Arch (pacman).

## Installation

```bash
git clone https://github.com/pr0t31n/Trawler /opt/pr0t31n/Trawler
cd /opt/pr0t31n/Trawler
python3 install.py
```

Or via Arsenal (the pr0t31n tool manager) which knows about Trawler's
install path and version.

## Usage

```bash
# Manual mode — analyse one pcap, one target IP, external-only
python3 trawler.py \
    --pcap /captures/admin.pcapng \
    --target 192.168.1.150 \
    --scope ext \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120000/ \
    --client foo

# With internal-rule analysis
python3 trawler.py \
    --pcap /captures/admin.pcapng \
    --pcap /captures/op.pcapng \
    --target 192.168.1.150 \
    --include-internal \
    --scope int \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120100/ \
    --client foo

# Multi-target — analyse every IP in a list (typical Scattershot3 use)
python3 trawler.py \
    --pcap /scattershot3_run/int/capture.pcapng \
    --targets-file /scattershot3_run/int/targets/active_ips.txt \
    --include-internal \
    --scope int \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120200/ \
    --client foo

# Hunt mode — threat hunting across all traffic (no target required)
python3 trawler.py \
    --pcap /captures/network_tap.pcap \
    --hunt \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120300/ \
    --client foo

# Hunt mode implied — just omit --target
python3 trawler.py \
    --pcap /captures/network_tap.pcap \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120400/

# Passive recon — hunt mode with testing server excluded
python3 trawler.py \
    --pcap /captures/passive_recon.pcap \
    --hunt \
    --ignore 192.168.1.100 \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120500/ \
    --client foo

# Multiple IPs to ignore (one --ignore per IP, or use --ignore-file)
python3 trawler.py \
    --pcap /captures/passive_recon.pcap \
    --hunt \
    --ignore 192.168.1.100 --ignore 192.168.1.101 \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120600/ \
    --client foo

# Ignore list from file (one IP per line)
python3 trawler.py \
    --pcap /captures/passive_recon.pcap \
    --hunt \
    --ignore-file /tmp/testing_servers.txt \
    --output-dir /clients/foo/2026/trawler/foo_20260529_120700/ \
    --client foo
```

## Output layout

```
<clients_base>/<client_short>/<year>/trawler/<client_short>_<YYYYMMDD_HHMMSS>/
├── meta.json                 # tool/version/client/scope/target metadata
├── findings.json             # universal schema findings array
├── findings.csv              # CSV mirror
├── summary.json              # totals + risk counts
├── targets.json              # per-host summary for Crucible Targets tab
├── traffic.json              # per-host expanded peer lists (Traffic tab)
├── scan.log                  # human-readable
├── scan.log.json             # machine-readable JSON event log
├── errors.log
├── inventory/
│   ├── external_peers.json
│   └── internal_peers.json   # (when --include-internal)
└── evidence/
    └── <target_ip>/
        ├── hardcoded_dns.txt
        ├── tls_cbc_ciphers.txt
        └── …
```

## Findings catalogue

17 entries in `findings_catalogue.json`:

| ID | Risk | Title |
|---|---|---|
| PT-001 | MEDIUM | Hardcoded Public DNS Resolvers Bypass Enterprise Controls |
| PT-002 | LOW | Cleartext DNS Exposes External Service Topology |
| PT-003 | LOW | Device Identity Leaked in TLS Client Certificate (mTLS) |
| PT-004 | LOW | TLS ClientHello Offers Legacy CBC Cipher Suites |
| PT-005 | MEDIUM | DHCP Hostname Discloses Asset Identifier |
| PT-006 | MEDIUM | DNS Search-Suffix Appended to FQDNs |
| PT-101 | HIGH | SMBv1 Traffic Observed (EternalBlue / NotPetya exposure) |
| PT-102 | HIGH | LLMNR / NBT-NS Name Resolution (Responder surface) |
| PT-103 | LOW | SSDP / UPnP Broadcasts |
| PT-104 | LOW | mDNS Activity on Internal Segment |
| PT-105 | LOW | LLDP Topology / Switch Firmware Disclosure |
| PT-106 | MEDIUM | ARP Anomalies (Duplicate IP-to-MAC) |
| PT-107 | HIGH | Cleartext FTP Traffic Observed |
| PT-108 | HIGH | Cleartext Telnet Traffic Observed |
| PT-109 | MEDIUM | SNMPv1/v2c Community String in Cleartext |
| PT-110 | HIGH | HTTP Basic Authentication in Cleartext |
| PT-111 | MEDIUM | LDAP Bind without TLS |

## Crucible integration

Trawler registers under the Crucible Flask UI alongside Scattershot3
(`ss`) and OSift (`os`) with tool key `tr`. Crucible exposes a "Traffic"
tab built from `traffic.json` showing per-host external/internal peer
breakdowns. Crucible also auto-triggers Trawler on Scattershot3 scope
completion when SS produces capture files — the scope label (`int` /
`ext`) is passed through so the appropriate rule set is selected.

## Cross-tool dependencies

Per `CLAUDE.md` Section 3:

- **Crucible** — reads Trawler `findings.json` + `traffic.json` for the
  Traffic tab and Findings tab.
- **Prometheus** — `UniversalParser` ingests Trawler's universal
  `meta.json` automatically (no Trawler-specific parser needed).
- **Shared Catalogue** — `pr0t31n_catalogue.py merge` includes Trawler's
  `findings_catalogue.json` in the master catalogue.

## Version

Current: see `VERSION` file in repo root and `VERSION = "..."` constant
in `trawler.py`.
