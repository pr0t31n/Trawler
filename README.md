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

Findings emit in the universal Scattershot3/Vantage schema and slot
straight into Vantage's Findings + Traffic tabs, Crucible's evidence
viewer, Prometheus's `UniversalParser`, and Bastion's ingest.

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
- Runs under Vantage (`VANTAGE_MANAGED=1`) and emits the standard
  `__VANTAGE_LOG__:` / `__VANTAGE_STATUS__:` / `__VANTAGE_TARGET__:` /
  `__VANTAGE_PORT__:` protocol tokens for live UI updates.

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
├── targets.json              # per-host summary for Vantage Targets tab
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

15+ entries in `findings_catalogue.json`:

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

## Vantage integration

Trawler registers under the Vantage Flask UI alongside Scattershot3
(`ss`) and OSift (`os`) with tool key `tr`. Vantage exposes a "Traffic"
tab built from `traffic.json` showing per-host external/internal peer
breakdowns. Vantage also auto-triggers Trawler on Scattershot3 scope
completion when SS produces capture files — the scope label (`int` /
`ext`) is passed through so the appropriate rule set is selected.

## Cross-tool dependencies

Per `CLAUDE.md` Section 3:

- **Vantage** — reads Trawler `findings.json` + `traffic.json` for the
  Traffic tab and Findings tab.
- **Prometheus** — `UniversalParser` ingests Trawler's universal
  `meta.json` automatically (no Trawler-specific parser needed).
- **Arbiter** — `pr0t31n_catalogue.py merge` includes Trawler's
  `findings_catalogue.json` in the master catalogue.

## Version

Current: see `VERSION` file in repo root and `VERSION = "..."` constant
in `trawler.py`.
