#!/usr/bin/env python3
"""
trawler.py — pr0t31n toolkit pcap-based traffic analyser.

Performs per-target passive analysis of one or more packet captures and
emits security findings in the universal Scattershot3/Vantage schema.

Modes:
  external-only  (default)       Flag DNS / TLS / DHCP / cloud-architecture
                                 risks the target IP exposes to public peers.
  external + internal            With --include-internal: additionally apply
                                 internal-network rules (SMBv1, LLMNR/NBT-NS,
                                 SSDP, mDNS exposure, LLDP, ARP anomalies,
                                 cleartext FTP/Telnet/SNMP, HTTP basic auth,
                                 LDAP cleartext) against private-IP peers.

Multi-format capture support:
  .pcap .pcapng .cap .ntar .erf .snoop .pcap.gz .pcapng.gz — anything
  Wireshark's editcap can read is auto-normalised to .pcapng before analysis.

Usage:
  trawler.py --pcap CAP [--pcap CAP …]
             (--target IP | --targets-file PATH)
             [--include-internal]
             [--scope int|ext]
             --output-dir DIR
             --client SHORT

When run under VANTAGE_MANAGED=1, emits __VANTAGE_LOG__:, __VANTAGE_STATUS__:,
__VANTAGE_TARGET__: and __VANTAGE_PORT__: tokens consumed by Vantage.
"""
from __future__ import annotations
VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

import argparse, csv, ipaddress, json, os, re, shutil, subprocess, sys
import threading, uuid
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path

# ── Optional shared schema (graceful fallback if missing) ─────────────────────
try:
    sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
    _SHARED_OK = True
except Exception:
    _us = None
    _SHARED_OK = False

# §13b/§14j/§14k: run-dir audit log (scan.log + scan.log.json + errors.log), set
# in main() once the run dir is known. VC.log/error/status forward here so every
# message + phase transition is persisted with a timestamp (tokens are ephemeral).
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_event_log as _el
except Exception:
    _el = None
_RUNLOG = None

# ── Optional threat-intelligence module ──────────────────────────────────────
try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_threat_intel as _ti
    _HAVE_THREAT_INTEL = True
except ImportError:
    _ti = None
    _HAVE_THREAT_INTEL = False

# ── Vantage protocol tokens ───────────────────────────────────────────────────
_VANTAGE_MANAGED = os.environ.get("VANTAGE_MANAGED", "") == "1"
_VP_LOG    = "__VANTAGE_LOG__:"
_VP_ERR    = "__VANTAGE_ERR__:"
_VP_STATUS = "__VANTAGE_STATUS__:"
_VP_TARGET = "__VANTAGE_TARGET__:"
_VP_PORT   = "__VANTAGE_PORT__:"

# ── Tooling discovery ─────────────────────────────────────────────────────────
# When Trawler runs under Vantage's daemon (no interactive PATH), shutil.which
# misses Wireshark binaries that were installed via the macOS .app bundle, the
# Homebrew/Apple-Silicon paths, or Windows Program Files. Fall back to a list
# of well-known install locations after the PATH lookup fails.
def _find_tool(name: str) -> "str | None":
    p = shutil.which(name)
    if p:
        return p
    candidates = (
        f"/Applications/Wireshark.app/Contents/MacOS/{name}",   # macOS .app
        f"/opt/homebrew/bin/{name}",                              # Apple Silicon brew
        f"/usr/local/bin/{name}",                                  # Intel brew / legacy
        f"/usr/bin/{name}",                                        # apt
        f"/usr/sbin/{name}",
        f"/usr/local/sbin/{name}",
        f"C:/Program Files/Wireshark/{name}.exe",                  # Windows
        f"C:/Program Files (x86)/Wireshark/{name}.exe",
    )
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None

TSHARK   = _find_tool("tshark")
EDITCAP  = _find_tool("editcap")
CAPINFOS = _find_tool("capinfos")

# ── Console / Vantage protocol emitter ────────────────────────────────────────
class VC:
    """Dual-mode console — ANSI when interactive, protocol tokens under Vantage."""
    _lock = threading.Lock()

    @classmethod
    def log(cls, message: str, level: str = "INFO") -> None:
        if _RUNLOG is not None:
            try:
                lv = (level or "INFO").upper()
                if lv == "ERROR":               _RUNLOG.error(message)
                elif lv in ("WARN", "WARNING"): _RUNLOG.warn(message)
                else:                           _RUNLOG.info(message)
            except Exception:
                pass
        if _VANTAGE_MANAGED:
            with cls._lock:
                entry = {"ts": _iso(), "level": level, "message": message}
                sys.stdout.write(_VP_LOG + json.dumps(entry) + "\n")
                sys.stdout.flush()
        else:
            tag = {"INFO":"[*]","SUCCESS":"[+]","WARNING":"[~]","ERROR":"[!]"}.get(level,"[*]")
            print(f"{tag} {message}", flush=True)

    @classmethod
    def error(cls, message: str, source: str = "trawler", detail: str = "") -> None:
        if _RUNLOG is not None:
            try: _RUNLOG.error(f"{message} {detail}".strip())
            except Exception: pass
        if _VANTAGE_MANAGED:
            with cls._lock:
                entry = {"ts": _iso(), "source": source, "message": message,
                         "detail": detail, "category": "Scan"}
                sys.stderr.write(_VP_ERR + json.dumps(entry) + "\n")
                sys.stderr.flush()
        else:
            print(f"[!] {message}  {detail}", file=sys.stderr, flush=True)

    @classmethod
    def status(cls, phase: str, label: str = "", status: str = "running",
               step: str = "", progress: int = 0, total: int = 0) -> None:
        # §14j: persist the phase transition to the audit log with a timestamp.
        if _RUNLOG is not None:
            try:
                _RUNLOG.event(f"phase {phase}: {status}" + (f" — {step}" if step else ""))
            except Exception:
                pass
        if _VANTAGE_MANAGED:
            with cls._lock:
                entry = {"phase": phase, "label": label or phase, "status": status,
                         "step": step, "progress": progress, "total": total,
                         "ts": _iso()}
                sys.stdout.write(_VP_STATUS + json.dumps(entry) + "\n")
                sys.stdout.flush()

    @classmethod
    def target(cls, ip: str, hostname: str | None = None,
               scope: str | None = None) -> None:
        if _VANTAGE_MANAGED:
            with cls._lock:
                entry = {"ts": _iso(), "ip": ip, "hostname": hostname,
                         "scope": scope, "alive": True, "source": "trawler"}
                sys.stdout.write(_VP_TARGET + json.dumps(entry) + "\n")
                sys.stdout.flush()

    @classmethod
    def port(cls, ip: str, port: int, proto: str = "tcp",
             name: str = "", scope: str | None = None) -> None:
        if _VANTAGE_MANAGED:
            with cls._lock:
                entry = {"ts": _iso(), "ip": ip, "port": int(port),
                         "proto": proto, "name": name, "scope": scope,
                         "state": "open"}
                sys.stdout.write(_VP_PORT + json.dumps(entry) + "\n")
                sys.stdout.flush()

    @classmethod
    def action_item(cls, item: dict) -> None:
        if _VANTAGE_MANAGED:
            with cls._lock:
                sys.stdout.write(_VP_LOG + json.dumps(
                    {"ts": _iso(), "level": "ACTION_ITEM",
                     "message": f"Action Item: {item.get('title', '')}"}) + "\n")
                sys.stdout.flush()
        else:
            print(f"[+] Action Item: {item.get('title', '')}", flush=True)

def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

def _ts_fname() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ── IP helpers ────────────────────────────────────────────────────────────────
def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False

def ip_key(ip: str) -> tuple:
    try:    return tuple(int(p) for p in ip.split("."))
    except: return (0,0,0,0)

# ── Capture-format normaliser ────────────────────────────────────────────────
def normalise_capture(in_path: Path, out_dir: Path) -> Path:
    """Convert any tshark/editcap-readable capture to .pcapng. Returns new path
    (or the original if already pcapng)."""
    suffix = in_path.suffix.lower()
    if suffix == ".pcapng":
        return in_path
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / (in_path.stem + ".pcapng")
    if not EDITCAP:
        VC.error("editcap not installed — cannot normalise capture format",
                 detail=str(in_path))
        return in_path
    try:
        subprocess.run([EDITCAP, "-F", "pcapng", str(in_path), str(out)],
                       check=True, capture_output=True, timeout=300)
        return out
    except subprocess.CalledProcessError as e:
        VC.error(f"editcap failed: {e.stderr.decode(errors='replace')[:200]}")
        return in_path

# ── Single-pass tshark ledger extraction ─────────────────────────────────────
LEDGER_FIELDS = [
    # framing
    "frame.time_epoch","frame.len","frame.protocols",
    # eth
    "eth.src","eth.dst",
    # ip
    "ip.src","ip.dst","ipv6.src","ipv6.dst",
    # transport
    "tcp.srcport","tcp.dstport","udp.srcport","udp.dstport",
    # tls
    "tls.handshake.type","tls.handshake.version","tls.handshake.ciphersuite",
    "tls.handshake.extensions_server_name","tls.handshake.extensions_alpn_str",
    "tls.handshake.extensions.supported_version",
    "tls.alert_message.level","tls.alert_message.desc",
    "x509sat.uTF8String","x509sat.printableString",
    # dns / mdns
    "dns.qry.name","dns.flags.response","dns.resp.name",
    "dns.a","dns.aaaa",
    # dhcp — modern Wireshark renamed bootp.* to dhcp.* (the field-set
    # change shipped in Wireshark 3.x and is the only spelling tshark 4.x
    # accepts as a -e extractor).
    "dhcp.option.hostname","dhcp.option.vendor_class_id","dhcp.option.dhcp",
    # mdns
    # (mdns rides on dns.qry.name with port 5353; we infer from udp.dstport)
    # arp
    "arp.src.hw_mac","arp.src.proto_ipv4","arp.dst.proto_ipv4","arp.opcode",
    # lldp
    "lldp.tlv.system.name","lldp.tlv.system.desc",
    # smb / smbv1
    "smb.cmd","smb2.cmd",
    # llmnr / nbt-ns — LLMNR has no dedicated field set (tshark dissects it via
    # the DNS dissector); detect protocol presence via frame.protocols. NBT-NS
    # has its own flags field.
    "nbns.flags","nbns.name",
    # ssdp — also no dedicated field set (tshark dissects via the HTTP-over-UDP
    # dissector); detect via frame.protocols.
    # cleartext protocols
    "ftp.request.command","telnet.data","http.host","http.request.uri",
    "http.authbasic","snmp.community","ldap.bindRequest_element",
    # ── 2026-06-11 review additions ───────────────────────────────────
    # Kerberos — needed for AS-REQ/AS-REP/TGS-REP capture (the artifacts
    # downstream Vault uses for offline cracking and authentication
    # surface analysis).
    "kerberos.msg_type",
    "kerberos.CNameString",
    "kerberos.realm",
    "kerberos.SNameString",
    # NTLM — relay opportunity detection via NEGOTIATE_SIGN flag and
    # SMB2 per-message signing flag.
    "ntlmssp.messagetype",
    "ntlmssp.negotiateflags",
    "smb2.flags",
    "smb2.flags.signature",
    # JA3 / JA3S — TLS fingerprints. Wireshark 4.x emits these as part
    # of the TLS dissector when "Calculate JA3" is enabled (default on).
    "tls.handshake.ja3",
    "tls.handshake.ja3s",
    # IPP / MQTT / AMQP — printer-control, IoT MQTT, AMQP cleartext.
    # These do not have field-set extractors equivalent to HTTP/SMB so
    # we infer presence via frame.protocols and emit per-port findings.
]

def extract_ledger(pcap: Path) -> list[dict]:
    """One tshark pass per pcap; returns a list of per-packet dicts with
    every LEDGER_FIELDS column."""
    if not TSHARK:
        VC.error("tshark not installed — cannot analyse captures")
        return []
    cmd = [TSHARK, "-r", str(pcap), "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=a", "-E", "aggregator=;"]
    for f in LEDGER_FIELDS:
        cmd += ["-e", f]
    VC.log(f"[ledger] extracting {pcap.name} via tshark ({len(LEDGER_FIELDS)} fields)")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        VC.error(f"tshark timeout on {pcap.name}"); return []
    if proc.returncode != 0:
        VC.error(f"tshark exited {proc.returncode}",
                 detail=proc.stderr[:300]); return []
    out = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(LEDGER_FIELDS):
            parts += [""] * (len(LEDGER_FIELDS) - len(parts))
        out.append(dict(zip(LEDGER_FIELDS, parts)))
    VC.log(f"[ledger] {pcap.name}: {len(out):,} frames")
    return out

# ── OutputManager — universal Scattershot3 schema ────────────────────────────
class OutputManager:
    _findings_lock = threading.Lock()

    _PRIVATE_IP_RE = re.compile(
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3}'
        r'|169\.254\.\d{1,3}\.\d{1,3}'
        r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    )

    def __init__(self, root: str, scope: str = "int",
                 include_internal: bool = False) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.scope = scope
        self.include_internal = bool(include_internal)
        self.findings_json   = self.root / "findings.json"
        self.findings_csv    = self.root / "findings.csv"
        self.summary_json    = self.root / "summary.json"
        self.targets_json    = self.root / "targets.json"
        self.traffic_json    = self.root / "traffic.json"
        self.log_file        = self.root / "scan.log"
        self.json_log_file   = self.root / "scan.log.json"
        self.error_log       = self.root / "errors.log"
        self.meta_json       = self.root / "meta.json"
        self.inventory_dir   = self.root / "inventory"
        self.evidence_dir    = self.root / "evidence"
        self.inventory_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        # NB: scan.log.json / errors.log.json are owned by the §14j EventLogger
        # (JSONL format), so they are NOT pre-seeded here as JSON arrays.
        for p, init in [(self.findings_json, "[]\n"),
                        (self.log_file, self._hdr("Trawler scan log")),
                        (self.error_log, self._hdr("Trawler error log"))]:
            if not p.exists():
                p.write_text(init, encoding="utf-8")
        if not self.findings_csv.exists():
            self._write_csv_header()

    def _hdr(self, what: str) -> str:
        return (f"{'='*70}\n  trawler — {what}\n"
                f"  Created : {_iso()}\n{'='*70}\n\n")

    CSV_FIELDS = ["id","tool","title","datetime","ip","port","hostname",
                  "risk","command","description","output","cves","sources",
                  "service","output_file","affected","exploitdb","metasploit",
                  "exploit_details","owasp","owasp_url","nist","remediation",
                  "scope","phase","catalogue_id","impact"]

    def _write_csv_header(self) -> None:
        with self.findings_csv.open("w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=self.CSV_FIELDS,
                           extrasaction="ignore").writeheader()

    def _write_meta(self, client_short: str, target_ip: str,
                    include_internal: bool) -> None:
        meta = {
            "schema_version": "1.0",
            "tool":           "trawler",
            "tool_version":   VERSION,
            "client_short":   client_short,
            "scope":          self.scope,
            "scan_started":   _iso(),
            "target_ip":      target_ip,
            "include_internal": include_internal,
        }
        self.meta_json.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def _redact_internal_ips(self, text: str, target_ip: str) -> str:
        """When include_internal is False, replace any RFC1918/loopback/link-
        local IPv4 in `text` with '[internal]' — except the target IP itself,
        which is preserved because the finding is ABOUT it."""
        if self.include_internal or not text:
            return text
        def _sub(m):
            ip = m.group(0)
            return ip if ip == target_ip else "[internal]"
        return self._PRIVATE_IP_RE.sub(_sub, text)

    def add_finding(self, *, catalogue_id: str, title: str, ip: str,
                    port: int, risk: str, description: str, impact: str,
                    remediation: str, affected: str, output: str = "",
                    output_file: str = "", service: str = "",
                    sources: str = "trawler", phase: str = "analysis",
                    hostname: str = "", command: str = "",
                    cves: str = "", owasp: str = "", nist: str = "") -> None:
        affected    = self._redact_internal_ips(affected,    ip)
        output      = self._redact_internal_ips(output,      ip)
        description = self._redact_internal_ips(description, ip)
        entry = {
            "id":              str(uuid.uuid4()),
            "tool":            "trawler",
            "title":           title,
            "datetime":        _iso(),
            "ip":              ip,
            "port":            int(port) if port else 0,
            "hostname":        hostname or "",
            "risk":            (risk or "INFO").upper(),
            "command":         command or "trawler pcap analysis",
            "description":     description,
            "output":          output[:4096],
            "cves":            cves,
            "sources":         sources,
            "service":         service,
            "output_file":     output_file,
            "affected":        affected,
            "exploitdb":       False,
            "metasploit":      False,
            "exploit_details": [],
            "owasp":           owasp,
            "owasp_url":       "",
            "nist":            nist,
            "remediation":     remediation,
            "scope":           self.scope,
            "phase":           phase,
            "catalogue_id":    catalogue_id,
            "impact":          impact,
        }
        with self._findings_lock:
            try:
                existing = json.loads(self.findings_json.read_text(encoding="utf-8"))
                if not isinstance(existing, list): existing = []
            except Exception:
                existing = []
            existing.append(entry)
            tmp = self.findings_json.with_suffix(".tmp")
            tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            tmp.replace(self.findings_json)
            with self.findings_csv.open("a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=self.CSV_FIELDS,
                               extrasaction="ignore").writerow(entry)
        VC.log(f"[finding] {risk:<8} {title} ({ip}:{port})", "SUCCESS")

    def write_targets(self, hosts: list[dict]) -> None:
        self.targets_json.write_text(
            json.dumps({"hosts": hosts}, indent=2), encoding="utf-8")

    def write_traffic(self, per_host: dict) -> None:
        self.traffic_json.write_text(
            json.dumps(per_host, indent=2), encoding="utf-8")

    def write_summary(self, summary: dict) -> None:
        summary["scan_meta"] = {
            "tool":      "trawler",
            "version":   VERSION,
            "generated": _iso(),
            "scope":     self.scope,
        }
        self.summary_json.write_text(
            json.dumps(summary, indent=2), encoding="utf-8")

    def write_inventory(self, kind: str, data: list | dict) -> None:
        p = self.inventory_dir / f"{kind}.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def evidence_root(self, target: str) -> Path:
        d = self.evidence_dir / target.replace(":", "_")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def evidence_path(self, target: str, fname: str) -> Path:
        return self.evidence_root(target) / fname

    def add_action_item(self, *, item_type: str, recommended_tool: str,
                        target: str, ip: str, port: int, hostname: str,
                        title: str, description: str, priority: str = "MEDIUM",
                        source_finding: str = "", scope: str = "",
                        metadata: dict | None = None) -> None:
        if not hasattr(self, "_ai_items"):
            self._ai_items = []
            self._ai_seen = set()
        key = (recommended_tool.lower(), target.lower(), title.strip().lower())
        if key in self._ai_seen:
            return
        self._ai_seen.add(key)
        entry = {
            "id": str(uuid.uuid4()),
            "type": item_type,
            "recommended_tool": recommended_tool,
            "target": target,
            "ip": ip, "port": port, "hostname": hostname,
            "title": title, "description": description,
            "source_finding": source_finding,
            "priority": priority,
            "scope": scope or self.scope,
            "status": "pending",
            "datetime": _iso(),
            "metadata": metadata or {},
        }
        self._ai_items.append(entry)
        VC.action_item(entry)

    def write_action_items(self) -> None:
        items = getattr(self, "_ai_items", [])
        if not items:
            return
        ai_path = self.root / "action_items.json"
        ai_path.write_text(json.dumps(items, indent=2, default=str), encoding="utf-8")
        VC.log(f"[cross-tool] {len(items)} action item(s) written", "SUCCESS")

# ── Per-target peer rollup ───────────────────────────────────────────────────
def rollup_target(ledger: list[dict], target_ip: str) -> dict:
    """Build per-peer rollup for traffic involving target_ip."""
    peers: dict[str, dict] = {}
    proto_set: set[str] = set()
    port_with_data: set[tuple[str,int]] = set()

    for r in ledger:
        src = r.get("ip.src") or r.get("ipv6.src") or ""
        dst = r.get("ip.dst") or r.get("ipv6.dst") or ""
        if target_ip not in (src, dst):
            continue
        peer = dst if src == target_ip else src
        if not peer or peer == target_ip:
            continue
        proto_str = (r.get("frame.protocols") or "").lower()
        for marker in ("tls","tcp","udp","dns","mdns","arp","dhcp","bootp",
                        "icmp","smb","smb2","lldp","ldap","ssdp","ftp",
                        "telnet","http","quic","snmp","kerberos","llmnr","nbns"):
            if marker in proto_str:
                proto_set.add({"bootp":"dhcp"}.get(marker, marker))

        p = peers.setdefault(peer, {
            "ip":         peer,
            "tcp_ports":  set(), "udp_ports": set(),
            "snis":       set(), "tx_bytes":  0, "rx_bytes": 0,
            "frames":     0, "protocols": set(),
            "purpose":    "", "category": "",
            "finding_count": 0, "top_risk": "",
        })
        try:    blen = int(r.get("frame.len") or 0)
        except: blen = 0
        if src == target_ip: p["tx_bytes"] += blen
        else:                p["rx_bytes"] += blen
        p["frames"] += 1
        p["protocols"].update(proto_set)

        # Destination port from device's perspective
        try:
            if src == target_ip:
                tdp = int(r.get("tcp.dstport") or 0); udp = int(r.get("udp.dstport") or 0)
            else:
                tdp = int(r.get("tcp.srcport") or 0); udp = int(r.get("udp.srcport") or 0)
        except (TypeError, ValueError):
            tdp = udp = 0
        if tdp:
            p["tcp_ports"].add(tdp); port_with_data.add((peer, tdp))
        if udp:
            p["udp_ports"].add(udp); port_with_data.add((peer, udp))
        sni = r.get("tls.handshake.extensions_server_name")
        if sni: p["snis"].add(sni)
    return {"peers": peers, "ports_with_data": port_with_data,
            "protocols": proto_set}

def classify_peer(peer_ip: str, snis: set) -> tuple[str,str,str]:
    """Return (category, org, purpose) for a peer based on SNI + IP heuristics."""
    s = " ".join(snis).lower()
    if any(x in s for x in ("modulim",)):
        cat = "external-vendor"; org = "Vendor (private SNI)"
    elif any(x in s for x in ("azure-devices","blob.core.windows","azurecontainerapps",
                                "windows.net","microsoft")):
        cat = "external-vendor"; org = "Microsoft Azure"
    elif any(x in s for x in ("google","gstatic","googleapis","ggpht")):
        cat = "external-vendor"; org = "Google LLC"
    elif any(x in s for x in ("amazon","amazonaws","cloudfront","awsstatic")):
        cat = "external-vendor"; org = "Amazon AWS"
    elif any(x in s for x in ("apple","icloud","mzstatic")):
        cat = "external-vendor"; org = "Apple"
    elif is_private(peer_ip):
        cat = "internal"; org = "Internal LAN"
    elif peer_ip in ("8.8.8.8","8.8.4.4"): cat = "external-dns"; org = "Google DNS"
    elif peer_ip in ("1.1.1.1","1.0.0.1"): cat = "external-dns"; org = "Cloudflare DNS"
    elif peer_ip in ("9.9.9.9","149.112.112.112"): cat = "external-dns"; org = "Quad9 DNS"
    else:
        cat = "external"; org = "Unknown"

    purpose = ""
    if "iothub" in s: purpose = "IoT Hub (MQTT/TLS)"
    elif "blob.core.windows" in s: purpose = "Azure Blob Storage"
    elif "azurecontainerapps" in s: purpose = "Azure Container App"
    elif "mtalk.google" in s: purpose = "Google FCM push"
    elif "android.clients.google" in s: purpose = "Google Play Services"
    elif "www.google" in s: purpose = "Captive-portal / connectivity probe"
    elif cat == "external-dns": purpose = "Public DNS resolver"
    return cat, org, purpose

# ── External finding rules ───────────────────────────────────────────────────
PUBLIC_DNS = {"8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112",
              "208.67.222.222","208.67.220.220","64.6.64.6","64.6.65.6"}

def ext_check_hardcoded_dns(ledger, target, om):
    queries_per_resolver: dict[str, set[str]] = defaultdict(set)
    for r in ledger:
        if r.get("ip.src") != target: continue
        if not r.get("dns.qry.name"): continue
        if int(r.get("udp.dstport") or 0) != 53 and int(r.get("tcp.dstport") or 0) != 53:
            continue
        dst = r.get("ip.dst") or ""
        if dst:
            queries_per_resolver[dst].add(r["dns.qry.name"])
    public_used = [d for d in queries_per_resolver if d in PUBLIC_DNS]
    if not public_used: return
    body = ["DNS resolvers contacted by " + target + ":\n"]
    for d, qs in sorted(queries_per_resolver.items()):
        tag = "(HARDCODED PUBLIC)" if d in PUBLIC_DNS else "(local)"
        body.append(f"  {d:<16} {tag}  ({len(qs)} unique queries)")
        for q in sorted(qs)[:8]:
            body.append(f"      → {q}")
    ev_text = "\n".join(body)
    ev_path = om.evidence_path(target, "hardcoded_dns.txt")
    ev_path.write_text(ev_text, encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-001",
        title="Hardcoded Public DNS Resolvers Bypass Enterprise Controls",
        ip=target, port=53, risk="MEDIUM", service="dns", phase="external_dns",
        description=(
            f"Device {target} sends DNS queries directly to public resolvers "
            f"({', '.join(sorted(public_used))}) instead of using only the "
            "DHCP-supplied resolver, bypassing enterprise DNS controls."),
        impact=(
            "Enterprise DNS filtering, sinkholing, anomaly detection, split-DNS "
            "and egress logging are bypassed for the device's most security-"
            "relevant traffic. Hospital security teams cannot detect or block "
            "the device contacting unexpected endpoints, and cannot audit "
            "clinical-data exfiltration patterns. Represents a HIPAA logging-"
            "control gap."),
        remediation=(
            "1. Modify the device firmware to use only the DHCP-supplied DNS "
            "resolver (DHCP option 6).\n"
            "2. Implement DoH/DoT to whatever resolver is selected.\n"
            "3. Provide a deployment-time configuration toggle for hospital IT "
            "to constrain the device to a specific resolver."),
        affected="\n".join(f"{target} → {d}:53 (UDP)" for d in sorted(queries_per_resolver)),
        output=ev_text[:2000],
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A09:2021 Security Logging and Monitoring Failures",
        nist="SC-20 Secure Name/Address Resolution; SC-7 Boundary Protection",
    )

def ext_check_cleartext_dns(ledger, target, om):
    queried_hosts: set[str] = set()
    for r in ledger:
        if r.get("ip.src") != target: continue
        if int(r.get("udp.dstport") or 0) != 53 and int(r.get("tcp.dstport") or 0) != 53:
            continue
        q = r.get("dns.qry.name") or ""
        if q: queried_hosts.add(q)
    if not queried_hosts: return
    ev_path = om.evidence_path(target, "cleartext_dns_queries.txt")
    ev_path.write_text("Cleartext DNS hostnames queried:\n" +
                       "\n".join(f"  {q}" for q in sorted(queried_hosts)),
                       encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-002",
        title="Cleartext DNS Exposes External Service Topology",
        ip=target, port=53, risk="LOW", service="dns", phase="external_dns",
        description=(
            "All DNS queries are sent over cleartext UDP/53. Any on-path observer "
            "can enumerate the full set of external services the device depends "
            f"on ({len(queried_hosts)} distinct hostnames observed)."),
        impact=(
            "An attacker who can passively observe device traffic learns the "
            "entire backend architecture without active probing — cloud-provider "
            "endpoints, push-notification dependencies, captive-portal probe "
            "destinations and SaaS services in use."),
        remediation=(
            "Implement DNS-over-HTTPS (RFC 8484) or DNS-over-TLS (RFC 7858) on "
            "the device. Use a privacy-respecting resolver that the hospital "
            "network can also operate."),
        affected=f"All outbound DNS from {target}",
        output="\n".join(sorted(queried_hosts))[:2000],
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A09:2021 Security Logging and Monitoring Failures",
        nist="SC-8 Transmission Confidentiality and Integrity",
    )

def ext_check_tls_client_cert_cn(ledger, target, om):
    """When the device sends a TLS Certificate (handshake.type=11) to an
    external peer, capture the Subject CN — that's mTLS client-cert leak."""
    sample = None
    for r in ledger:
        if r.get("ip.src") != target: continue
        if (r.get("tls.handshake.type") or "").split(";")[0] != "11":
            continue
        peer = r.get("ip.dst") or ""
        if is_private(peer): continue
        cn = (r.get("x509sat.uTF8String") or r.get("x509sat.printableString") or "")
        if cn:
            sample = (peer, cn); break
    if not sample: return
    peer, cn = sample
    ev_path = om.evidence_path(target, "tls_client_cert_cn.txt")
    ev_path.write_text(f"TLS Certificate sent by {target} → {peer}\n"
                       f"x509 Subject content (first):\n  {cn}\n", encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-003",
        title="Device Identity Leaked in TLS Client Certificate (mTLS handshake)",
        ip=target, port=443, risk="LOW", service="tls",
        phase="external_tls",
        description=(
            "The device authenticates to an external endpoint with a client X.509 "
            "certificate (mTLS). The certificate subject is sent in cleartext "
            "during the handshake and exposes identifying information."),
        impact=(
            "Passive observers (segments with SPAN, ISP-level observers, "
            "downstream intermediaries) can extract the device's identity from "
            "the TLS handshake bytes. Privacy-relevant in clinical contexts."),
        remediation=(
            "Use an opaque per-device identifier (UUID) as the Subject CN. Move "
            "the human-readable serial / model into a custom certificate "
            "extension or SubjectAltName otherName."),
        affected=f"{target} → {peer} (TLS mTLS handshake)",
        output=f"x509 Subject content observed: {cn}",
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-17 PKI Certificates",
    )

# Cipher suites considered "legacy CBC" worth flagging
LEGACY_CBC_SUITES = {"0xc024","0xc023","0xc028","0xc027","0xc013","0xc014",
                     "0x002f","0x0035","0x003c","0x003d","0x0009","0x002f"}
def ext_check_tls_cbc_ciphers(ledger, target, om):
    seen_cbc: set[str] = set()
    for r in ledger:
        if r.get("ip.src") != target: continue
        if (r.get("tls.handshake.type") or "").split(";")[0] != "1": continue
        suites = (r.get("tls.handshake.ciphersuite") or "").replace(";",",").lower()
        for s in suites.split(","):
            s = s.strip()
            if s in LEGACY_CBC_SUITES:
                seen_cbc.add(s)
    if not seen_cbc: return
    ev_path = om.evidence_path(target, "tls_cbc_ciphers.txt")
    ev_path.write_text(
        f"TLS ClientHello cipher suites offered by {target}\n"
        f"Legacy CBC suites observed:\n  " + "\n  ".join(sorted(seen_cbc)),
        encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-004",
        title="TLS ClientHello Offers Legacy CBC Cipher Suites",
        ip=target, port=443, risk="LOW", service="tls",
        phase="external_tls",
        description=(
            "The device's TLS ClientHello offers legacy CBC-mode cipher suites "
            f"({', '.join(sorted(seen_cbc))}) alongside modern AEAD ciphers. "
            "While AEAD is typically negotiated, the CBC offer preserves a "
            "downgrade surface."),
        impact=(
            "CBC suites are vulnerable to historical attacks (BEAST, Lucky13, "
            "POODLE-variants) when paired with TLS 1.0/1.1. In TLS 1.2 with "
            "correct implementation the practical exploit cost is high but the "
            "offer is unnecessary given AEAD alternatives are universally "
            "supported."),
        remediation=(
            "Remove CBC cipher suites from the device's TLS ClientHello offer "
            "list. Keep only the AEAD set: TLS 1.3 (0x1301/02/03) and TLS 1.2 "
            "ECDHE-AEAD (0xc02c/2b/30/2f)."),
        affected=f"TLS ClientHello from {target}",
        output=f"Legacy CBC suites: {', '.join(sorted(seen_cbc))}",
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-13 Cryptographic Protection",
    )

def ext_check_dhcp_hostname(ledger, target, om):
    """DHCP option 12 leaking an identifier."""
    hostnames: set[str] = set()
    for r in ledger:
        # DHCP source 0.0.0.0 or assigned IP; we don't always know target before lease
        h = r.get("dhcp.option.hostname")
        if h and (r.get("ip.src") in (target, "0.0.0.0") or h):
            hostnames.add(h)
    # Match against any hostname; if exactly the target appeared in DHCP, flag
    hostnames = {h for h in hostnames if h}
    if not hostnames: return
    ev_path = om.evidence_path(target, "dhcp_hostname.txt")
    ev_path.write_text(
        f"DHCP Option 12 hostname values observed:\n  " +
        "\n  ".join(sorted(hostnames)),
        encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-005",
        title="DHCP Hostname Discloses Asset Identifier",
        ip=target, port=68, risk="MEDIUM", service="dhcp",
        phase="external_dhcp",
        description=(
            "The device populates DHCP option 12 (Host Name) with an identifier "
            f"({', '.join(sorted(hostnames))[:200]}) that is broadcast on every "
            "DHCP DISCOVER/REQUEST."),
        impact=(
            "Any host on the broadcast domain can passively map the device's "
            "MAC and IP to the broadcast asset tag — vendor, model and serial "
            "are derivable without sending a single packet."),
        remediation=(
            "Replace the DHCP Host Name with an opaque per-device identifier "
            "(UUID or salted hash). The true serial number should only travel "
            "inside the encrypted device-to-cloud channel."),
        affected=f"DHCP broadcasts from {target}",
        output="\n".join(sorted(hostnames))[:1000],
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A01:2021 Broken Access Control",
        nist="SC-7 Boundary Protection",
    )

def ext_check_dns_suffix_appending(ledger, target, om):
    """Detect FQDN.<search-suffix> pattern in DNS queries — RFC 1535/8767
    violation by the resolver."""
    bad_queries: set[str] = set()
    for r in ledger:
        if r.get("ip.src") != target: continue
        q = r.get("dns.qry.name") or ""
        if not q: continue
        # Heuristic: queries with ≥4 labels ending in .lan / .local (other
        # than .arpa) AND containing a likely-fqdn middle (core.windows / azure /
        # googleapis / aws / cloud / com / net)
        labels = q.rstrip(".").split(".")
        if len(labels) < 4: continue
        tld = labels[-1].lower()
        if tld in ("arpa",): continue
        suspect_tlds = ("lan","local","intra","internal","corp","home","prv","priv")
        if tld not in suspect_tlds: continue
        # And earlier labels look like a real FQDN
        if any(t in ".".join(labels[:-1]).lower() for t in (
              "windows.net","azure","amazonaws","googleapis","cloud","cdn",
              "blob.core","akamai","fastly","cloudflare","cloudfront",
              "akadns","trafficmanager")):
            bad_queries.add(q)
    if not bad_queries: return
    ev_path = om.evidence_path(target, "dns_suffix_bug.txt")
    ev_path.write_text(
        f"Likely FQDN+search-suffix bug observed:\n  " +
        "\n  ".join(sorted(bad_queries)),
        encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-006",
        title="DNS Search-Suffix Appended to Fully-Qualified Hostnames",
        ip=target, port=53, risk="MEDIUM", service="dns",
        phase="external_dns",
        description=(
            "The device's DNS client appends the DHCP-supplied search domain to "
            "hostnames that are already fully-qualified. RFC 1535 and RFC 8767 "
            "require resolvers not to apply search-suffix processing to FQDNs."),
        impact=(
            "An attacker controlling the search-suffix DNS zone can redirect the "
            "device's cloud traffic to attacker-controlled IPs. TLS server "
            "certificate validation usually catches the substitution, but the "
            "failure mode leaks connection metadata on every retry. If cert "
            "pinning is incorrectly implemented, the substitution succeeds."),
        remediation=(
            "Patch the device DNS client so hostnames with three or more labels "
            "(or a trailing dot) bypass search-domain processing. Set 'ndots' to "
            "1 (POSIX style)."),
        affected=f"DNS resolver in {target}",
        output="\n".join(sorted(bad_queries))[:1500],
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A04:2021 Insecure Design",
        nist="SC-20 Secure Name/Address Resolution; SI-10 Input Validation",
    )

# ─────────────────────────────────────────────────────────────────────────────
# Defensive baseline rule — outbound protocol / destination catalogue
# Added in v1.1.0.  Emits one Informational finding per target listing every
# unique (destination, protocol, TLS version) triple observed outbound.  Acts
# as the documented network-baseline allow-list for the device.
# ─────────────────────────────────────────────────────────────────────────────

# legacy version field → human label.  TLS 1.3 advertises 0x0303 as the
# legacy_version in the ServerHello and the real version in the
# supported_versions extension (0x0304).
_TLS_VER_LABEL = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

def _tls_label(legacy: str, supported: str) -> str:
    """Resolve the negotiated TLS version from the ServerHello fields."""
    sup = (supported or "").strip().split(",")[0].strip().lower()
    leg = (legacy    or "").strip().split(",")[0].strip().lower()
    if sup in _TLS_VER_LABEL: return _TLS_VER_LABEL[sup]
    if leg in _TLS_VER_LABEL: return _TLS_VER_LABEL[leg]
    return ""

def ext_check_outbound_protocol_catalogue(ledger, target, om):
    """Catalogue every unique outbound (destination, protocol, TLS version)
    seen from the target.  Emitted as an Informational finding that serves as
    the documented network baseline for the device."""

    # 1. DNS reverse map (IP → FQDN) from observed A / AAAA answers
    ip_to_name: dict[str, str] = {}
    for r in ledger:
        a_records   = (r.get("dns.a")    or "").strip()
        aaaa_records = (r.get("dns.aaaa") or "").strip()
        if not a_records and not aaaa_records: continue
        name = (r.get("dns.qry.name") or "").strip().lower()
        if not name: continue
        for ip in (a_records.split(",") + aaaa_records.split(",")):
            ip = ip.strip()
            if ip and ip not in ip_to_name:
                ip_to_name[ip] = name

    # 2. Per-peer TLS version map from ServerHello frames headed back to target
    tls_by_peer: dict[str, str] = {}
    for r in ledger:
        if r.get("ip.dst") != target: continue
        if (r.get("tls.handshake.type") or "").strip().split(",")[0] != "2":
            continue
        peer = r.get("ip.src") or ""
        if not peer: continue
        label = _tls_label(r.get("tls.handshake.version"),
                           r.get("tls.handshake.extensions.supported_version"))
        if label and peer not in tls_by_peer:
            tls_by_peer[peer] = label

    # 3. Walk outbound packets and group into unique sets
    entries: dict[tuple, dict] = {}
    for r in ledger:
        if r.get("ip.src") != target: continue
        dst = r.get("ip.dst") or ""
        if not dst: continue
        try:
            tdp = int((r.get("tcp.dstport") or "0").split(",")[0])
            udp = int((r.get("udp.dstport") or "0").split(",")[0])
        except (TypeError, ValueError):
            tdp = udp = 0
        proto_str = (r.get("frame.protocols") or "").lower()
        sni = (r.get("tls.handshake.extensions_server_name") or "").strip()

        # Protocol descriptor
        if "mdns" in proto_str:                    pdesc = "mDNS over UDP/5353"
        elif "llmnr" in proto_str:                 pdesc = "LLMNR over UDP/5355"
        elif "nbns" in proto_str:                  pdesc = "NBT-NS over UDP/137"
        elif "ssdp" in proto_str:                  pdesc = "SSDP over UDP/1900"
        elif "dhcp" in proto_str or "bootp" in proto_str:
                                                    pdesc = "DHCP over UDP/67-68"
        elif "dns"  in proto_str and udp == 53:    pdesc = "DNS over UDP/53"
        elif "dns"  in proto_str and tdp == 53:    pdesc = "DNS over TCP/53"
        elif "igmp" in proto_str:                  pdesc = "IGMP"
        elif "icmp" in proto_str:                  pdesc = "ICMP"
        elif "arp"  in proto_str:                  pdesc = "ARP"
        elif "quic" in proto_str:                  pdesc = f"QUIC over UDP/{udp or 443}"
        elif tdp == 8883:                           pdesc = "MQTT over TLS, TCP/8883"
        elif "tls"  in proto_str and tdp:          pdesc = f"TLS over TCP/{tdp}"
        elif tdp:                                   pdesc = f"TCP/{tdp}"
        elif udp:                                   pdesc = f"UDP/{udp}"
        else:                                       pdesc = "raw"

        # TLS version label.  For QUIC, RFC 9001 mandates TLS 1.3.
        tls_label = ""
        if "quic" in proto_str:
            tls_label = "TLS 1.3"
        elif "tls" in proto_str or tdp in (443, 5228, 8883):
            tls_label = tls_by_peer.get(dst, "")

        name = sni or ip_to_name.get(dst, "")
        display = f"{name}  ({dst})" if name else dst
        key = (display, pdesc, tls_label)
        if key not in entries:
            cat, org, purpose = classify_peer(dst, {sni} if sni else set())
            entries[key] = {
                "destination": display, "protocol": pdesc,
                "tls_version": tls_label, "category": cat,
                "org": org, "purpose": purpose,
                "dest_ip": dst, "dest_name": name,
            }

    if not entries: return

    sorted_entries = sorted(
        entries.values(),
        key=lambda e: (0 if is_private(e["dest_ip"]) else 1,
                       e["destination"], e["protocol"]))

    # Human-readable evidence
    lines = [f"Outbound destinations and protocols observed from {target}",
             "Format: destination | description | protocol | TLS version", ""]
    for e in sorted_entries:
        desc = e["purpose"] or e["org"] or e["category"] or "unclassified"
        tls  = e["tls_version"] or "—"
        lines.append(f"  {e['destination']}")
        lines.append(f"      {desc}")
        lines.append(f"      {e['protocol']}   [{tls}]")
        lines.append("")
    ev_path = om.evidence_path(target, "outbound_protocols.txt")
    ev_path.write_text("\n".join(lines), encoding="utf-8")

    # Machine-readable evidence
    js_path = om.evidence_path(target, "outbound_protocols.json")
    js_path.write_text(json.dumps(sorted_entries, indent=2), encoding="utf-8")

    om.add_finding(
        catalogue_id="PT-010",
        title="Outbound Protocols and Destinations Observed (Defensive Catalogue)",
        ip=target, port=0, risk="INFO", service="network",
        phase="external_protocol_catalogue",
        description=(
            f"CISO catalogued every unique destination and protocol combination "
            f"observed originating from {target} across the supplied packet "
            f"captures. {len(sorted_entries)} unique combinations identified, "
            "annotated with the negotiated TLS version where applicable. The "
            "catalogue serves as a documented network baseline against which "
            "future captures can be compared — any unfamiliar destination "
            "appearing in future traffic is the actionable event."),
        impact=(
            "Positive impact: the device's outbound surface is small, "
            "well-defined and entirely encrypted at the transport layer for "
            "external destinations. The catalogue documents the operational "
            "baseline and is the authoritative scope for any perimeter egress "
            "allow-listing the deployment environment chooses to enforce."),
        remediation=(
            "1) Treat this catalogue as the device's network-baseline allow-list "
            "and re-validate it after every firmware release. 2) Where the "
            "deployment environment supports egress allow-listing, configure the "
            "perimeter to permit only the documented FQDNs over the documented "
            "protocols and ports. 3) If a future release adds a new external "
            "dependency, publish an updated baseline alongside the release notes."),
        affected=f"All outbound traffic from {target}",
        output="\n".join(lines[:60])[:4096],
        output_file=str(ev_path.relative_to(om.root)),
        owasp="A09:2021 Security Logging and Monitoring Failures",
        nist="SC-7 Boundary Protection; AU-12 Audit Generation",
    )

EXTERNAL_CHECKS = [
    ext_check_hardcoded_dns,
    ext_check_cleartext_dns,
    ext_check_tls_client_cert_cn,
    ext_check_tls_cbc_ciphers,
    ext_check_dhcp_hostname,
    ext_check_dns_suffix_appending,
    ext_check_outbound_protocol_catalogue,
]


# ── Threat-intelligence peer checks ─────────────────────────────────────────
# These run separately (need threat_db param) after the standard EXTERNAL_CHECKS.

def ext_check_threat_intel_peers(ledger, target, om, threat_db):
    """Check every unique external peer against threat-intel blocklists."""
    if threat_db is None:
        return
    seen_peers: set[str] = set()
    for r in ledger:
        src = r.get("ip.src") or r.get("ipv6.src") or ""
        dst = r.get("ip.dst") or r.get("ipv6.dst") or ""
        if target not in (src, dst):
            continue
        peer = dst if src == target else src
        if peer and not is_private(peer) and peer != target:
            seen_peers.add(peer)

    known_hits: list[dict] = []
    suspected_hits: list[dict] = []

    for peer_ip in sorted(seen_peers):
        hit = threat_db.lookup_ip(peer_ip)
        if not hit:
            continue
        geo = threat_db.geoip(peer_ip)
        hit_record = hit.as_dict()
        if geo:
            hit_record["country_code"] = geo.country_code
            hit_record["country_name"] = geo.country_name

        # Write evidence file
        ev_dir = om.evidence_root(target) / "threat_intel"
        ev_dir.mkdir(parents=True, exist_ok=True)
        ev_path = ev_dir / f"{peer_ip.replace(':','_')}_threat_hit.json"
        ev_path.write_text(json.dumps(hit_record, indent=2), encoding="utf-8")

        country_str = ""
        if geo:
            country_str = f" (Country: {geo.country_name} [{geo.country_code}])"

        if hit.classification == "known_malicious":
            known_hits.append(hit_record)
            om.add_finding(
                catalogue_id="PT-TI-001",
                title=f"Outbound Connection to Known Malicious IP ({peer_ip})",
                ip=target, port=0, risk="HIGH", service="network",
                phase="threat_intelligence",
                hostname="",
                description=(
                    f"Device {target} communicated with {peer_ip}{country_str}, "
                    f"which is listed as KNOWN MALICIOUS on {len(hit.sources)} "
                    f"threat-intelligence feed(s): {', '.join(hit.sources)}. "
                    f"Tags: {', '.join(hit.tags)}."),
                impact=(
                    f"Communication with a confirmed malicious IP indicates "
                    f"possible C2 callback, data exfiltration, or malware "
                    f"download activity. The IP appears on curated blocklists "
                    f"maintained by abuse.ch, Spamhaus, and/or Emerging Threats "
                    f"— sources with very low false-positive rates. Immediate "
                    f"investigation of {target} is warranted."),
                remediation=(
                    f"1. Block {peer_ip} at the perimeter firewall immediately.\n"
                    f"2. Investigate {target} for compromise indicators — check "
                    f"running processes, scheduled tasks, startup items.\n"
                    f"3. Review the full traffic capture for data sent to this IP.\n"
                    f"4. If confirmed compromised, isolate {target} and begin "
                    f"incident response."),
                affected=f"{target} → {peer_ip}",
                output=json.dumps(hit_record, indent=2)[:4096],
                output_file=str(ev_path.relative_to(om.root)),
                owasp="A09:2021 Security Logging and Monitoring Failures",
                nist="SI-4 System Monitoring; IR-4 Incident Handling",
            )
        else:
            suspected_hits.append(hit_record)
            om.add_finding(
                catalogue_id="PT-TI-002",
                title=f"Outbound Connection to Suspected Malicious IP ({peer_ip})",
                ip=target, port=0, risk="MEDIUM", service="network",
                phase="threat_intelligence",
                hostname="",
                description=(
                    f"Device {target} communicated with {peer_ip}{country_str}, "
                    f"which is listed as SUSPECTED on {len(hit.sources)} "
                    f"threat-intelligence feed(s): {', '.join(hit.sources)}. "
                    f"Tags: {', '.join(hit.tags)}. "
                    f"Note: suspected listings come from honeypot, crowdsourced, "
                    f"or scan-activity sources and have a moderate false-positive "
                    f"rate — manual verification is recommended."),
                impact=(
                    f"The destination IP has been reported for suspicious "
                    f"activity (scanning, brute-force, or poor reputation) by "
                    f"community-driven sources. While not confirmed malicious, "
                    f"the communication warrants investigation — especially if "
                    f"{target} is not expected to reach arbitrary internet hosts."),
                remediation=(
                    f"1. Verify whether {peer_ip} is a legitimate service endpoint "
                    f"for {target}'s expected operation.\n"
                    f"2. If not expected, investigate {target} for compromise.\n"
                    f"3. Consider blocking {peer_ip} at the perimeter if no "
                    f"legitimate purpose is identified."),
                affected=f"{target} → {peer_ip}",
                output=json.dumps(hit_record, indent=2)[:4096],
                output_file=str(ev_path.relative_to(om.root)),
                owasp="A09:2021 Security Logging and Monitoring Failures",
                nist="SI-4 System Monitoring",
            )

    if known_hits or suspected_hits:
        VC.log(f"[threat-intel] {target}: {len(known_hits)} known malicious, "
               f"{len(suspected_hits)} suspected out of {len(seen_peers)} "
               f"external peers checked", "WARNING" if known_hits else "INFO")


def write_threat_intel_report(om, all_traffic, threat_db):
    """Write a consolidated threat_intel_report.json to the run dir."""
    if threat_db is None:
        return
    report: dict[str, dict] = {}
    total_ext_checked = 0

    for target_ip, rec in all_traffic.items():
        for peer in rec.get("external_peers", []):
            peer_ip = peer.get("ip", "")
            if not peer_ip:
                continue
            total_ext_checked += 1
            hit = threat_db.lookup_ip(peer_ip)
            if not hit:
                continue
            geo = threat_db.geoip(peer_ip)
            if peer_ip not in report:
                report[peer_ip] = {
                    "ip": peer_ip,
                    "classification": hit.classification,
                    "sources": hit.sources,
                    "tags": hit.tags,
                    "confidence": hit.confidence,
                    "risk": hit.risk,
                    "country_code": geo.country_code if geo else "",
                    "country_name": geo.country_name if geo else "",
                    "communicating_targets": [],
                }
            if target_ip not in report[peer_ip]["communicating_targets"]:
                report[peer_ip]["communicating_targets"].append(target_ip)

    known_count = sum(1 for v in report.values()
                      if v["classification"] == "known_malicious")
    suspected_count = sum(1 for v in report.values()
                          if v["classification"] == "suspected")

    output = {
        "generated": _iso(),
        "tool": "trawler",
        "version": VERSION,
        "summary": {
            "total_external_peers_checked": total_ext_checked,
            "unique_external_peers": len({p.get("ip","") for r in all_traffic.values()
                                          for p in r.get("external_peers",[])}),
            "known_malicious_ips": known_count,
            "suspected_malicious_ips": suspected_count,
            "clean_ips": total_ext_checked - known_count - suspected_count,
            "blocklist_stats": threat_db.stats(),
        },
        "malicious_peers": sorted(report.values(),
                                   key=lambda x: (0 if x["classification"] == "known_malicious" else 1,
                                                  x["ip"])),
    }
    path = om.root / "threat_intel_report.json"
    path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    VC.log(f"[threat-intel] report written: {known_count} known malicious, "
           f"{suspected_count} suspected across {total_ext_checked} peers",
           "SUCCESS" if known_count == 0 else "WARNING")


# ── Internal finding rules ───────────────────────────────────────────────────
def int_check_smbv1(ledger, target, om):
    """smb.cmd field exists only for SMBv1 (smb2.cmd for SMB2/3)."""
    peers: set[str] = set()
    for r in ledger:
        if not r.get("smb.cmd"): continue
        if target not in (r.get("ip.src"), r.get("ip.dst")): continue
        peer = r.get("ip.dst") if r.get("ip.src") == target else r.get("ip.src")
        if peer and is_private(peer or ""): peers.add(peer)
    if not peers: return
    ev_path = om.evidence_path(target, "smbv1_peers.txt")
    ev_path.write_text("SMBv1 peers (private):\n  " + "\n  ".join(sorted(peers)),
                       encoding="utf-8")
    om.add_finding(
        catalogue_id="PT-101",
        title="SMBv1 Traffic Observed (EternalBlue / NotPetya exposure)",
        ip=target, port=445, risk="HIGH", service="smb",
        phase="internal_smb",
        description=(
            f"SMBv1 protocol traffic observed between {target} and {len(peers)} "
            "internal peer(s). SMBv1 is deprecated since 2014 and is the "
            "transport for EternalBlue (MS17-010) / WannaCry / NotPetya."),
        impact=(
            "Active SMBv1 on a clinical network creates a worm propagation path. "
            "Disable per FDA Postmarket Cybersecurity Guidance and Joint "
            "Commission EHR-protection expectations."),
        remediation=(
            "Disable SMBv1 on every host. Confirm SMB2+ minimum on file servers "
            "(`Set-SmbServerConfiguration -EnableSMB1Protocol $false`) and on "
            "Windows/Linux/embedded clients. Block 445/tcp at the segmentation "
            "boundary."),
        affected="\n".join(f"{target} ↔ {p}:445/tcp" for p in sorted(peers)),
        output="Internal peers using SMBv1:\n" + "\n".join(sorted(peers)),
        output_file=str(ev_path.relative_to(om.root)),
        cves="CVE-2017-0143 CVE-2017-0144 CVE-2017-0145 CVE-2017-0146 CVE-2017-0148",
        owasp="A05:2021 Security Misconfiguration",
        nist="CM-7 Least Functionality; SI-2 Flaw Remediation",
    )

def int_check_llmnr_nbtns(ledger, target, om):
    # LLMNR has no dedicated tshark field set — it rides on the DNS dissector.
    # Detect via frame.protocols containing 'llmnr'. NBT-NS has its own flags.
    seen_llmnr = any("llmnr" in (r.get("frame.protocols") or "").lower()
                     and target in (r.get("ip.src"), r.get("ip.dst"))
                     for r in ledger)
    seen_nbtns = any(r.get("nbns.flags") and target in (r.get("ip.src"), r.get("ip.dst"))
                     for r in ledger)
    if not (seen_llmnr or seen_nbtns): return
    parts = []
    if seen_llmnr: parts.append("LLMNR (UDP/5355)")
    if seen_nbtns: parts.append("NetBIOS Name Service (UDP/137)")
    om.add_finding(
        catalogue_id="PT-102",
        title="LLMNR / NBT-NS Name Resolution in Use (Responder Attack Surface)",
        ip=target, port=5355 if seen_llmnr else 137,
        risk="HIGH", service="llmnr/nbns",
        phase="internal_name_resolution",
        description=(
            f"Name-resolution fallback observed on {target}: {', '.join(parts)}. "
            "These broadcast-based protocols are abused by Responder / Inveigh "
            "to poison name resolution and capture NTLMv2 hashes."),
        impact=(
            "An attacker on the same broadcast domain runs `responder -I eth0` "
            "and captures hashes from any device that mistypes a hostname or "
            "uses a non-FQDN lookup. Hashes are crackable offline or relayed via "
            "ntlmrelayx for immediate authentication elsewhere."),
        remediation=(
            "Disable LLMNR (GPO: Turn Off Multicast Name Resolution = Enabled) "
            "and NBT-NS (interface property → WINS → Disable NetBIOS over "
            "TCP/IP). Block UDP/5355 and UDP/137 at every L3 boundary."),
        affected=f"{target} broadcasts {', '.join(parts)}",
        output=f"Name-resolution broadcasts observed: {', '.join(parts)}",
        owasp="A07:2021 Identification and Authentication Failures",
        nist="SC-7 Boundary Protection; CM-7 Least Functionality",
    )

def int_check_ssdp(ledger, target, om):
    # SSDP is HTTP-over-UDP (port 1900); tshark dissects it via the HTTP
    # dissector and exposes it through frame.protocols rather than a
    # dedicated ssdp.* field set.
    peers: set[str] = set()
    for r in ledger:
        if "ssdp" not in (r.get("frame.protocols") or "").lower(): continue
        if target in (r.get("ip.src"), r.get("ip.dst")):
            peer = r.get("ip.dst") if r.get("ip.src") == target else r.get("ip.src")
            if peer: peers.add(peer)
    if not peers: return
    om.add_finding(
        catalogue_id="PT-103",
        title="SSDP Broadcasts Expose Internal Services (UPnP Discovery)",
        ip=target, port=1900, risk="LOW", service="ssdp",
        phase="internal_discovery",
        description=(
            f"SSDP/UPnP discovery traffic observed between {target} and "
            f"{len(peers)} peer(s). SSDP advertises every UPnP-aware device on "
            "the local broadcast domain."),
        impact=(
            "SSDP discovery reveals consumer-IoT, printers, smart TVs, NAS and "
            "router admin interfaces to anyone on the LAN. In a clinical network "
            "this co-mingles consumer devices with medical equipment and "
            "facilitates lateral discovery."),
        remediation=(
            "Disable UPnP/SSDP on all clinical-network hosts where not required. "
            "Block UDP/1900 at every L3 boundary."),
        affected=f"{target} ↔ " + ", ".join(sorted(peers)[:10]),
        output=f"SSDP peers: {', '.join(sorted(peers))}",
        nist="CM-7 Least Functionality",
    )

def int_check_mdns_internal_leak(ledger, target, om):
    """mDNS query/response activity from target on the internal segment."""
    activity = 0
    for r in ledger:
        if int(r.get("udp.dstport") or 0) == 5353 or int(r.get("udp.srcport") or 0) == 5353:
            if target in (r.get("ip.src"), r.get("ip.dst")):
                activity += 1
    if activity < 5: return
    om.add_finding(
        catalogue_id="PT-104",
        title="mDNS Activity on Internal Segment (Device Discovery Surface)",
        ip=target, port=5353, risk="LOW", service="mdns",
        phase="internal_discovery",
        description=(
            f"{activity:,} mDNS frames observed involving {target}. mDNS exposes "
            "the device's hostname and services to any host on the multicast-"
            "reachable segment, and is reflected across L3 by mDNS-reflector-"
            "enabled gateways."),
        impact=(
            "Device fingerprinting and asset enumeration without active probing. "
            "Reduces the cost of targeting a specific device for theft, support-"
            "call social engineering, or RF replay."),
        remediation=(
            "Disable mDNS on the device if not required by the deployment. "
            "Audit network-side mDNS reflector configuration (Avahi `reflector="
            "yes`, UniFi 'Multicast DNS') and disable cross-VLAN reflection."),
        affected=f"mDNS multicast traffic from/to {target}",
        output=f"{activity:,} mDNS frames",
        nist="CM-7 Least Functionality",
    )

def int_check_lldp(ledger, target, om):
    """LLDP TLVs received by the target (or sent) — switch info disclosure."""
    samples: set[str] = set()
    for r in ledger:
        s = r.get("lldp.tlv.system.name"); d = r.get("lldp.tlv.system.desc")
        if s or d:
            samples.add(f"{s or '?'} / {d or '?'}")
    if not samples: return
    om.add_finding(
        catalogue_id="PT-105",
        title="LLDP Topology / Switch Firmware Information Disclosure",
        ip=target, port=0, risk="LOW", service="lldp",
        phase="internal_discovery",
        description=(
            "LLDP TLVs observed on the segment leak switch identity, model and "
            "firmware. Information that downstream attackers can use to select "
            "vendor-specific CVEs."),
        impact=(
            "An attacker passively learns the network gear vendor, model and "
            "firmware version without sending any probes. Combined with public "
            "CVE databases this is a free vulnerability-research head-start."),
        remediation=(
            "Disable LLDP on access ports facing devices (`no lldp transmit` / "
            "`no lldp receive`). Keep LLDP only on inter-switch trunks."),
        affected=f"Segment reachable by {target}",
        output="\n".join(f"  {s}" for s in sorted(samples)),
        nist="SC-7 Boundary Protection",
    )

def int_check_arp_anomalies(ledger, target, om):
    """Detect duplicate IP-to-MAC mappings or excessive gratuitous ARP."""
    mac_for_ip: dict[str, set[str]] = defaultdict(set)
    for r in ledger:
        ip = r.get("arp.src.proto_ipv4") or ""
        mac = r.get("arp.src.hw_mac") or ""
        if ip and mac:
            mac_for_ip[ip].add(mac)
    dupes = {ip: macs for ip, macs in mac_for_ip.items() if len(macs) > 1}
    if not dupes: return
    body = "\n".join(f"  {ip} → {', '.join(sorted(macs))}"
                     for ip, macs in dupes.items())
    om.add_finding(
        catalogue_id="PT-106",
        title="ARP Anomalies (Duplicate IP-to-MAC Mappings)",
        ip=target, port=0, risk="MEDIUM", service="arp",
        phase="internal_discovery",
        description=(
            f"Duplicate ARP entries observed: {len(dupes)} IP(s) advertised by "
            "multiple MAC addresses. Possible legitimate HA pair, gratuitous "
            "ARP storm, or active ARP-spoofing / MitM."),
        impact=(
            "If the duplicate is a MitM attack, the attacker is intercepting "
            "traffic between the device and another host. Even when legitimate "
            "(HA failover), the unannounced duplicate breaks deterministic "
            "L2 routing and can drop packets."),
        remediation=(
            "Investigate each duplicate. Configure DAI (Dynamic ARP Inspection) "
            "on managed switches to drop spoofed gratuitous ARP. Bind static "
            "IP↔MAC for critical clinical-device subnets."),
        affected=f"Segment reachable by {target}",
        output=body[:2000],
        nist="SC-7 Boundary Protection",
    )

def int_check_cleartext_ftp(ledger, target, om):
    """ftp.request.command captured = cleartext FTP."""
    peers: set[str] = set()
    for r in ledger:
        if not r.get("ftp.request.command"): continue
        if target in (r.get("ip.src"), r.get("ip.dst")):
            peer = r.get("ip.dst") if r.get("ip.src") == target else r.get("ip.src")
            if peer: peers.add(peer)
    if not peers: return
    om.add_finding(
        catalogue_id="PT-107",
        title="Cleartext FTP Traffic Observed (credentials in plaintext)",
        ip=target, port=21, risk="HIGH", service="ftp",
        phase="internal_cleartext",
        description=(
            "FTP control-channel traffic observed in cleartext between "
            f"{target} and {len(peers)} peer(s). FTP USER/PASS commands and "
            "file contents are passively captureable."),
        impact=(
            "Any L2 / SPAN / wifi-sniffing attacker can capture FTP credentials "
            "and uploaded/downloaded file content. In a clinical setting this "
            "may include device firmware, calibration data, or PHI."),
        remediation=(
            "Disable FTP. Use SFTP (SSH) or FTPS (FTP over TLS, explicit AUTH "
            "TLS or implicit on port 990). Block 21/tcp at the segmentation "
            "boundary."),
        affected="\n".join(f"{target} ↔ {p}:21/tcp" for p in sorted(peers)),
        output=f"FTP peers: {', '.join(sorted(peers))}",
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-8 Transmission Confidentiality and Integrity",
    )

def int_check_cleartext_telnet(ledger, target, om):
    peers: set[str] = set()
    for r in ledger:
        if not r.get("telnet.data"): continue
        if target in (r.get("ip.src"), r.get("ip.dst")):
            peer = r.get("ip.dst") if r.get("ip.src") == target else r.get("ip.src")
            if peer: peers.add(peer)
    if not peers: return
    om.add_finding(
        catalogue_id="PT-108",
        title="Cleartext Telnet Traffic Observed",
        ip=target, port=23, risk="HIGH", service="telnet",
        phase="internal_cleartext",
        description=(
            f"Telnet traffic observed between {target} and {len(peers)} peer(s). "
            "Telnet credentials and keystrokes are sent in plaintext."),
        impact=(
            "Full session capture — usernames, passwords and every keystroke "
            "are recoverable from a passive sniff. Common on legacy embedded "
            "and ICS devices."),
        remediation=(
            "Replace Telnet with SSH. Block 23/tcp at every L3 boundary."),
        affected="\n".join(f"{target} ↔ {p}:23/tcp" for p in sorted(peers)),
        output=f"Telnet peers: {', '.join(sorted(peers))}",
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-8 Transmission Confidentiality and Integrity",
    )

def int_check_snmp_community(ledger, target, om):
    communities: set[str] = set()
    for r in ledger:
        c = r.get("snmp.community")
        if c and target in (r.get("ip.src"), r.get("ip.dst")):
            communities.add(c)
    if not communities: return
    om.add_finding(
        catalogue_id="PT-109",
        title="SNMPv1/v2c Community String Observed in Cleartext",
        ip=target, port=161, risk="MEDIUM", service="snmp",
        phase="internal_cleartext",
        description=(
            f"SNMP community strings observed in plaintext involving {target}: "
            f"{', '.join(repr(c) for c in sorted(communities))[:200]}."),
        impact=(
            "SNMP community strings are passwords. An attacker capturing them "
            "can read MIB data (interface stats, ARP tables, routing tables) "
            "and, with a write community, reconfigure the device."),
        remediation=(
            "Migrate to SNMPv3 with authentication (SHA) + encryption (AES). "
            "Disable SNMPv1/v2c. Restrict SNMP source IPs at the device."),
        affected=f"SNMP traffic from/to {target}",
        output=f"Communities observed: {', '.join(sorted(communities))}",
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-8; AC-3 Access Enforcement",
    )

def int_check_http_basic_auth(ledger, target, om):
    sites: set[str] = set()
    for r in ledger:
        if not r.get("http.authbasic"): continue
        if target in (r.get("ip.src"), r.get("ip.dst")):
            host = r.get("http.host") or "(unknown)"
            sites.add(host)
    if not sites: return
    om.add_finding(
        catalogue_id="PT-110",
        title="HTTP Basic Authentication Observed in Cleartext",
        ip=target, port=80, risk="HIGH", service="http",
        phase="internal_cleartext",
        description=(
            f"HTTP Basic Auth headers observed in cleartext involving {target}, "
            f"on {len(sites)} site(s): {', '.join(sorted(sites)[:5])[:200]}."),
        impact=(
            "Basic Auth credentials are base64-encoded usernames+passwords. Any "
            "passive observer can decode them in one step (`base64 -d`)."),
        remediation=(
            "Wrap the affected service in TLS (HTTPS) or replace Basic Auth "
            "with a token/cookie-based scheme over TLS. Block plain HTTP on "
            "authenticated administrative endpoints."),
        affected=f"{target} ↔ " + ", ".join(sorted(sites)[:5]),
        output=f"Sites: {', '.join(sorted(sites))}",
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-8 Transmission Confidentiality and Integrity",
    )

def int_check_ldap_cleartext(ledger, target, om):
    # tshark exposes LDAP bind requests as 'ldap.bindRequest_element' (the
    # ASN.1 sequence element wrapper). The bare 'ldap.bindRequest' name does
    # not exist as an extractable field.
    seen = any(r.get("ldap.bindRequest_element") and
               target in (r.get("ip.src"), r.get("ip.dst"))
               for r in ledger)
    if not seen: return
    om.add_finding(
        catalogue_id="PT-111",
        title="LDAP Bind Observed Without TLS",
        ip=target, port=389, risk="MEDIUM", service="ldap",
        phase="internal_cleartext",
        description=(
            "LDAP bind request observed in cleartext involving "
            f"{target}. Without LDAPS or StartTLS, the bind DN and password "
            "are exposed."),
        impact=(
            "An attacker capturing the bind can extract the LDAP credentials. "
            "Domain-bound accounts are reusable across the AD forest."),
        remediation=(
            "Enforce LDAPS (TCP/636) or LDAP+StartTLS. Block plain LDAP "
            "(389/tcp) at the firewall."),
        affected=f"LDAP traffic involving {target}",
        output="LDAP bind in cleartext observed",
        owasp="A02:2021 Cryptographic Failures",
        nist="SC-8 Transmission Confidentiality and Integrity",
    )

# ── 2026-06-11 review: Kerberos artefact extraction ───────────────────────────
# Records every Kerberos AS-REQ/AS-REP/TGS-REQ/TGS-REP observed in the pcap.
# Each artefact is a credential-adjacent observation:
#   AS-REQ with no preauth → AS-REP roastable user (offline crack against
#     RC4 etype). Counts as MEDIUM in a passive trace.
#   TGS-REP with RC4 → Kerberoastable SPN. MEDIUM in a passive trace.
# Output goes to <run_dir>/kerberos/<target>_kerberos_artifacts.txt.

_KRB_MSG = {"10":"AS-REQ", "11":"AS-REP", "12":"TGS-REQ", "13":"TGS-REP",
            "14":"AP-REQ", "15":"AP-REP", "30":"ERROR"}

def int_check_kerberos_artifacts(ledger, target, om):
    msgs: list = []
    for f in ledger:
        mt = f.get("kerberos.msg_type", "")
        if not mt: continue
        cn = f.get("kerberos.CNameString", "")
        sn = f.get("kerberos.SNameString", "")
        rl = f.get("kerberos.realm", "")
        src = f.get("ip.src", "") or f.get("ipv6.src", "")
        dst = f.get("ip.dst", "") or f.get("ipv6.dst", "")
        if target not in (src, dst): continue
        msgs.append({"msg_type": _KRB_MSG.get(mt, mt), "raw_type": mt,
                      "cname": cn, "sname": sn, "realm": rl,
                      "src": src, "dst": dst})
    if not msgs:
        return
    out_dir = om.evidence_root(target) / "kerberos"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{target.replace(':','_')}_kerberos_artifacts.txt"
    out_path.write_text(
        "\n".join(f"{m['msg_type']:8s} cname={m['cname']:24s} "
                  f"sname={m['sname']:32s} realm={m['realm']:24s} "
                  f"src={m['src']:15s} dst={m['dst']}"
                  for m in msgs), encoding="utf-8")
    # Per-type summaries
    asreq = sum(1 for m in msgs if m["raw_type"] == "10")
    asrep = sum(1 for m in msgs if m["raw_type"] == "11")
    tgsrep = sum(1 for m in msgs if m["raw_type"] == "13")
    cn_set = sorted({m["cname"] for m in msgs if m["cname"]})
    sn_set = sorted({m["sname"] for m in msgs if m["sname"]})
    om.add_finding(
        title=f"Kerberos Authentication Traffic Captured ({len(msgs)} messages)",
        risk="MEDIUM" if (asrep > 0 or tgsrep > 0) else "INFO",
        ip=target, hostname="", port=88,
        catalogue_id="TRW-KRB-001",
        description=(
            f"Trawler observed Kerberos traffic to/from {target}: "
            f"{asreq} AS-REQ, {asrep} AS-REP, {tgsrep} TGS-REP. "
            f"Principals: {cn_set[:10]}{'…' if len(cn_set)>10 else ''}. "
            f"Service names: {sn_set[:10]}{'…' if len(sn_set)>10 else ''}. "
            f"AS-REP responses for users with 'Do not require Kerberos "
            f"preauthentication' are offline-crackable (AS-REP roastable). "
            f"TGS-REP responses with RC4 encryption are offline-crackable "
            f"(Kerberoastable). Pivot via Vault for active enum."),
        impact=(
            f"An attacker who captured this Kerberos traffic can extract "
            f"AS-REP and RC4 TGS-REP material for offline cracking. Any "
            f"cracked credential yields authenticated domain access and "
            f"lateral movement, and a privileged service ticket can escalate "
            f"toward domain compromise."),
        sources="trawler-kerberos",
        affected=target, command="tshark -Y kerberos",
        output_file=str(out_path.relative_to(om.root)) if hasattr(om,"root") else str(out_path),
        remediation=(
            "Disable RC4 in Kerberos policies (use AES256-CTS-HMAC-SHA1-96). "
            "Audit user accounts for the 'Do not require Kerberos preauthentication' flag "
            "and remove it where possible."),
        owasp="A02:2021 Cryptographic Failures", nist="IA-2",
    )


# ── 2026-06-11 review: NTLM-relay opportunity detection ───────────────────────
# Two paths:
#   1. NTLMSSP NEGOTIATE message with NEGOTIATE_SIGN bit unset
#      (bit 0x00000010 of negotiateflags).
#   2. SMB2 traffic with the signing flag clear in NEGOTIATE/SESSION_SETUP.
# Both indicate downstream relay-feasibility.

def int_check_ntlm_relay_surface(ledger, target, om):
    ntlm_no_sign = 0
    smb_no_sign  = 0
    samples = []
    for f in ledger:
        mt = f.get("ntlmssp.messagetype", "")
        nf = f.get("ntlmssp.negotiateflags", "")
        if mt and nf:
            try:
                flags = int(nf, 16) if nf.startswith("0x") else int(nf)
                # NEGOTIATE_SIGN = 0x00000010, NEGOTIATE_SEAL = 0x00000020
                if not (flags & 0x10):
                    ntlm_no_sign += 1
                    if len(samples) < 10: samples.append({"src": f.get("ip.src",""),
                                                            "dst": f.get("ip.dst",""),
                                                            "flags": nf})
            except (ValueError, TypeError):
                pass
        # SMB2 signing flag check — smb2.flags has SIGNED bit 0x00000008
        sf = f.get("smb2.flags", "")
        if sf:
            try:
                v = int(sf, 16) if sf.startswith("0x") else int(sf)
                if not (v & 0x8):
                    smb_no_sign += 1
            except (ValueError, TypeError):
                pass
    if ntlm_no_sign == 0 and smb_no_sign < 5:
        return
    out_dir = om.evidence_root(target) / "ntlm"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{target.replace(':','_')}_ntlm_relay_surface.txt"
    out_path.write_text(
        f"NTLM NEGOTIATE without SIGN flag: {ntlm_no_sign}\n"
        f"SMB2 frames without signed flag : {smb_no_sign}\n\n"
        f"Sample NTLM frames:\n" + "\n".join(str(s) for s in samples),
        encoding="utf-8")
    om.add_finding(
        title=f"NTLM Relay Surface Observed (target {target})",
        risk="HIGH",
        ip=target, hostname="", port=445,
        catalogue_id="TRW-NTLM-001",
        description=(
            f"Trawler observed NTLM/SMB2 traffic for {target} with the "
            f"signing flag NOT set: {ntlm_no_sign} NTLMSSP NEGOTIATE messages "
            f"without NEGOTIATE_SIGN; {smb_no_sign} SMB2 frames without the "
            f"signed flag. Combined with LLMNR/NBT-NS poisoning + Responder, "
            f"this enables NTLMv2 relay attacks (impacket-ntlmrelayx) for "
            f"RBCD, shadow-credential, or AD-CS / ESC8 paths to domain "
            f"compromise. Promote to Vault for active enumeration."),
        impact=(
            f"Because the observed NTLM/SMB2 traffic is unsigned, an on-path "
            f"attacker can relay the victim's authentication to other services "
            f"and act with the victim's privileges. Chained with LLMNR/NBT-NS "
            f"poisoning and AD CS (ESC8) or resource-based constrained "
            f"delegation, this can escalate to full domain compromise."),
        sources="trawler-ntlm",
        affected=target, command="tshark -Y ntlmssp || smb2",
        output_file=str(out_path.relative_to(om.root)) if hasattr(om,"root") else str(out_path),
        remediation=(
            "Enforce SMB signing on all SMB clients and servers via Group "
            "Policy ('Microsoft network server: Digitally sign communications "
            "(always)'). Disable NTLMv1 entirely. Where possible, restrict "
            "NTLM to specific accounts via 'Network security: Restrict NTLM'."),
        owasp="A02:2021 Cryptographic Failures", nist="IA-2(8)",
    )


# ── 2026-06-11 review: JA3 / JA3S TLS fingerprint capture ─────────────────────
# Records distinct JA3 fingerprints per target so downstream analysts can
# correlate against well-known threat-actor JA3 catalogues (FoxIO, JA4-DB).

def int_check_ja3_fingerprints(ledger, target, om):
    ja3_seen:  dict[str, int] = {}
    ja3s_seen: dict[str, int] = {}
    for f in ledger:
        src = f.get("ip.src", "") or f.get("ipv6.src", "")
        dst = f.get("ip.dst", "") or f.get("ipv6.dst", "")
        if target not in (src, dst): continue
        j  = f.get("tls.handshake.ja3", "")
        js = f.get("tls.handshake.ja3s", "")
        if j:  ja3_seen[j]  = ja3_seen.get(j,  0) + 1
        if js: ja3s_seen[js] = ja3s_seen.get(js, 0) + 1
    if not ja3_seen and not ja3s_seen:
        return
    out_dir = om.evidence_root(target) / "tls"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{target.replace(':','_')}_ja3.txt"
    lines = ["JA3 client fingerprints:"]
    for h, n in sorted(ja3_seen.items(), key=lambda x: -x[1]):
        lines.append(f"  {h}  ×{n}")
    lines.append("JA3S server fingerprints:")
    for h, n in sorted(ja3s_seen.items(), key=lambda x: -x[1]):
        lines.append(f"  {h}  ×{n}")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    om.add_finding(
        title=f"TLS JA3/JA3S Fingerprints Captured ({len(ja3_seen)} clients, {len(ja3s_seen)} servers)",
        risk="INFO",
        ip=target, hostname="", port=443,
        catalogue_id="TRW-JA3-001",
        description=(
            f"Trawler captured {len(ja3_seen)} unique JA3 client and "
            f"{len(ja3s_seen)} unique JA3S server TLS fingerprints for "
            f"traffic to/from {target}. JA3 fingerprints can be matched "
            f"against threat-actor catalogues (FoxIO ja3er.com, JA4-DB) "
            f"to identify malicious tools / Cobalt Strike / specific "
            f"malware families. Top JA3: "
            f"{sorted(ja3_seen.items(), key=lambda x: -x[1])[:3]}."),
        impact=(
            f"The fingerprints themselves are not an exposure, but they let "
            f"an analyst identify the TLS client/server software in use. If a "
            f"captured JA3 matches a known C2 or malware signature (e.g. Cobalt "
            f"Strike, Metasploit), it indicates an active compromise on the "
            f"host that warrants immediate investigation."),
        sources="trawler-ja3",
        affected=target, command="tshark -e tls.handshake.ja3",
        output_file=str(out_path.relative_to(om.root)) if hasattr(om,"root") else str(out_path),
        remediation=(
            "Cross-reference captured JA3 fingerprints against FoxIO ja3er.com "
            "or local threat-intel JA3 lists to identify Cobalt Strike, "
            "Metasploit, or other tooling signatures."),
    )


# ── 2026-06-11 review: IPP / MQTT / AMQP cleartext detection ───────────────────
# Detects presence + emits MEDIUM when these protocols are observed in
# cleartext. Uses frame.protocols string match since tshark has no
# dedicated extractors for the relevant fields.

def int_check_ipp_mqtt_amqp_cleartext(ledger, target, om):
    proto_counts = {"ipp": 0, "mqtt": 0, "amqp": 0}
    proto_remote = {"ipp": set(), "mqtt": set(), "amqp": set()}
    for f in ledger:
        protos = (f.get("frame.protocols") or "").lower()
        src = f.get("ip.src", "") or f.get("ipv6.src", "")
        dst = f.get("ip.dst", "") or f.get("ipv6.dst", "")
        if target not in (src, dst): continue
        for p in ("ipp", "mqtt", "amqp"):
            if p in protos:
                proto_counts[p] += 1
                proto_remote[p].add(src if dst == target else dst)
    out_dir = om.evidence_root(target) / "iot"
    out_dir.mkdir(parents=True, exist_ok=True)
    for p, n in proto_counts.items():
        if n == 0: continue
        out_path = out_dir / f"{target.replace(':','_')}_{p}.txt"
        out_path.write_text(
            f"{p.upper()} frames involving {target}: {n}\n"
            f"Remote peers: {sorted(proto_remote[p])[:30]}",
            encoding="utf-8")
        port = {"ipp": 631, "mqtt": 1883, "amqp": 5672}[p]
        om.add_finding(
            title=f"Cleartext {p.upper()} traffic observed (target {target})",
            risk="MEDIUM",
            ip=target, hostname="", port=port,
            catalogue_id=f"TRW-{p.upper()}-001",
            description=(
                f"Trawler observed {n} {p.upper()} frames involving {target}. "
                f"{p.upper()} is commonly used for "
                + {"ipp": "printer control (often with usernames in URIs)",
                    "mqtt": "IoT pub/sub (CONNECT packets carry user/pass in cleartext)",
                    "amqp": "AMQP message brokering (cleartext credentials and message bodies)"}[p]
                + f". Remote peers: {sorted(proto_remote[p])[:5]}."),
            impact=(
                f"Because the {p.upper()} traffic is unencrypted, any on-path "
                f"observer can read the credentials and message contents it "
                f"carries. Captured credentials enable unauthorized control of "
                f"the printer, IoT device, or message broker and access to the "
                f"sensitive data flowing through it."),
            sources=f"trawler-{p}",
            affected=target, command=f"tshark -Y {p}",
            output_file=str(out_path.relative_to(om.root)) if hasattr(om,"root") else str(out_path),
            remediation=(
                f"Migrate {p.upper()} traffic to its TLS-wrapped variant ("
                + {"ipp": "IPPS over TCP/443",
                    "mqtt": "MQTT over TLS, port 8883",
                    "amqp": "AMQPS, port 5671"}[p]
                + ")."),
            owasp="A02:2021 Cryptographic Failures", nist="SC-8",
        )


INTERNAL_CHECKS = [
    int_check_smbv1,
    int_check_llmnr_nbtns,
    int_check_ssdp,
    int_check_mdns_internal_leak,
    int_check_lldp,
    int_check_arp_anomalies,
    int_check_cleartext_ftp,
    int_check_cleartext_telnet,
    int_check_snmp_community,
    int_check_http_basic_auth,
    int_check_ldap_cleartext,
    # 2026-06-11 review additions
    int_check_kerberos_artifacts,
    int_check_ntlm_relay_surface,
    int_check_ja3_fingerprints,
    int_check_ipp_mqtt_amqp_cleartext,
]

# ── Driver ────────────────────────────────────────────────────────────────────
def analyse_target(ip: str, ledger: list[dict], om: OutputManager,
                   include_internal: bool, scope: str,
                   threat_db=None) -> dict:
    """Run all checks for one target and write per-target traffic rollup."""
    VC.status(f"target_{ip}", f"Target {ip}", "running", "starting", 0, 0)
    VC.target(ip=ip, scope=scope)

    # External rules
    for fn in EXTERNAL_CHECKS:
        try:    fn(ledger, ip, om)
        except Exception as e: VC.error(f"external check {fn.__name__} failed: {e}")

    # Threat-intelligence peer check (runs after standard external checks)
    try:
        ext_check_threat_intel_peers(ledger, ip, om, threat_db)
    except Exception as e:
        VC.error(f"threat-intel check failed: {e}")

    # Internal rules (opt-in)
    if include_internal:
        for fn in INTERNAL_CHECKS:
            try:    fn(ledger, ip, om)
            except Exception as e: VC.error(f"internal check {fn.__name__} failed: {e}")

    # Per-target rollup for Traffic tab
    roll = rollup_target(ledger, ip)
    peers = roll["peers"]
    # Classify each peer and emit port events
    ext_list, int_list = [], []
    for peer_ip, p in peers.items():
        cat, org, purpose = classify_peer(peer_ip, p["snis"])
        p["category"] = cat; p["org"] = org; p["purpose"] = purpose
        p["snis"] = sorted(p["snis"]); p["tcp_ports"] = sorted(p["tcp_ports"])
        p["udp_ports"] = sorted(p["udp_ports"]); p["protocols"] = sorted(p["protocols"])
        is_internal = cat == "internal" or is_private(peer_ip)
        # Enrich external peers with threat-intel and GeoIP data
        if not is_internal and threat_db is not None:
            hit = threat_db.lookup_ip(peer_ip)
            if hit:
                p["threat_hit"] = hit.as_dict()
            geo = threat_db.geoip(peer_ip)
            if geo:
                p["country_code"] = geo.country_code
                p["country_name"] = geo.country_name
        for port in p["tcp_ports"]:
            VC.port(ip=ip, port=port, proto="tcp", scope=scope)
        for port in p["udp_ports"]:
            VC.port(ip=ip, port=port, proto="udp", scope=scope)
        (int_list if is_internal else ext_list).append(p)

    int_list.sort(key=lambda x: ip_key(x["ip"]))
    ext_list.sort(key=lambda x: ip_key(x["ip"]))

    VC.status(f"target_{ip}", f"Target {ip}", "complete",
              f"{len(ext_list)} ext / {len(int_list)} int peers")

    return {
        "ip":            ip,
        "scope":         scope,
        "external_peers": ext_list,
        "internal_peers": int_list,
        "protocols":     sorted(roll["protocols"]),
        "ports_with_data": len(roll["ports_with_data"]),
    }

def main() -> int:
    ap = argparse.ArgumentParser(description="trawler — pcap traffic analyser")
    ap.add_argument("--pcap", action="append", required=True,
                    help="Capture file (multi-format). Repeat for multiple files.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--target", help="Single target IP")
    g.add_argument("--targets-file", help="File with one IP per line")
    ap.add_argument("--include-internal", action="store_true",
                    help="Also apply internal-network rules")
    ap.add_argument("--scope", default="int", choices=("int","ext"),
                    help="Scope label (passed through from Scattershot3 or set manually)")
    ap.add_argument("--output-dir", required=True, help="Universal run-dir root")
    ap.add_argument("--client", default="trawler", help="Client short name")
    args = ap.parse_args()

    if not TSHARK:
        VC.error(
            "tshark not found. Searched PATH and standard install locations "
            "(/Applications/Wireshark.app/Contents/MacOS/, /opt/homebrew/bin/, "
            "/usr/local/bin/, /usr/bin/, C:/Program Files/Wireshark/). Install "
            "Wireshark CLI tools (`apt install wireshark-common` / `brew install "
            "wireshark` / `choco install wireshark`) then re-run.")
        return 1

    om = OutputManager(args.output_dir, scope=args.scope,
                       include_internal=args.include_internal)

    # §13b/§14j/§14k: bring up the run-dir audit log + own-version startup EVENT.
    global _RUNLOG
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(om.root / "scan.log",
                                       errors_path=om.root / "errors.log")
            _RUNLOG.event(f"Trawler v{VERSION} started")
        except Exception:
            _RUNLOG = None

    # Threat-intelligence DB init
    _threat_db = None
    if _HAVE_THREAT_INTEL:
        try:
            VC.status("threat_intel", "Threat Intelligence", "running",
                      "loading blocklists")
            _threat_db = _ti.ThreatIntelDB()
            stats = _threat_db.stats()
            VC.log(f"Threat-intel loaded: {stats['total_ips']} IPs "
                   f"({stats['known_malicious']} known malicious, "
                   f"{stats['suspected']} suspected), "
                   f"{stats['cidr_ranges']} CIDR ranges")
            if _RUNLOG:
                _RUNLOG.event(f"Threat-intel DB loaded: {stats['total_ips']} IPs, "
                              f"{stats['cidr_ranges']} CIDRs, "
                              f"GeoIP={stats['geoip_available']}")
            VC.status("threat_intel", "Threat Intelligence", "complete",
                      f"{stats['total_ips']} IPs loaded")
        except Exception as exc:
            VC.error(f"Threat-intel init failed: {exc}")

    target_list = []
    if args.target:
        target_list = [args.target.strip()]
    else:
        target_list = [l.strip() for l in Path(args.targets_file).read_text().splitlines()
                       if l.strip()]
    om._write_meta(args.client, ", ".join(target_list), args.include_internal)

    VC.log(f"trawler v{VERSION} — scope={args.scope} include_internal={args.include_internal}")
    VC.log(f"targets: {len(target_list)}  pcaps: {len(args.pcap)}")

    # Phase 1: normalise + extract
    VC.status("load_captures", "Load Captures", "running", "", 0, len(args.pcap))
    norm_dir = Path(args.output_dir) / "_normalised"
    norm_dir.mkdir(exist_ok=True)
    combined_ledger: list[dict] = []
    for i, pp in enumerate(args.pcap, 1):
        path = Path(pp)
        if not path.exists():
            VC.error(f"pcap not found: {pp}"); continue
        npath = normalise_capture(path, norm_dir)
        combined_ledger.extend(extract_ledger(npath))
        VC.status("load_captures", "Load Captures", "running",
                  f"{path.name}", i, len(args.pcap))
    VC.status("load_captures", "Load Captures", "complete",
              f"{len(combined_ledger):,} total frames")

    # Phase 2: per-target analysis
    traffic_rollup = {}
    targets_summary = []
    for ip in target_list:
        rec = analyse_target(ip, combined_ledger, om, args.include_internal,
                             args.scope, threat_db=_threat_db)
        traffic_rollup[ip] = rec
        targets_summary.append({
            "ip":            ip,
            "scope":         args.scope,
            "hostname":      "",
            "tools":         ["trawler"],
            "ports":         [{"port": p, "protocol": "tcp"}
                              for peer in rec["external_peers"]+rec["internal_peers"]
                              for p in peer["tcp_ports"]],
            "top_risk":      "",
            "os":            "",
            "finding_count": 0,
        })

    om.write_traffic(traffic_rollup)
    om.write_targets(targets_summary)

    # Consolidated threat-intelligence report
    try:
        write_threat_intel_report(om, traffic_rollup, _threat_db)
    except Exception as exc:
        VC.error(f"Threat-intel report failed: {exc}")

    # Inventory dumps
    om.write_inventory("external_peers",
        [p for r in traffic_rollup.values() for p in r["external_peers"]])
    if args.include_internal:
        om.write_inventory("internal_peers",
            [p for r in traffic_rollup.values() for p in r["internal_peers"]])

    # Phase 3: summary
    try:
        findings = json.loads(om.findings_json.read_text(encoding="utf-8"))
    except Exception:
        findings = []
    risk_counts = Counter((f.get("risk") or "INFO").upper() for f in findings)
    om.write_summary({
        "targets_analysed":  len(target_list),
        "pcaps_analysed":    len(args.pcap),
        "frames_analysed":   len(combined_ledger),
        "findings_total":    len(findings),
        "findings_by_risk":  dict(risk_counts),
        "include_internal":  args.include_internal,
    })

    # Phase 4: cross-tool action items
    _generate_cross_tool_action_items(om, findings, traffic_rollup)

    VC.log(f"Scan complete. Findings: {len(findings)} "
           f"({dict(risk_counts)})", "SUCCESS")
    VC.status("trawler_complete", "Trawler", "complete",
              f"{len(findings)} findings")
    return 0


def _generate_cross_tool_action_items(om: OutputManager, findings: list,
                                       traffic_rollup: dict) -> None:
    """Emit Scattershot3 action items based on Trawler traffic analysis."""
    _SS3_TRIGGER_CATALOGUES = {
        "PT-101": ("SMBv1 traffic — scan for EternalBlue and SMB vulnerabilities",
                   "CRITICAL"),
        "PT-102": ("LLMNR/NBT-NS — scan for Responder relay surface",
                   "HIGH"),
        "PT-103": ("SSDP broadcasts — scan for exposed UPnP services",
                   "MEDIUM"),
        "PT-104": ("mDNS activity — scan for service discovery surface",
                   "LOW"),
        "PT-107": ("Cleartext FTP — scan for anonymous access and brute force",
                   "HIGH"),
        "PT-108": ("Cleartext Telnet — scan for default credentials",
                   "HIGH"),
        "PT-109": ("SNMPv1/v2c — scan for community string brute force",
                   "HIGH"),
        "PT-110": ("HTTP Basic Auth cleartext — scan for credential brute force",
                   "HIGH"),
        "PT-111": ("LDAP without TLS — scan for bind credential exposure",
                   "HIGH"),
    }

    # Collect IPs involved in cleartext/vulnerable protocol findings
    _ips_by_finding: dict = {}
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id not in _SS3_TRIGGER_CATALOGUES:
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        _ips_by_finding.setdefault(cat_id, set()).add(ip)

    for cat_id, ips in _ips_by_finding.items():
        desc_suffix, priority = _SS3_TRIGGER_CATALOGUES[cat_id]
        for ip in list(ips)[:10]:
            om.add_action_item(
                item_type="network_scan",
                recommended_tool="Scattershot3",
                target=ip, ip=ip, port=0, hostname="",
                title=f"Network scan: {desc_suffix.split(' — ')[0]}",
                description=(
                    f"Trawler captured {desc_suffix.split(' — ')[0].lower()} "
                    f"involving {ip}. Scattershot3 can perform targeted scanning "
                    f"to {desc_suffix.split(' — ')[1]}."),
                priority=priority,
                source_finding=cat_id,
                metadata={"source_category": "trawler_protocol_detection",
                           "catalogue_id": cat_id},
            )

    # Malicious IP findings → SS3 deep scan
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id not in ("PT-TI-001", "PT-TI-002"):
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        om.add_action_item(
            item_type="network_scan",
            recommended_tool="Scattershot3",
            target=ip, ip=ip, port=0, hostname="",
            title="Deep scan: threat-intel flagged IP",
            description=(
                f"Trawler identified outbound traffic to {ip}, which is flagged "
                f"by threat intelligence. Scattershot3 can perform comprehensive "
                f"port scanning and vulnerability assessment."),
            priority="CRITICAL",
            source_finding=cat_id,
            metadata={"source_category": "trawler_threat_intel"},
        )

    # ── Cross-tool: Isotope (credential capture / analysis) ────────────
    _ISOTOPE_TRIGGERS = {
        "PT-102": "LLMNR/NBT-NS poisoning captured credentials",
    }
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id not in _ISOTOPE_TRIGGERS:
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        om.add_action_item(
            item_type="credential_reuse",
            recommended_tool="Isotope",
            target=ip, ip=ip, port=0, hostname="",
            title="Isotope: Crack captured NTLM hashes",
            description=(
                f"Trawler detected LLMNR/NBT-NS credential capture involving "
                f"{ip}. Isotope can crack NTLMv1/v2 hashes via hashcat/John "
                f"and test for credential reuse across services."),
            priority="HIGH",
            source_finding=cat_id,
            metadata={"source_category": "trawler_credential_capture"},
        )

    # Kerberos traffic → Isotope Kerberoast
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id not in ("PT-112", "PT-113"):
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        om.add_action_item(
            item_type="credential_reuse",
            recommended_tool="Isotope",
            target=ip, ip=ip, port=88, hostname="",
            title="Isotope: Kerberoast/AS-REP roast",
            description=(
                f"Trawler detected Kerberos traffic to {ip}. Isotope can "
                f"perform Kerberoasting and AS-REP roasting to extract "
                f"service account TGS tickets for offline cracking."),
            priority="HIGH",
            source_finding=cat_id,
            metadata={"source_category": "trawler_kerberos"},
        )

    # NTLM traffic → Isotope relay + Bastion SMB signing
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id not in ("PT-101", "PT-102"):
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        om.add_action_item(
            item_type="config_audit",
            recommended_tool="Bastion",
            target=ip, ip=ip, port=445, hostname="",
            title="Bastion: Audit SMB signing configuration",
            description=(
                f"Trawler detected SMB/NTLM traffic involving {ip}. "
                f"Bastion can audit SMB signing enforcement to determine "
                f"if NTLM relay attacks are feasible."),
            priority="HIGH",
            source_finding=cat_id,
            metadata={"source_category": "trawler_smb_signing"},
        )

    # ── Cross-tool: Fracture/Siphon (web/API from HTTP traffic) ──────
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id != "PT-110":
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        om.add_action_item(
            item_type="web_app",
            recommended_tool="Fracture",
            target=ip, ip=ip, port=80, hostname="",
            title="Fracture: Web application security test",
            description=(
                f"Trawler captured HTTP traffic involving {ip}. "
                f"Fracture can perform comprehensive web application "
                f"security testing including OWASP Top 10 checks."),
            priority="MEDIUM",
            source_finding=cat_id,
            metadata={"source_category": "trawler_http_detection"},
        )
        om.add_action_item(
            item_type="api",
            recommended_tool="Siphon",
            target=ip, ip=ip, port=80, hostname="",
            title="Siphon: API security test",
            description=(
                f"Trawler captured HTTP traffic involving {ip}. "
                f"Siphon can test for API-specific vulnerabilities "
                f"including OWASP API Top 10."),
            priority="MEDIUM",
            source_finding=cat_id,
            metadata={"source_category": "trawler_http_detection"},
        )

    # LDAP without TLS → Auger directory audit
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id != "PT-111":
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        om.add_action_item(
            item_type="directory_audit",
            recommended_tool="Auger",
            target=ip, ip=ip, port=389, hostname="",
            title="Auger: LDAP directory audit",
            description=(
                f"Trawler detected unencrypted LDAP traffic to {ip}. "
                f"Auger can perform comprehensive Active Directory and "
                f"LDAP auditing for misconfigurations, privilege escalation "
                f"paths, and access control weaknesses."),
            priority="HIGH",
            source_finding=cat_id,
            metadata={"source_category": "trawler_ldap_detection"},
        )

    # IoT protocol traffic → Forge
    for f in findings:
        cat_id = f.get("catalogue_id", "")
        if cat_id not in ("PT-114", "PT-115", "PT-116"):
            continue
        ip = f.get("ip", "")
        if not ip:
            continue
        proto = f.get("title", "IoT protocol").split(":")[0] if ":" in f.get("title", "") else "IoT"
        om.add_action_item(
            item_type="iot_audit",
            recommended_tool="Forge",
            target=ip, ip=ip, port=f.get("port", 0), hostname="",
            title=f"Forge: {proto} service exploitation",
            description=(
                f"Trawler detected {proto} traffic involving {ip}. "
                f"Forge can test for default credentials, authentication "
                f"bypass, and command injection on IoT/ICS protocols."),
            priority="HIGH",
            source_finding=cat_id,
            metadata={"source_category": "trawler_iot_protocol"},
        )

    # Traffic rollup: discovered peers with many ports → SS3
    for target_ip, rollup in traffic_rollup.items():
        for peer in rollup.get("external_peers", []):
            tcp_ports = peer.get("tcp_ports", set())
            if isinstance(tcp_ports, set):
                tcp_ports = list(tcp_ports)
            if len(tcp_ports) >= 5:
                om.add_action_item(
                    item_type="network_scan",
                    recommended_tool="Scattershot3",
                    target=peer["ip"], ip=peer["ip"], port=0, hostname="",
                    title="Network scan: multi-port external peer",
                    description=(
                        f"Trawler observed {len(tcp_ports)} TCP ports in traffic "
                        f"to {peer['ip']} from {target_ip}. "
                        f"Scattershot3 can enumerate services on all ports."),
                    priority="MEDIUM",
                    source_finding="traffic_analysis",
                    metadata={"source_category": "trawler_multi_port",
                               "observed_ports": tcp_ports[:20]},
                )

    om.write_action_items()


if __name__ == "__main__":
    sys.exit(main())
