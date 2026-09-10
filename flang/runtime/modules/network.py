"""
Network Analysis Module
--------------------------
Parses packet captures into flow / DNS-event records.

If `scapy` is installed, real .pcap/.pcapng files are parsed directly.
Otherwise (or for test fixtures), a JSON sidecar describing flows/DNS
events in the same shape is accepted -- see load_pcap() in the
interpreter builtins. Analysis functions are written against the
normalized shape either way.
"""

from __future__ import annotations
from typing import List, Dict, Any
from ..evidence import EvidenceHandle

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR  # type: ignore
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False


def _require_pcap(handle: EvidenceHandle):
    if handle.evidence_type != "PacketCapture":
        raise TypeError("This function requires a PacketCapture evidence handle")


def parse_pcap_file(path: str) -> Dict[str, Any]:
    """Real parser used when scapy + an actual .pcap file are available."""
    flows: Dict[tuple, Dict[str, Any]] = {}
    dns_events: List[Dict[str, Any]] = []

    packets = rdpcap(path)
    for pkt in packets:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            key = (src, dst, sport, dport, proto)
            flow = flows.setdefault(key, {
                "type": "NetFlow", "src_ip": src, "dst_ip": dst,
                "src_port": sport, "dst_port": dport, "protocol": proto,
                "packet_count": 0, "byte_count": 0,
                "timestamp": float(pkt.time),
            })
            flow["packet_count"] += 1
            flow["byte_count"] += len(pkt)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                qname = str(pkt[DNSQR].qname)
            dns_events.append({
                "type": "Event", "category": "dns_query",
                "query": qname, "timestamp": float(pkt.time),
            })

    return {"flows": list(flows.values()), "dns_events": dns_events}


def list_flows(handle: EvidenceHandle, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    _require_pcap(handle)
    return data.get("flows", [])


def extract_dns(handle: EvidenceHandle, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    _require_pcap(handle)
    return data.get("dns_events", [])


def flag_suspicious_connections(flows: List[Dict[str, Any]], iocs: Dict[str, Any]) -> List[Dict[str, Any]]:
    bad_ips = set(iocs.get("ip_addresses", []))
    bad_ports = set(iocs.get("ports", []))
    flagged = []
    for f in flows:
        if f.get("dst_ip") in bad_ips or f.get("src_ip") in bad_ips or f.get("dst_port") in bad_ports:
            f = dict(f)
            f["flagged_reason"] = "matched IOC (ip or port)"
            flagged.append(f)
    return flagged
