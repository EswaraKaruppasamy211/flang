"""
Correlation Engine
--------------------
Merges findings from multiple analysis modules (filesystem, memory,
network, log records -- any list of dict-like records with a
timestamp-ish field) into a single chronological Timeline, grouped
into correlation windows.

Timestamp normalization: records may carry `timestamp` (unix epoch
float), `mtime`/`ctime`/`atime` (filesystem), or an ISO-8601 string
(logs). We normalize everything to a unix epoch float for sorting and
windowing, but keep the original record intact in the output.
"""

from __future__ import annotations
import json
from datetime import datetime
from typing import List, Dict, Any


def _normalize_ts(record: Dict[str, Any]):
    for key in ("timestamp", "mtime", "ctime", "atime"):
        if key in record and record[key] is not None:
            val = record[key]
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val).timestamp()
                except ValueError:
                    continue
    return None


def correlate(sources: List[List[Dict[str, Any]]], window_seconds: int = 300) -> Dict[str, Any]:
    flat: List[Dict[str, Any]] = []
    for source in sources:
        for record in source:
            ts = _normalize_ts(record)
            flat.append({"timestamp": ts, "record": record})

    with_ts = sorted([r for r in flat if r["timestamp"] is not None], key=lambda r: r["timestamp"])
    without_ts = [r for r in flat if r["timestamp"] is None]

    clusters: List[Dict[str, Any]] = []
    current_cluster: List[Dict[str, Any]] = []
    cluster_start = None

    for item in with_ts:
        if cluster_start is None:
            cluster_start = item["timestamp"]
            current_cluster = [item]
            continue
        if item["timestamp"] - cluster_start <= window_seconds:
            current_cluster.append(item)
        else:
            clusters.append(_finish_cluster(current_cluster))
            cluster_start = item["timestamp"]
            current_cluster = [item]

    if current_cluster:
        clusters.append(_finish_cluster(current_cluster))

    return {
        "type": "Timeline",
        "window_seconds": window_seconds,
        "clusters": clusters,
        "unordered_records": [r["record"] for r in without_ts],
        "total_records": len(flat),
    }


def _finish_cluster(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    start = items[0]["timestamp"]
    end = items[-1]["timestamp"]
    return {
        "start": start,
        "end": end,
        "record_count": len(items),
        "records": [i["record"] for i in items],
    }


# ---------------------------------------------------------------------
# Added: cross-artifact linking utilities. These are new, additive
# functions -- correlate() above is completely unchanged. Where
# correlate() groups records by *time proximity*, link()/find_related()
# let an investigator connect artifacts by a shared *value* (a PID, a
# hostname, an IP, a filename) regardless of when each was observed.

def link(artifact_a: Dict[str, Any], artifact_b: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """Records an explicit investigator-asserted relationship between
    two artifacts (e.g. "this process opened this network connection").
    Returns a plain edge record -- callers collect these into a list to
    build up a relationship graph for a report."""
    return {"type": "CorrelationLink", "from": artifact_a, "to": artifact_b, "reason": reason}


def find_related(artifacts: List[Dict[str, Any]], key: str, value: Any) -> List[Dict[str, Any]]:
    """Returns every artifact in `artifacts` whose `key` field equals
    `value` -- the basic building block for "find everything connected
    to this PID / this IP / this filename" queries."""
    return [a for a in artifacts if a.get(key) == value]


def build_relationship_graph(links: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarizes a list of link() edges into a simple node/edge shape
    suitable for a report section or a graph-rendering tool."""
    nodes = {}
    edges = []
    for l in links:
        a_id = json.dumps(l["from"], sort_keys=True, default=str)
        b_id = json.dumps(l["to"], sort_keys=True, default=str)
        nodes[a_id] = l["from"]
        nodes[b_id] = l["to"]
        edges.append({"from": a_id, "to": b_id, "reason": l["reason"]})
    return {"type": "RelationshipGraph", "node_count": len(nodes), "edge_count": len(edges),
            "nodes": list(nodes.values()), "edges": edges}
