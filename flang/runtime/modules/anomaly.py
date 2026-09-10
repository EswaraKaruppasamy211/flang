"""
Anomaly Detection Module
---------------------------
Generic statistical anomaly detection over any numeric field extracted
from a list of forensic records (file sizes, flow byte counts, event
frequencies, process counts per host, etc.). This directly implements
the "anomaly detection" capability named in the original project brief,
which earlier prototype iterations left implicit inside detect_injection()
only. This module makes it a general, reusable primitive.

Method: z-score against the sample mean/standard deviation. This is a
simple, explainable baseline suitable for an investigator to reason
about and defend in a report -- deliberately not a black-box ML model,
since forensic findings need to be explainable.
"""

from __future__ import annotations
import math
from typing import List, Dict, Any


def mean(values: List[float]) -> float:
    if not values:
        raise ValueError("mean() of an empty list is undefined")
    return sum(values) / len(values)


def median(values: List[float]) -> float:
    if not values:
        raise ValueError("median() of an empty list is undefined")
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2
    return s[mid]


def stdev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    variance = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def detect_outliers(values: List[float], threshold_stdevs: float = 2.0) -> List[Dict[str, Any]]:
    """
    Returns entries {index, value, z_score} for every value whose
    z-score magnitude exceeds threshold_stdevs.
    """
    if len(values) < 2:
        return []
    m = mean(values)
    sd = stdev(values)
    if sd == 0:
        return []
    outliers = []
    for i, v in enumerate(values):
        z = (v - m) / sd
        if abs(z) >= threshold_stdevs:
            outliers.append({"index": i, "value": v, "z_score": round(z, 3)})
    return outliers


def detect_anomalies(records: List[Dict[str, Any]], field: str,
                      threshold_stdevs: float = 2.0) -> List[Dict[str, Any]]:
    """
    Generic anomaly detector over a list of forensic records (file
    records, network flows, log-derived event counts, etc). Extracts
    `field` from each record, computes the z-score against the sample,
    and returns the original records that are statistical outliers,
    each annotated with its z-score and a human-readable reason --
    ready to drop straight into a report section.
    """
    numeric_pairs = [(r, r[field]) for r in records if isinstance(r.get(field), (int, float))]
    values = [v for _, v in numeric_pairs]
    outliers = detect_outliers(values, threshold_stdevs)
    outlier_indices = {o["index"]: o["z_score"] for o in outliers}

    flagged = []
    for i, (record, _) in enumerate(numeric_pairs):
        if i in outlier_indices:
            r = dict(record)
            r["anomaly_z_score"] = outlier_indices[i]
            r["flagged_reason"] = (
                f"statistical outlier on '{field}' "
                f"({outlier_indices[i]:+.2f} standard deviations from sample mean)"
            )
            flagged.append(r)
    return flagged
