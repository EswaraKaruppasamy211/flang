"""
Security Testing Laboratory
------------------------------
Generates harmless SYNTHETIC test artifacts (plain text placeholder
files containing a benign marker string) and mutates them with
non-functional padding/noise, so a researcher can check whether a
keyword/IOC-based detection rule still recognizes the same logical
artifact after superficial changes. This is explicitly NOT a malware
generator or an evasion tool: every artifact created here is
non-executable placeholder text, generated locally, and never leaves
the lab directory. See the project's safety boundary for why this
module exists in this shape rather than operating on real payloads.
"""

from __future__ import annotations
import os
import random
import string
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..evidence import sha256_file


@dataclass
class TestCase:
    name: str
    lab_dir: str
    seed_path: str
    marker: str


def create_test_case(name: str, marker: str = "TEST-ARTIFACT-SIGNATURE") -> TestCase:
    lab_dir = os.path.join(tempfile.gettempdir(), "flang_testlab", name)
    os.makedirs(lab_dir, exist_ok=True)
    seed_path = os.path.join(lab_dir, "seed.txt")
    with open(seed_path, "w") as f:
        f.write(f"# synthetic non-functional test artifact\n")
        f.write(f"marker: {marker}\n")
        f.write(f"created: {time.ctime()}\n")
    return TestCase(name=name, lab_dir=lab_dir, seed_path=seed_path, marker=marker)


def generate_variants(test_case: TestCase, count: int) -> List[Dict[str, Any]]:
    with open(test_case.seed_path, "r") as f:
        seed_content = f.read()

    variants = []
    for i in range(int(count)):
        noise = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 64)))
        variant_content = f"{seed_content}\n# padding: {noise}\n"
        variant_path = os.path.join(test_case.lab_dir, f"variant_{i:03d}.txt")
        with open(variant_path, "w") as f:
            f.write(variant_content)
        variants.append({
            "index": i,
            "path": variant_path,
            "sha256": sha256_file(variant_path),
        })
    return variants


def compare_detection(test_case: TestCase, variants: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    for v in variants:
        with open(v["path"], "r") as f:
            content = f.read()
        detected = test_case.marker in content
        results.append({**v, "detected": detected})
    return results


def generate_report(test_case: TestCase, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    detected = sum(1 for r in results if r["detected"])
    return {
        "test_case": test_case.name,
        "marker": test_case.marker,
        "total_variants": total,
        "detected_count": detected,
        "detection_rate": round(detected / total, 4) if total else None,
        "undetected_variants": [r["path"] for r in results if not r["detected"]],
    }


class TestLabSession:
    """
    Stateful wrapper matching the flat `test.create(...) / test.generate_variants(...) /
    test.compare_detection() / test.generate_report()` call sequence the language
    exposes -- each call implicitly acts on "the current test case" rather than
    requiring the script to thread a TestCase object through every call by hand.
    One session is created per Interpreter instance (see interpreter.py).
    """

    def __init__(self):
        self.current_case: TestCase | None = None
        self.current_variants: List[Dict[str, Any]] = []
        self.current_results: List[Dict[str, Any]] = []

    def create(self, name: str, marker: str = "TEST-ARTIFACT-SIGNATURE") -> Dict[str, Any]:
        self.current_case = create_test_case(name, marker)
        self.current_variants = []
        self.current_results = []
        return {"name": name, "seed_path": self.current_case.seed_path, "marker": marker}

    def generate_variants(self, count) -> List[Dict[str, Any]]:
        if self.current_case is None:
            raise ValueError("No test case created -- call test.create(name) first")
        self.current_variants = generate_variants(self.current_case, int(count))
        return self.current_variants

    def compare_detection(self) -> List[Dict[str, Any]]:
        if self.current_case is None:
            raise ValueError("No test case created -- call test.create(name) first")
        self.current_results = compare_detection(self.current_case, self.current_variants)
        return self.current_results

    def generate_report(self) -> Dict[str, Any]:
        if self.current_case is None:
            raise ValueError("No test case created -- call test.create(name) first")
        return generate_report(self.current_case, self.current_results)
