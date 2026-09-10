"""
File Forensics Module (static analysis only)
-----------------------------------------------
Every function here reads a file and reports about it -- none of them
open a file for writing, and none of them execute anything. This
module deliberately implements minimal PE/ELF header parsing by hand
(struct-based) rather than depending on `pefile`, so it has zero
third-party dependency surface for something that reads
attacker-influenced file formats -- a smaller, auditable parser is a
smaller attack surface than a large general-purpose one.
"""

from __future__ import annotations
import math
import os
import re
import struct
import time
from typing import Any, Dict, List

from ..evidence import sha256_file

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"


def file_info(path: str) -> Dict[str, Any]:
    st = os.stat(path)
    return {
        "path": path,
        "size_bytes": st.st_size,
        "extension": os.path.splitext(path)[1],
        "modified": time.ctime(st.st_mtime),
        "created": time.ctime(st.st_ctime),
        "accessed": time.ctime(st.st_atime),
        "file_type": detect_file_type(path),
    }


def file_hash(path: str) -> str:
    return sha256_file(path)


def file_metadata(path: str) -> Dict[str, Any]:
    info = file_info(path)
    info["sha256"] = file_hash(path)
    return info


def file_entropy(path: str) -> float:
    """Shannon entropy in bits/byte (0.0 = fully uniform, 8.0 = maximal
    randomness -- often used as a rough packed/encrypted-content signal)."""
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def file_strings(path: str, min_length: int = 4, limit: int = 200) -> List[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    with open(path, "rb") as f:
        data = f.read()
    found = [m.decode("ascii", errors="ignore") for m in pattern.findall(data)]
    return found[:limit]


def detect_file_type(path: str) -> str:
    with open(path, "rb") as f:
        header = f.read(16)
    if header.startswith(PE_MAGIC):
        return "PE (Windows executable/DLL)"
    if header.startswith(ELF_MAGIC):
        return "ELF (Linux executable/object)"
    if header.startswith(b"PK\x03\x04"):
        return "ZIP-based (docx/xlsx/jar/zip)"
    if header.startswith(b"%PDF"):
        return "PDF"
    if header[:2] in (b"\xff\xd8",):
        return "JPEG image"
    if header.startswith(b"\x89PNG"):
        return "PNG image"
    if all(32 <= b <= 126 or b in (9, 10, 13) for b in header):
        return "text/ASCII"
    return "unknown/binary"


def parse_pe_basic(path: str) -> Dict[str, Any]:
    """Minimal PE header parse: DOS header -> e_lfanew -> COFF header ->
    machine type, section count, section names. Not a full PE parser
    (no import table walking, no resource parsing) -- deliberately
    scoped to the metadata an investigator actually triages on first
    pass."""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(PE_MAGIC):
        raise ValueError("Not a PE file (missing 'MZ' signature)")
    if len(data) < 0x40:
        raise ValueError("File too small to contain a valid DOS header")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("PE signature not found at expected offset (corrupt or non-PE file)")

    machine, num_sections, timestamp = struct.unpack_from("<HHI", data, e_lfanew + 4)
    machine_names = {0x14c: "x86 (I386)", 0x8664: "x64 (AMD64)", 0x1c0: "ARM", 0xaa64: "ARM64"}

    opt_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    section_table_offset = e_lfanew + 24 + opt_header_size
    sections = []
    for i in range(num_sections):
        off = section_table_offset + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        virt_size, virt_addr, raw_size = struct.unpack_from("<III", data, off + 8)
        sections.append({"name": name, "virtual_size": virt_size, "raw_size": raw_size})

    return {
        "format": "PE",
        "machine": machine_names.get(machine, hex(machine)),
        "num_sections": num_sections,
        "compile_timestamp": time.ctime(timestamp) if 0 < timestamp < 2**31 else None,
        "sections": sections,
    }


def parse_elf_basic(path: str) -> Dict[str, Any]:
    """Minimal ELF header parse (e_ident + the fixed-size ELF header
    fields) -- machine type, entry point, section/program header
    counts. Same scoping rationale as parse_pe_basic()."""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(ELF_MAGIC):
        raise ValueError("Not an ELF file (missing magic bytes)")
    if len(data) < 64:
        raise ValueError("File too small to contain a valid ELF header")

    ei_class = data[4]      # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]       # 1 = little-endian, 2 = big-endian
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2

    if is64:
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff = struct.unpack_from(
            endian + "HHIQQQ", data, 16)
        e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
    else:
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff = struct.unpack_from(
            endian + "HHIIII", data, 16)
        e_shnum = struct.unpack_from(endian + "H", data, 48)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 44)[0]

    machine_names = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "ARM64"}
    type_names = {1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (shared object/PIE)", 4: "CORE (core dump)"}

    return {
        "format": "ELF",
        "class": "64-bit" if is64 else "32-bit",
        "endianness": "little" if ei_data == 1 else "big",
        "type": type_names.get(e_type, hex(e_type)),
        "machine": machine_names.get(e_machine, hex(e_machine)),
        "entry_point": hex(e_entry),
        "num_sections": e_shnum,
        "num_program_headers": e_phnum,
    }


def parse_imports(path: str) -> Dict[str, Any]:
    """Import-table detail is intentionally out of scope for this
    struct-based prototype parser (real import parsing needs to walk
    the PE import directory or the ELF dynamic symbol table, which is
    exactly the kind of format-parsing complexity better delegated to
    a maintained library in production -- see README)."""
    file_type = detect_file_type(path)
    return {"file_type": file_type, "imports": [],
            "note": "Import-table parsing is a documented gap in this prototype; "
                    "production builds should delegate to `pefile` (PE) or `pyelftools` (ELF)."}


def parse_sections(path: str) -> Dict[str, Any]:
    if detect_file_type(path).startswith("PE"):
        return parse_pe_basic(path)
    if detect_file_type(path).startswith("ELF"):
        return parse_elf_basic(path)
    raise ValueError("Section parsing only supported for PE and ELF files")
