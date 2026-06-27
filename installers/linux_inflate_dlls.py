#!/usr/bin/env python3
"""
linux_inflate_dlls.py

Helper script to inflate Windows DLLs and build SHAREM JSON mapping files on
Linux. The JSON files must use the same DLL load order as SHAREM on Windows.

Usage example:
    python3 linux_inflate_dlls.py \
        --src-x86 /tmp/raw_dlls/SysWOW64/ \
        --src-x64 /tmp/raw_dlls/System32/ \
        --out-x86 ~/git/sharem/sharem/sharem/sharem/DLLs/x86/ \
        --out-x64 ~/git/sharem/sharem/sharem/sharem/DLLs/x64/ \
        --json-dir ~/git/sharem/sharem/sharem/sharem/
"""

import os
import json
import re
import ast
import argparse
import pefile

# allDlls from modules.py initMods. Exact order including duplicates.
# Duplicates are significant: SHAREM advances baseGlobal for each entry that
# exists in save_path, so order and duplicates must match.
INIT_DLL_ORDER_WITH_DUPS = [
    "ntdll", "kernel32", "KernelBase", "advapi32", "comctl32", "comdlg32",
    "gdi32", "gdiplus", "imm32", "mscoree", "msvcrt", "netapi32", "ole32",
    "oleaut32", "shell32", "shlwapi", "urlmon", "user32", "wininet", "winmm",
    "ws2_32", "wsock32", "advpack", "bcrypt", "crypt32", "dnsapi", "mpr",
    "ncrypt", "netutils", "samcli", "secur32", "wkscli", "wtsapi32",
    "cabinet", "cfgmgr32", "clfsw32", "combase", "dhcpsapi", "gdiplus",
    "httpapi", "imm32", "iphlpapi", "iscsidsc", "mprapi", "msi", "msvcrxx",
    "odbc32", "pdh", "powrprof", "rasapi32", "rpcrt4", "shell32", "usp10",
    "virtdisk", "websocket", "winbio", "winhttp", "winspool", "wlanapi",
    "wldap32", "dbghelp", "winspool", "pdh", "clfsw32", "powrprof",
    "mprapi", "winbio", "authz", "cryptnet", "psapi", "sechost"
]


def load_dll_list(dict6_path: str) -> list[str]:
    """Load dict6DllNames list from dict6.py without importing SHAREM."""
    with open(dict6_path, "r", encoding="utf-8") as f:
        content = f.read()

    matches = list(re.finditer(r"dict6DllNames\s*=\s*\[", content))
    if not matches:
        raise RuntimeError("dict6DllNames list not found in dict6.py")

    m = matches[-1]
    start = m.start()
    i = content.index("[", start)
    depth = 0
    end = i

    while end < len(content):
        if content[end] == "[":
            depth += 1
        elif content[end] == "]":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1

    return ast.literal_eval(content[i:end])


# Locate dict6.py relative to this script.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

# Script expected at: REPO_ROOT/installers/linux_inflate_dlls.py
# dict6.py at: REPO_ROOT/sharem/sharem/sharem/DLLs/dict6.py
DICT6_PATH = os.path.join(
    REPO_ROOT, "sharem", "sharem", "sharem", "DLLs", "dict6.py"
)

DLL_NAMES = load_dll_list(DICT6_PATH)


def resolve_src(src_dir: str, dll_name: str) -> tuple[str | None, str | None]:
    """
    Resolve a DLL name to a source file path.

    Searches src_dir and src_dir/downlevel and tries several filename variants:
      - dll_name + ".dll"
      - api_ms_* names with underscores replaced by hyphens
      - *_drv names with .drv extension
      - windows_* names converted to dotted form (Windows.UI.dll etc.)
    Lookup is case-insensitive on Linux.
    """
    search_dirs = [src_dir, os.path.join(src_dir, "downlevel")]
    candidates = [dll_name + ".dll"]

    if dll_name.startswith("api_ms_") or "_ms_win_" in dll_name:
        candidates.append(dll_name.replace("_", "-") + ".dll")

    if dll_name.endswith("_drv"):
        base = dll_name[:-4]
        candidates += [base + ".drv", base.replace("_", "-") + ".drv"]

    if dll_name.startswith("windows_"):
        parts = dll_name.split("_")
        candidates.append(".".join(p.capitalize() for p in parts) + ".dll")
        candidates.append(
            ".".join(p.upper() if len(p) <= 2 else p.capitalize()
                     for p in parts) + ".dll"
        )

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            ci = {f.lower(): f for f in os.listdir(d)}
        except OSError:
            continue
        for c in candidates:
            if c.lower() in ci:
                return os.path.join(d, ci[c.lower()]), ci[c.lower()]

    return None, None


def read_raw(path: str) -> bytes:
    """Read entire file into bytes."""
    with open(path, "rb") as f:
        return f.read()


def insert_into_bytes(blob: bytes, start: int, size: int, value: int) -> bytes:
    """Insert 'size' copies of 'value' at position 'start' in blob."""
    lst = list(blob)
    for _ in range(size):
        lst.insert(start, value)
    return bytes(lst)


def pad_dll(src_path: str, dst_path: str) -> bytes:
    """
    Inflate a DLL so that file offsets match the in-memory layout.

    Uses the export directory virtual address to compute padding and adjusts
    e_lfanew and inserts padding bytes near the DOS header.
    """
    pe = pefile.PE(src_path)
    va = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
    padding = 0

    for section in pe.sections:
        ptr = section.PointerToRawData
        s_va = section.VirtualAddress
        size = section.SizeOfRawData
        if s_va <= va < (s_va + size):
            padding = va - (va - s_va + ptr)
            break

    elfanew = pe.DOS_HEADER.e_lfanew
    pe.DOS_HEADER.e_lfanew = elfanew + padding
    pe.write(dst_path)

    raw = read_raw(dst_path)
    final = insert_into_bytes(raw, 0x40, padding, 0x00)
    with open(dst_path, "wb") as f:
        f.write(final)

    return read_raw(dst_path)


def parse_exports(src_path: str, base: int, dll_file: str,
                  export_dict: dict[str, tuple[str, str]]) -> None:
    """
    Parse export table from src_path and add entries to export_dict.

    Keys are absolute addresses (base + export RVA) as hex strings.
    Values are (function_name, dll_file).
    """
    try:
        pe = pefile.PE(src_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                addr_key = hex(base + exp.address)
                try:
                    name = exp.name.decode()
                except Exception:
                    name = "unknown_function"
                export_dict[addr_key] = (name, dll_file)
    except Exception:
        # Silent failure: missing or malformed export tables are tolerated.
        pass


def process_arch(src_dir: str, out_dir: str, json_path: str,
                 arch_label: str) -> None:
    """
    Process one architecture (x86 or x64).

    Pass 1 inflates all DLL_NAMES that can be found in src_dir.
    Pass 2 builds the export JSON using INIT_DLL_ORDER_WITH_DUPS so that
    addresses match SHAREM's load order.
    """
    os.makedirs(out_dir, exist_ok=True)

    # Pass 1: inflate all DLL_NAMES (dict6DllNames list). Skip if already done.
    print(f"\n[{arch_label}] Pass 1: inflating DLLs...")
    inflated = 0
    skipped: list[str] = []

    for dll_name in DLL_NAMES:
        dst = os.path.join(out_dir, dll_name + ".dll")
        if os.path.exists(dst):
            inflated += 1
            continue

        src, _ = resolve_src(src_dir, dll_name)
        if src is None:
            skipped.append(dll_name)
            continue

        subdir = "(downlevel)" if "downlevel" in src else ""
        print(f"  [{arch_label}] {dll_name} {subdir}")
        try:
            pad_dll(src, dst)
            inflated += 1
        except Exception as e:
            print(f"    WARNING: {dll_name}: {e}")
            skipped.append(dll_name)

    print(f"[{arch_label}] Pass 1 done: {inflated} available, {len(skipped)} skipped")

    # Pass 2: build JSON in allDlls order.
    # SHAREM iterates INIT_DLL_ORDER_WITH_DUPS and advances baseGlobal by
    # len(rawDll) + 20 for each DLL found in save_path. This replicates that.
    print(f"\n[{arch_label}] Pass 2: building export JSON in allDlls order...")
    export_dict: dict[str, tuple[str, str]] = {}
    base = 0x14100000
    seen_bases: dict[str, str] = {}

    for dll_name in INIT_DLL_ORDER_WITH_DUPS:
        dll_file = dll_name + ".dll"
        dst = os.path.join(out_dir, dll_file)
        if not os.path.exists(dst):
            continue

        raw = read_raw(dst)
        src_orig, _ = resolve_src(src_dir, dll_name)
        if src_orig:
            parse_exports(src_orig, base, dll_file, export_dict)

        if dll_name not in seen_bases:
            seen_bases[dll_name] = hex(base)

        base += len(raw) + 20

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export_dict, f)

    print(f"[{arch_label}] Key bases:")
    for key in ["ntdll", "kernel32", "KernelBase", "user32"]:
        print(f"  {key}: {seen_bases.get(key, 'NOT LOADED')}")
    print(
        f"[{arch_label}] JSON: {json_path} "
        f"({os.path.getsize(json_path) // 1024} KB, {len(export_dict)} entries)"
    )


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Inflate Windows DLLs and build SHAREM export JSONs on Linux"
    )
    ap.add_argument("--src-x86", required=True,
                    help="Directory containing x86 DLLs harvested from Windows")
    ap.add_argument("--src-x64", required=True,
                    help="Directory containing x64 DLLs harvested from Windows")
    ap.add_argument("--out-x86", required=True,
                    help="Output directory for inflated x86 DLLs")
    ap.add_argument("--out-x64", required=True,
                    help="Output directory for inflated x64 DLLs")
    ap.add_argument("--json-dir", required=True,
                    help="Directory where JSON files will be written")
    args = ap.parse_args()

    print(f"DLL list loaded: {len(DLL_NAMES)} entries")

    process_arch(
        os.path.expanduser(args.src_x86),
        os.path.expanduser(args.out_x86),
        os.path.join(os.path.expanduser(args.json_dir),
                     "foundDLLAddresses32.json"),
        "x86",
    )
    process_arch(
        os.path.expanduser(args.src_x64),
        os.path.expanduser(args.out_x64),
        os.path.join(os.path.expanduser(args.json_dir),
                     "FoundDLLAddresses64.json"),
        "x64",
    )


if __name__ == "__main__":
    main()