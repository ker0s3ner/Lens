"""Measure a prebuilt Lens on Linux: python3 scripts/large-file-gate.py target/release/lens"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys
import tempfile
import time


MIB = 1024 * 1024
PAGE = 4096
BASE = 0x400000
ENTRY = BASE + PAGE
DATA_OFFSET = 2 * PAGE
SEGMENT_SIZE = 64 * MIB
FILE_SEGMENT_SIZE = 100 * MIB
FILE_SIZE = DATA_OFFSET + FILE_SEGMENT_SIZE
BSS1 = BASE + DATA_OFFSET + FILE_SEGMENT_SIZE + PAGE
BSS2 = BSS1 + SEGMENT_SIZE + PAGE
MARKER = b"LENS large-file fixture end"
MARKER_OFFSET = FILE_SIZE - len(MARKER) - 1
SECONDS_LIMIT = 120
RSS_LIMIT_MIB = 384


def make_fixture(path):
    # Sectionless ELF64 ET_EXEC. Its only code is Linux x86-64 exit(0).
    code = bytes.fromhex("b8 3c 00 00 00 31 ff 0f 05")
    ident = b"\x7fELF\x02\x01\x01".ljust(16, b"\0")
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, ENTRY, 64,
                         0, 0, 64, 56, 4, 64, 0, 0)
    segments = [(PAGE, BASE + PAGE, len(code), len(code), 5),
                (DATA_OFFSET, BASE + DATA_OFFSET, FILE_SEGMENT_SIZE, FILE_SEGMENT_SIZE, 4),
                (0, BSS1, 0, SEGMENT_SIZE, 4), (0, BSS2, 0, SEGMENT_SIZE, 4)]
    with path.open("xb") as stream:
        stream.write(header)
        for offset, address, file_size, memory_size, flags in segments:
            stream.write(struct.pack("<IIQQQQQQ", 1, flags, offset, address,
                                     address, file_size, memory_size, PAGE))
        stream.seek(PAGE)
        stream.write(code)
        # Keep the 100 MiB file-backed segment sparse. The two later ELF
        # segments have p_filesz=0 and p_memsz=64 MiB, exercising lazy zeros.
        stream.seek(MARKER_OFFSET)
        stream.write(MARKER + b"\0")
    path.chmod(0o400)
    if path.stat().st_size != FILE_SIZE:
        raise ValueError("incorrect fixture size")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(report, fixture_sha256):
    expected = {"schema": "lens.analysis.v1", "format": "ELF64 executable",
                "architecture": "x86-64", "bits": 64, "entry_point": ENTRY, "sha256": fixture_sha256}
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f"{key}: expected {value!r}, got {report.get(key)!r}")
    if not any(i["address"] == ENTRY and i["length"] == 5 for i in report["instruction_records"]):
        raise ValueError("missing decoded entry instruction")
    mapped = {(s["file_offset"], s["start"], s["file_bytes"], s["size"]) for s in report["segment_records"]
              if not s["executable"] and not s["writable"]}
    expected_segments = {(DATA_OFFSET, BASE + DATA_OFFSET, FILE_SEGMENT_SIZE, FILE_SEGMENT_SIZE),
                         (0, BSS1, 0, SEGMENT_SIZE), (0, BSS2, 0, SEGMENT_SIZE)}
    for segment in expected_segments:
        if segment not in mapped:
            raise ValueError(f"missing read-only file or zero-fill segment {segment!r}")
    if not any(s["address"] == BASE + MARKER_OFFSET and s["text"] == MARKER.decode("ascii")
               for s in report["string_records"]):
        raise ValueError("missing end-of-file marker at its mapped address")


def limit_child():
    # Bound allocation even if the analyzer regresses before RSS can be reported.
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * MIB,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * MIB,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def measure(lens, fixture, report_path):
    with report_path.open("xb") as output:
        start = time.monotonic()
        try:
            result = subprocess.run([lens, fixture, "--json"], stdout=output,
                                    stdin=subprocess.DEVNULL, preexec_fn=limit_child,
                                    timeout=SECONDS_LIMIT, check=False)
        finally:
            elapsed = time.monotonic() - start
            # Lens is this script's only child. Linux reports ru_maxrss in KiB.
            rss_mib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
            metrics = (f"{fixture.stat().st_size:,} file bytes | {FILE_SEGMENT_SIZE // MIB} MiB file-backed | "
                       f"{2 * SEGMENT_SIZE // MIB} MiB virtual zero-fill "
                       f"| wall {elapsed:.3f} s "
                       f"(limit {SECONDS_LIMIT} s) | peak RSS {rss_mib:.2f} MiB "
                       f"(limit {RSS_LIMIT_MIB} MiB)")
            print(metrics, flush=True)
            if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(summary, "a", encoding="utf-8") as dest:
                    print(f"Lens large-file analysis: {metrics}", file=dest)
    result.check_returncode()
    if elapsed > SECONDS_LIMIT or not 0 < rss_mib <= RSS_LIMIT_MIB:
        raise ValueError("wall time or peak RSS outside budget")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lens", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("measurement requires Linux")
    lens = args.lens.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="lens-large-") as directory:
        fixture = Path(directory) / "fixture.elf"
        report = Path(directory) / "analysis.json"
        fixture_sha256 = make_fixture(fixture)
        measure(lens, fixture, report)
        with report.open("rb") as stream:
            validate(json.load(stream), fixture_sha256)
    print("Large-file metadata and performance checks passed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f"Large-file gate failed: {error}")
