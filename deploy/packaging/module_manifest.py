#!/usr/bin/env python3
"""Build inventory metadata alongside a module built from this exact checkout."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def manifest(root, binary, module_path):
    abi = (root / "engine/ffi/src/abi.rs").read_text()
    major = int(re.search(r"STRATA_ABI_VERSION_MAJOR: u32 = (\d+)", abi)[1])
    minor = int(re.search(r"STRATA_ABI_VERSION_MINOR: u32 = (\d+)", abi)[1])
    header = (root / "connectors/nginx/src/ngx_http_strata_module.h").read_text()
    version = re.search(r'NGX_HTTP_STRATA_VERSION\s+"([^"]+)"', header)[1]
    kinds = (root / "engine/src/bundle.rs").read_text().split("pub mod kind {", 1)[1].split("\n}", 1)[0]
    sections = sorted({int(n) for n in re.findall(r"pub const [A-Z_]+: u32 = (\d+);", kinds) if int(n) >= 8})
    return {"module_path": module_path, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "module_version": version, "abi_version": (major << 16) | minor,
            "capabilities": ["max_args", "snippet.2048", "snippet.4096"] + [f"section.{n}" for n in sections]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--module-path", required=True)
    a = p.parse_args()
    print(json.dumps(manifest(a.root, a.binary, a.module_path), indent=2))
