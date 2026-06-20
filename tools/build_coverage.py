#!/usr/bin/env python3
"""Generate the bundled coverage artifacts from local CP OpenAPI specs (dev/release-time step).

The generation logic lives in ``app.services.coverage_build`` (shared with the in-app "check for
updates" endpoint). This CLI just loads spec files and writes artifacts to ``app/coverage_data/``.

    python tools/build_coverage.py                 # latest management + gaia
    python tools/build_coverage.py --api management --version v2.0.1 --spec /path/openapi.json
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services import coverage_build as cb  # noqa: E402

SPEC_ROOT = "/Users/khalid/Desktop/CP-Docs-To-Swagger/data/processed"


def _all_versions(api_type):
    root = os.path.join(SPEC_ROOT, api_type)
    vers = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    return sorted(vers, key=lambda v: [int(x) for x in re.findall(r"\d+", v)] or [0])


def _latest(api_type):
    return _all_versions(api_type)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", choices=["management", "gaia", "both"], default="both")
    ap.add_argument("--version", default="")
    ap.add_argument("--spec", default="")
    ap.add_argument("--all", action="store_true", help="generate EVERY local version, not just the latest")
    args = ap.parse_args()
    for api_type in (["management", "gaia"] if args.api == "both" else [args.api]):
        todo = _all_versions(api_type) if args.all else [args.version or _latest(api_type)]
        for version in todo:
            spec_path = (os.path.join(SPEC_ROOT, api_type, version, "openapi.json")
                         if args.all else (args.spec or os.path.join(SPEC_ROOT, api_type, version, "openapi.json")))
            with open(spec_path) as f:
                spec = json.load(f)
            art = cb.build_from_spec(api_type, version, spec)
            if not art["object_count"]:
                print(f"{api_type} {version}: 0 objects — skipped (no add-*/set-* paths in this spec)")
                continue
            fn = cb.write_artifact(art)
            print(f"{api_type} {version}: {art['object_count']} objects -> {fn}")


if __name__ == "__main__":
    main()
