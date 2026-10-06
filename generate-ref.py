#!/usr/bin/env python3
"""Generate Custom/External (json_v2) 10k unique-issue fixture at ref.json.

STO json_v2 groups rows by meta.key. Unique packageName => 10k issues, 1 occ each.
Without meta.key, Custom ingest collapses everything into 1 issue / 10k occs.
"""

import json
import random

ISSUE_COUNT = 10000
OUTPUT_FILE = "ref.json"
SEED = 42
LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
RISKS = ("critical", "high", "medium", "low")
SEVERITIES = (10, 7, 4, 3)


def refs_for(index):
    return [
        {"type": "cve", "id": f"2024-{10000 + (index % 1000)}"},
        {"type": "cwe", "id": str(200 + (index % 50))},
        {"type": "ghsa", "id": f"{index:04x}-sort-{index % 997:04x}"},
        {"type": "snyk", "id": f"PYTHON-PKG{index}-400000"},
    ]


def main():
    random.seed(SEED)
    issues = []
    for i in range(ISSUE_COUNT):
        bucket = i % 4
        issues.append(
            {
                "packageName": f"pkg-issue{i}",
                "issueName": f"Issue {i:05d} {LOREM}",
                "issueDescription": (
                    f"Issue {i} for severity-sort / Iceberg performance testing"
                ),
                "fileName": f"src/module{i % 100}/file{i}.java",
                "remediationSteps": "Upgrade to latest version.",
                "risk": RISKS[bucket],
                "severity": SEVERITIES[bucket],
                "status": "open",
                "referenceIdentifiers": refs_for(i),
            }
        )
    root = {
        "meta": {
            "key": ["packageName"],
            "subproduct": "RefIdPerfScanner",
        },
        "issues": issues,
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(root, f, separators=(",", ":"))

    pkgs = {row["packageName"] for row in issues}
    print(f"Wrote {OUTPUT_FILE}")
    print(f"  issues:           {len(issues)}")
    print(f"  unique packageName: {len(pkgs)}")
    print(f"  meta.key:         {root['meta']['key']}")
    print("  expected after Custom ingest: ~10000 issues, 1 occ each")


if __name__ == "__main__":
    main()
