#!/usr/bin/env python3
"""Regression tests for the TL script classification inventory."""
from __future__ import annotations

import json
import subprocess
import unittest
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "artifacts" / "tl-script-inventory.json"
ALLOWED_CLASSIFICATIONS = {
    "active example",
    "fixture test",
    "historical probe",
    "unsafe/deprecated",
    "superseded by manifest/request-plan",
}


class TlScriptInventoryTests(unittest.TestCase):
    maxDiff = 4000

    def load_inventory(self) -> dict[str, Any]:
        self.assertTrue(INVENTORY.exists(), "canonical TL script inventory is missing")
        return json.loads(INVENTORY.read_text(encoding="utf-8"))

    def git_tl_files(self, *, tracked_only: bool = False) -> set[str]:
        cmd = ["git", "ls-files"]
        if tracked_only:
            cmd.append("*.tl")
        else:
            cmd.extend(["-co", "--exclude-standard", "*.tl"])
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return {line for line in result.stdout.splitlines() if line}

    def test_inventory_covers_every_non_ignored_tl_script(self) -> None:
        inventory = self.load_inventory()
        self.assertEqual(inventory["schema"], "tallow.tl_script_inventory.v1")
        self.assertEqual(set(inventory["classification_values"]), ALLOWED_CLASSIFICATIONS)
        self.assertTrue(inventory["non_claims"]["does_not_execute_scripts"])
        self.assertTrue(inventory["non_claims"]["classification_inventory_only"])

        entries = inventory["entries"]
        paths = [entry["path"] for entry in entries]
        self.assertEqual(len(paths), len(set(paths)), "inventory must not contain duplicate paths")
        self.assertEqual(set(paths), self.git_tl_files(), "all non-ignored .tl files must be classified")

        classifications = Counter(entry["classification"] for entry in entries)
        self.assertEqual(set(classifications), ALLOWED_CLASSIFICATIONS)
        self.assertEqual(sum(classifications.values()), inventory["summary"]["total_tl_files"])
        self.assertEqual(dict(classifications), inventory["summary"]["counts_by_classification"])

    def test_inventory_summary_matches_git_tracked_state(self) -> None:
        inventory = self.load_inventory()
        entries = inventory["entries"]
        tracked_paths = self.git_tl_files(tracked_only=True)
        tracked = [entry for entry in entries if entry["git_tracked"]]
        untracked = [entry for entry in entries if not entry["git_tracked"]]

        self.assertEqual({entry["path"] for entry in tracked}, tracked_paths)
        self.assertEqual(len(tracked), inventory["summary"]["tracked_count"])
        self.assertEqual(len(untracked), inventory["summary"]["untracked_count"])
        self.assertEqual(len(tracked) + len(untracked), inventory["summary"]["total_tl_files"])

    def test_known_unsafe_superseded_and_fixture_scripts_are_not_mislabeled(self) -> None:
        inventory = self.load_inventory()
        by_path = {entry["path"]: entry for entry in inventory["entries"]}
        expected = {
            "kroger_mega_scrape.tl": "unsafe/deprecated",
            "personal_database/ashraf_ali_business_inquiry/ashraf_ali_business_inquiry.legacy-http-batch.tl": "superseded by manifest/request-plan",
            "examples/hello_simple.tl": "active example",
            "tests/fixtures/stdlib_codegen_test.tl": "fixture test",
        }
        for path, classification in expected.items():
            self.assertIn(path, by_path)
            self.assertEqual(by_path[path]["classification"], classification, by_path[path])
            self.assertTrue(by_path[path]["rationale"].strip(), f"missing rationale for {path}")

    def test_deprecated_and_superseded_entries_have_actionable_rationale(self) -> None:
        inventory = self.load_inventory()
        for entry in inventory["entries"]:
            if entry["classification"] not in {"unsafe/deprecated", "superseded by manifest/request-plan"}:
                continue
            rationale = entry["rationale"].lower()
            signals = " ".join(entry.get("signals", [])).lower()
            combined = f"{rationale} {signals}"
            self.assertTrue(entry["rationale"].strip(), f"missing rationale for {entry['path']}")
            if entry["classification"] == "unsafe/deprecated":
                self.assertRegex(
                    combined,
                    r"unsafe|live|stealth|deploy|credential|captcha|network|browser|http|proxy|tor|headed|reviewed|gated",
                    f"unsafe/deprecated entry should explain risk: {entry}",
                )
            else:
                self.assertIn(
                    "manifest/request-plan",
                    combined,
                    f"superseded entry should point to manifest/request-plan migration: {entry}",
                )


if __name__ == "__main__":
    unittest.main()
