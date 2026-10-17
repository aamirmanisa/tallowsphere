#!/usr/bin/env python3
"""P2-009 docs-truth maintenance regressions."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRUTH_LABELED_DOCS = [
    "docs/mega/tallow-1000x-blocker-register.md",
    "docs/mega/tallow-1000x-capability-matrix.md",
    "docs/mega/tallow-1000x-docs-contract-map.md",
    "docs/tallow-scraper-full-task-list.md",
    "docs/operations/tallow-request-plan-runner.md",
    "docs/operations/compliance-gate.md",
    "docs/benchmarks/benchmark-protocol.md",
]
REQUIRED_NON_CLAIMS = [
    "live scraping",
    "production browser fallback",
    "real vault",
    "destructive retention",
    "paid/live benchmark",
    "Windows support",
]

# E-3-09 (2026-09-13): §3.5 doc-align wiring + mockup claim-banner wave.
# Mockups that carry per-claim labels (files with undetectable/big-number copy).
CLAIM_LABELED_MOCKUPS = [
    "docs/mockups/v1-editorial.html",
    "docs/mockups/v2-cinematic.html",
    "docs/mockups/v3-stripe.html",
    "docs/mockups/v4-spatial.html",
    "docs/mockups/v5-brutalist.html",
    "docs/mockups/tallow-copy-premium.html",
    "docs/mockups/tallow-presets.html",
    "docs/mockups/tallow-search-final.html",
    "docs/mockups/tallow-luxury.html",
]
# Operating runbooks whose `/mnt/Personal/Nixe` workspace paths were corrected.
OPS_DOCS_PATH_CHECKED = [
    "docs/operations/quickstart.md",
    "docs/operations/operator-checklist.md",
    "docs/operations/tallow-runtime-bootstrap.md",
    "docs/operations/phase1-smoke-ladder.md",
    "docs/operations/target-policy.md",
    "docs/operations/phase11-proving-grounds.md",
]


class DocsTruthMaintenanceTests(unittest.TestCase):
    def read(self, rel: str) -> str:
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_high_risk_docs_have_visible_truth_labels(self) -> None:
        for rel in TRUTH_LABELED_DOCS:
            with self.subTest(path=rel):
                first_lines = "\n".join(self.read(rel).splitlines()[:8])
                self.assertIn("Docs truth label:", first_lines)

    def test_current_contract_docs_reflect_p2_008_error_object(self) -> None:
        capability = self.read("docs/mega/tallow-1000x-capability-matrix.md")
        blocker = self.read("docs/mega/tallow-1000x-blocker-register.md")
        contract_map = self.read("docs/mega/tallow-1000x-docs-contract-map.md")
        runner = self.read("docs/operations/tallow-request-plan-runner.md")

        self.assertIn("P2-008 canonical emitted error object", capability)
        self.assertIn("P2-008 canonical emitted error object", blocker)
        self.assertIn("tallow.error_object.v1", contract_map)
        self.assertIn("canonical error object", runner)
        self.assertNotIn(
            "Current rows/scripts still use legacy category names outside the Phase 5 local/mock row validator",
            contract_map,
        )

    def test_truth_docs_preserve_required_non_claims(self) -> None:
        combined = "\n".join(
            self.read(rel)
            for rel in [
                "docs/mega/tallow-1000x-blocker-register.md",
                "docs/mega/tallow-1000x-capability-matrix.md",
                "docs/mega/tallow-1000x-docs-contract-map.md",
            ]
        ).lower()
        for phrase in REQUIRED_NON_CLAIMS:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase.lower(), combined)

    # ── E-3-09 · §3.5 six doc-align rewrites (no comptime/borrow drift) ──

    def test_section_3_5_sites_aligned_no_comptime_drift(self) -> None:
        ref = self.read("docs/tallow-complete-reference.html")
        self.assertIn(
            "Constant folding in codegen (no <code>comptime</code> language feature)", ref
        )
        self.assertIn(
            "Policy/safety passes (@legal validation, privacy flow, agent boundaries)", ref
        )
        self.assertIn(
            "Term used in older docs; not a Tallow language feature. "
            "Compile-time work is limited to constant folding in codegen.",
            ref,
        )
        low = ref.lower()
        self.assertNotIn("comptime execution", low)
        self.assertNotIn("zero runtime cost", low)
        self.assertNotIn("borrow/lifetime analysis", low)

        caps = self.read("docs/TALLOW-CAPABILITIES.md")
        self.assertIn("Constant Folding (codegen; no comptime feature)", caps)
        self.assertNotIn("Comptime Execution", caps)

        comparison = self.read("docs/TALLOW-LANGUAGE-COMPARISON-2026-09-12.md")
        self.assertIn("31 compiler passes", comparison)
        self.assertNotIn("29 compiler passes", comparison)
        self.assertNotIn("comptime", comparison)

    def test_compiler_pass_count_no_stale_29_claims(self) -> None:
        for rel in [
            "docs/TALLOW-CAPABILITIES.md",
            "docs/TALLOW-LANGUAGE-COMPARISON-2026-09-12.md",
            "docs/TALLOW-330-TOOLS.md",
            "docs/MEGA_SCRAPER_ENGINE_RESEARCH.md",
        ]:
            with self.subTest(path=rel):
                text = self.read(rel)
                self.assertNotIn("29 compiler passes", text)
                self.assertNotIn("29 Compiler Passes", text)
        self.assertNotIn("29 passes", self.read("docs/MEGA_SCRAPER_ENGINE_RESEARCH.md"))

    def test_delta_sync_flag_count_relabeled(self) -> None:
        caps = self.read("docs/TALLOW-CAPABILITIES.md")
        # 23: `--vss` was removed in W2-08 (design D-C1), and src/main.rs's `DeltaSync` variant
        # defines 23 named flags. This expected 24 and was red wherever it ran.
        self.assertIn("Delta-Sync Flags (23)", caps)
        self.assertNotIn("Delta-Sync Flags (22)", caps)

    def test_operations_docs_have_no_stale_workspace_paths(self) -> None:
        for rel in OPS_DOCS_PATH_CHECKED:
            with self.subTest(path=rel):
                self.assertNotIn("/mnt/Personal", self.read(rel))

    # ── E-3-09 · mockup claim-banner wave ────────────────────────────────

    def test_mockups_carry_truth_banners(self) -> None:
        mockups = sorted((ROOT / "docs" / "mockups").glob("*.html"))
        self.assertGreaterEqual(len(mockups), 13, "mockup set shrank unexpectedly")
        for path in mockups:
            with self.subTest(mockup=path.name):
                head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:8])
                self.assertIn("Docs truth label", head)

    def test_mockup_claim_sites_are_labeled(self) -> None:
        for rel in CLAIM_LABELED_MOCKUPS:
            with self.subTest(mockup=rel):
                self.assertIn("claim label:", self.read(rel))
        # Every visible `undetectable` tagline has its adjacent claim label.
        for path in sorted((ROOT / "docs" / "mockups").glob("*.html")):
            lines = path.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                if "undetectable" not in line.lower():
                    continue
                if "claim label" in line or line.strip().startswith("<!--"):
                    continue
                window = "\n".join(lines[i + 1 : i + 3])
                self.assertIn(
                    "claim label:",
                    window,
                    f"unlabeled 'undetectable' in {path.name}:{i + 1}",
                )


    # ── Stub register integrity ──────────────────────────────────────────
    # The 2026-10-17 re-verification found four cells cut off at write time
    # ("... [truncated]") and four rows carrying an extra column, which made
    # their last cell invisible when the table rendered. This guard keeps the
    # register one row per audit id with exactly five cells.

    def test_stub_register_rows_are_complete(self) -> None:
        text = self.read("docs/operations/stub-register.md")
        rows: dict[int, str] = {}
        for line in text.splitlines():
            match = re.match(r"^\|\s*(\d{1,2})\s*\|", line)
            if not match:
                continue
            number = int(match.group(1))
            self.assertNotIn("[truncated]", line, f"row {number} is truncated")
            self.assertEqual(
                line.count("|"), 6, f"row {number} is not five cells"
            )
            self.assertNotIn(number, rows, f"row {number} appears twice")
            rows[number] = line
        # Rows are numbered 1..=N with no gaps; N is the highest id in the table.
        self.assertEqual(sorted(rows), list(range(1, 99)))


if __name__ == "__main__":
    unittest.main()
