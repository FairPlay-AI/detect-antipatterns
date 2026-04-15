"""Tests for detect_antipatterns."""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from detect_antipatterns import scan
from detect_antipatterns.__main__ import Finding, apply_fixes


def _write(tmp_path: Path, content: str, name: str = "sample.py") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _findings_of(findings: List[Finding], subtype: str) -> List[Finding]:
    return [f for f in findings if f.subtype == subtype]


# ---------------------------------------------------------------------------
# Epic 1: DAP009 excess-blank-lines detector
# ---------------------------------------------------------------------------

class TestExcessBlankLinesDetector:
    def test_detects_3_blank_run(self, tmp_path: Path) -> None:
        src = "x = 1\n\n\n\ny = 2\n"  # 3 blank lines between two statements
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        blanks = _findings_of(findings, "excess-blank-lines")
        assert len(blanks) == 1
        assert blanks[0].line == 2  # first blank line

    def test_ignores_2_blank_run(self, tmp_path: Path) -> None:
        # Black-compatible: 2 blank lines between top-level defs must not fire.
        src = "def a():\n    pass\n\n\ndef b():\n    pass\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        assert _findings_of(findings, "excess-blank-lines") == []

    def test_ignores_1_blank_run(self, tmp_path: Path) -> None:
        src = "x = 1\n\ny = 2\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        assert _findings_of(findings, "excess-blank-lines") == []

    def test_flags_trailing_blank_run(self, tmp_path: Path) -> None:
        # 3 trailing blank lines at EOF should flush.
        src = "x = 1\n\n\n\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        blanks = _findings_of(findings, "excess-blank-lines")
        assert len(blanks) == 1
        assert blanks[0].line == 2

    def test_flags_multiple_runs_separately(self, tmp_path: Path) -> None:
        src = "a = 1\n\n\n\nb = 2\n\n\n\n\nc = 3\n"
        # Run 1: blanks at L2,3,4 (len 3); Run 2: blanks at L6,7,8,9 (len 4)
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        blanks = _findings_of(findings, "excess-blank-lines")
        assert len(blanks) == 2
        assert [b.line for b in blanks] == [2, 6]

    def test_fix_lines_keeps_one_blank(self, tmp_path: Path) -> None:
        # Run of 4 blank lines (L2..L5) → delete L3..L5, keep L2.
        src = "x = 1\n\n\n\n\ny = 2\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        blanks = _findings_of(findings, "excess-blank-lines")
        assert len(blanks) == 1
        assert blanks[0].fix_action == "delete-lines"
        assert blanks[0].fix_lines == (3, 5)


class TestApplyFixesPreservesBlankGaps:
    def test_unused_import_fix_preserves_2blank_gap(self, tmp_path: Path) -> None:
        # After deleting an unused import, the black-mandated 2-blank gap
        # between top-level imports and defs must NOT be collapsed to 1.
        src = "import os\nimport sys\n\n\ndef f():\n    return os.path\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["deadcode"])
        apply_fixes(findings)
        result = path.read_text()
        assert result == "import os\n\n\ndef f():\n    return os.path\n"

    def test_excess_blank_fix_reduces_to_single_blank(self, tmp_path: Path) -> None:
        # End-to-end: 4 blanks between two statements → 1 blank after --fix.
        src = "x = 1\n\n\n\n\ny = 2\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["blank-lines"])
        apply_fixes(findings)
        assert path.read_text() == "x = 1\n\ny = 2\n"

    def test_all_patterns_includes_blank_lines(self, tmp_path: Path) -> None:
        from detect_antipatterns.__main__ import DETECTORS
        assert "blank-lines" in DETECTORS
        src = "x = 1\n\n\n\ny = 2\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], list(DETECTORS.keys()))
        assert _findings_of(findings, "excess-blank-lines")
