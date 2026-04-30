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


# ---------------------------------------------------------------------------
# Epic 2: --disable CLI flag
# ---------------------------------------------------------------------------

class TestDisableSuppression:
    def test_disable_dap_code_filters_matching_findings(self, tmp_path: Path) -> None:
        src = "x = 1\n\n\n\ny = 2\n"
        path = _write(tmp_path, src)
        # Baseline — the finding is present.
        baseline = scan([str(path)], ["blank-lines"])
        assert _findings_of(baseline, "excess-blank-lines")
        # With DAP009 disabled it must be dropped.
        filtered = scan([str(path)], ["blank-lines"], disabled={"DAP009"})
        assert _findings_of(filtered, "excess-blank-lines") == []

    def test_disable_by_subtype_name(self, tmp_path: Path) -> None:
        src = "import os\n"  # `os` is unused → unused-import finding
        path = _write(tmp_path, src)
        baseline = scan([str(path)], ["deadcode"])
        assert _findings_of(baseline, "unused-import")
        filtered = scan([str(path)], ["deadcode"], disabled={"unused-import"})
        assert _findings_of(filtered, "unused-import") == []

    def test_disable_code_does_not_leak_across_subtypes(
        self, tmp_path: Path
    ) -> None:
        # DAP009 disabled must NOT affect DAP006 findings in the same file.
        src = "import os\n\n\n\nx = 1\n"  # unused import + 3 blank run
        path = _write(tmp_path, src)
        filtered = scan(
            [str(path)], ["deadcode", "blank-lines"], disabled={"DAP009"}
        )
        assert _findings_of(filtered, "excess-blank-lines") == []
        assert _findings_of(filtered, "unused-import")

    def test_disable_code_case_insensitive(self, tmp_path: Path) -> None:
        src = "x = 1\n\n\n\ny = 2\n"
        path = _write(tmp_path, src)
        for code in ("dap009", "Dap009", "DAP009"):
            filtered = scan([str(path)], ["blank-lines"], disabled={code})
            assert _findings_of(filtered, "excess-blank-lines") == [], code

    def test_cli_disable_comma_separated(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from detect_antipatterns.__main__ import main
        src = "import os\n\n\n\nx = 1\n"  # unused import + 3 blank run
        path = _write(tmp_path, src)
        # Comma-separated: should suppress both.
        main([str(path), "--disable", "DAP006,DAP009"])
        out = capsys.readouterr().out
        assert "unused-import" not in out
        assert "excess-blank-lines" not in out

    def test_cli_disable_repeated_flags(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from detect_antipatterns.__main__ import main
        src = "import os\n\n\n\nx = 1\n"
        path = _write(tmp_path, src)
        main([str(path), "--disable", "DAP006", "--disable", "DAP009"])
        out = capsys.readouterr().out
        assert "unused-import" not in out
        assert "excess-blank-lines" not in out

    def test_disable_bare_DAP_suppresses_everything(
        self, tmp_path: Path
    ) -> None:
        src = "import os\n\n\n\nx = 1\n"
        path = _write(tmp_path, src)
        findings = scan(
            [str(path)], ["deadcode", "blank-lines"], disabled={"DAP"}
        )
        assert findings == []

    def test_cli_disable_DAP009_prevents_fix(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # With DAP009 disabled, --fix must NOT delete the excess blanks.
        from detect_antipatterns.__main__ import main
        original = "x = 1\n\n\n\ny = 2\n"
        path = _write(tmp_path, original)
        rc = main([str(path), "--fix", "--disable", "DAP009"])
        capsys.readouterr()  # discard
        assert path.read_text() == original
        assert rc == 1  # no fixes applied

    def test_in_source_noqa_still_suppresses(self, tmp_path: Path) -> None:
        # noqa suppression must work independently of --disable.
        src = "import os  # noqa: DAP006\n"
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["deadcode"])
        assert _findings_of(findings, "unused-import") == []

    def test_disable_empty_set_is_no_op(self, tmp_path: Path) -> None:
        src = "x = 1\n\n\n\ny = 2\n"
        path = _write(tmp_path, src)
        baseline = scan([str(path)], ["blank-lines"])
        filtered = scan([str(path)], ["blank-lines"], disabled=set())
        assert len(baseline) == len(filtered) == 1


# ---------------------------------------------------------------------------
# Epic 3: DAP002 log-then-swallow subtype
# ---------------------------------------------------------------------------

class TestLogThenSwallowDetector:
    """The camouflage case: handler logs the failure (`logger.warning(...)`)
    then silently recovers (`return`/`continue`/`pass`/`raise NewError(...)`).
    Per the no-default-recovery rule, a warning to a log file the operator
    rarely reads is functionally silent."""

    def test_logger_warning_then_return_fires(self, tmp_path: Path) -> None:
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        return\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert len(_findings_of(findings, "log-then-swallow")) == 1

    def test_logger_then_continue_fires(self, tmp_path: Path) -> None:
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f(items):\n"
            "    for item in items:\n"
            "        try:\n"
            "            handle(item)\n"
            "        except Exception as err:\n"
            "            logger.warning('skip %r: %s', item, err)\n"
            "            continue\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert len(_findings_of(findings, "log-then-swallow")) == 1

    def test_logger_then_pass_fires(self, tmp_path: Path) -> None:
        src = (
            "import logging\n"
            "log = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception:\n"
            "        log.error('failed')\n"
            "        pass\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert len(_findings_of(findings, "log-then-swallow")) == 1

    def test_logger_then_raise_new_without_from_fires(
        self, tmp_path: Path
    ) -> None:
        # Drops context: caller can't see the original error.
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        raise RuntimeError('something failed')\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert len(_findings_of(findings, "log-then-swallow")) == 1

    def test_multiple_leading_loggers_then_return_fires(
        self, tmp_path: Path
    ) -> None:
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('a')\n"
            "        logger.error('b: %s', err)\n"
            "        return None\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert len(_findings_of(findings, "log-then-swallow")) == 1

    def test_self_logger_attribute_chain_fires(self, tmp_path: Path) -> None:
        src = (
            "class C:\n"
            "    def f(self):\n"
            "        try:\n"
            "            self.do_work()\n"
            "        except Exception as err:\n"
            "            self.logger.warning('oops: %s', err)\n"
            "            return\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert len(_findings_of(findings, "log-then-swallow")) == 1

    # --- negatives ---

    def test_logger_then_bare_reraise_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        raise\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []

    def test_logger_then_raise_new_with_from_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        # `raise NewError(...) from err` preserves the cause chain.
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        raise RuntimeError('wrapped') from err\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []

    def test_logger_then_raise_bound_name_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        # `raise err` where err is the bound exception is just re-raising.
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        raise err\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []

    def test_narrow_except_does_not_fire(self, tmp_path: Path) -> None:
        # `except KeyError:` is targeted, not slop.
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f(d):\n"
            "    try:\n"
            "        return d['x']\n"
            "    except KeyError as err:\n"
            "        logger.warning('missing: %s', err)\n"
            "        return None\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []

    def test_work_between_log_and_recovery_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        # If the handler does additional work besides log+return, treat as
        # an intentional fallback path.
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "state = {}\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        state['fallback'] = True\n"
            "        return\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []

    def test_no_logger_uses_existing_broad_except_subtype(
        self, tmp_path: Path
    ) -> None:
        # `except Exception: pass` — no leading logger, falls under existing
        # broad-except-swallowed, NOT log-then-swallow.
        src = (
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception:\n"
            "        pass\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []
        assert _findings_of(findings, "broad-except-swallowed") != []

    def test_decorated_error_handler_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        # Click commands and Flask error handlers conventionally log + return
        # as their documented contract.
        src = (
            "import logging\n"
            "import click\n"
            "logger = logging.getLogger(__name__)\n"
            "@click.command\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        return\n"
        )
        path = _write(tmp_path, src)
        findings = scan([str(path)], ["phantom"])
        assert _findings_of(findings, "log-then-swallow") == []

    def test_subtype_maps_to_DAP002(self, tmp_path: Path) -> None:
        from detect_antipatterns.__main__ import _SUBTYPE_TO_CODE
        assert _SUBTYPE_TO_CODE["log-then-swallow"] == "DAP002"

    def test_disable_DAP002_suppresses_log_then_swallow(
        self, tmp_path: Path
    ) -> None:
        src = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def f():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception as err:\n"
            "        logger.warning('oops: %s', err)\n"
            "        return\n"
        )
        path = _write(tmp_path, src)
        baseline = scan([str(path)], ["phantom"])
        assert _findings_of(baseline, "log-then-swallow")
        filtered = scan([str(path)], ["phantom"], disabled={"DAP002"})
        assert _findings_of(filtered, "log-then-swallow") == []
