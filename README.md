# detect-antipatterns

AST-based detector for common anti-patterns in AI-generated Python code. Finds thin shims, phantom guards, unnecessary indirection, over-commenting, single-use helpers, dead code, stray prints, and write-then-discard patterns.

Stdlib only. No dependencies.

## Install

```bash
pip install git+https://github.com/FairPlay-AI/detect-antipatterns.git
```

## Usage

```bash
# Scan a directory
detect-antipatterns src/

# Auto-fix safe issues (unused imports, stray prints, trivial comments, immediate overwrites)
detect-antipatterns src/ --fix

# Preview fixes and get suggestions for manual review
detect-antipatterns src/ --suggest

# Target a specific detector
detect-antipatterns src/ --pattern phantom

# JSON output for CI integration
detect-antipatterns src/ --json
```

## Detectors

| Pattern | Flag | Description |
|---------|------|-------------|
| `shim` | | Functions that import-and-delegate to another module |
| `phantom` | | Epsilon guards, broad except, redundant None checks |
| `indirection` | | Config unpackers, single-method proxy classes |
| `overcomment` | | Trivial comments that paraphrase code |
| `single-use` | | Functions called from exactly one site |
| `deadcode` | | Unused imports, assigned-but-never-read locals |
| `stray-print` | | `print()` / `logging.debug()` in production code |
| `write-discard` | | Variables immediately overwritten or wrap-then-unwrap |

## Fix modes

- `--fix` auto-applies safe deletions (unused imports, stray prints, trivial comments, immediate overwrites). Inserts `pass` when the deleted statement is the sole body of a block.
- `--suggest` previews what `--fix` would do, plus actionable suggestions for single-use helpers and wrap-then-unwrap patterns.
