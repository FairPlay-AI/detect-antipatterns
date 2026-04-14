# detect-antipatterns

AST-based linter that catches common anti-patterns in AI-generated Python code. Finds thin shims, phantom guards, unnecessary indirection, over-commenting, single-use helpers, dead code, stray prints, and write-then-discard patterns.

Stdlib only. No dependencies. Python 3.9+.

## Install

```bash
pip install git+https://github.com/FairPlay-AI/detect-antipatterns.git
```

Or for development:

```bash
git clone https://github.com/FairPlay-AI/detect-antipatterns.git
cd detect-antipatterns
pip install -e .
```

## Quick start

```bash
detect-antipatterns src/
```

See [HOWTO.md](HOWTO.md) for a walkthrough of common workflows.

## Usage

```bash
# Scan a directory (default: current directory)
detect-antipatterns src/

# Auto-fix safe issues
detect-antipatterns src/ --fix

# Preview fixes and get suggestions for manual review
detect-antipatterns src/ --suggest

# Target a specific detector
detect-antipatterns src/ --pattern phantom

# JSON output for CI integration
detect-antipatterns src/ --json
```

## Detectors

| Code | Pattern | `--pattern` flag | What it finds |
|------|---------|------------------|---------------|
| DAP001 | Thin shims | `shim` | Functions that import-and-delegate to another module |
| DAP002 | Phantom guards | `phantom` | Epsilon guards, broad except, redundant None/isinstance checks |
| DAP003 | Unnecessary indirection | `indirection` | Config unpackers, single-method proxy classes |
| DAP004 | Over-commenting | `overcomment` | Trivial comments that paraphrase adjacent code |
| DAP005 | Single-use helpers | `single-use` | Functions called from exactly one site in the same file |
| DAP006 | Dead code | `deadcode` | Unused imports, assigned-but-never-read locals |
| DAP007 | Stray prints | `stray-print` | `print()` / `logging.debug()` in production code |
| DAP008 | Write-then-discard | `write-discard` | Variables immediately overwritten, or wrap-then-unwrap |

## Fix modes

**`--fix`** auto-applies safe deletions for four low-risk categories:

- Unused imports (DAP006)
- Stray prints (DAP007)
- Trivial comments (DAP004)
- Immediate overwrites (DAP008)

When the deleted statement is the sole body of a block (`if`, `except`, etc.), `--fix` inserts `pass` to preserve syntax.

**`--suggest`** previews what `--fix` would delete, plus actionable suggestions for findings that need human judgment (single-use helpers, wrap-then-unwrap patterns). Does not modify files.

## Suppression

Use the standard `# noqa` convention to suppress findings:

```python
def my_helper():  # noqa: DAP005
    ...

x = max(val, 1e-5)  # noqa: DAP002

from .module import unused_name  # noqa: DAP006
```

`# noqa: DAP` (without a number) suppresses all detect-antipatterns findings on that line.

Existing `# noqa: F401` comments on imports are automatically respected — the tool won't flag intentional re-exports.

## Pre-commit integration

Add to `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: detect-antipatterns
      name: detect-antipatterns
      entry: detect-antipatterns
      language: system
      types: [python]
      exclude: ^(tests/|notebooks/)
```

To skip in CI (e.g., pre-commit.ci), add to the `ci` section:

```yaml
ci:
  skip: [detect-antipatterns]
```

## Programmatic use

```python
from detect_antipatterns import scan, Finding

findings = scan(["src/"], ["shim", "phantom"])
for f in findings:
    print(f"{f.file}:{f.line} [{f.pattern}/{f.subtype}] {f.description}")
```

## Background

This tool was built after discovering that AI coding assistants (Claude, GPT, Copilot) systematically introduce certain code patterns that accumulate as technical debt. The detectors are based on:

- [OX Security: Anti-Patterns in AI-Generated Code](https://www.softwareseni.com/understanding-anti-patterns-and-quality-degradation-in-ai-generated-code/) (300+ repo analysis)
- [Guo et al. — A Deep Dive Into LLM Code Generation Mistakes](https://arxiv.org/html/2411.01414v1) (7-category taxonomy)
- Hands-on experience cleaning up a production fair-lending analysis codebase

## License

MIT
