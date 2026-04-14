# HOWTO: detect-antipatterns

Practical workflows for using detect-antipatterns on a Python codebase.

## 1. First scan of a new codebase

Start with a full scan to understand the baseline:

```bash
detect-antipatterns src/ --json | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
counts = Counter(d['subtype'] for d in data)
for s, n in sorted(counts.items(), key=lambda x: -x[1]):
    print(f'  {n:4d}  {s}')
print(f'  ----')
print(f'  {len(data):4d}  total')
"
```

This gives you a breakdown by subtype so you can decide what to tackle first.

## 2. Auto-fix the safe stuff

The `--fix` flag handles four low-risk categories automatically:

```bash
detect-antipatterns src/ --fix
```

This deletes:
- **Trivial comments** that paraphrase adjacent code (`# Loop through items`)
- **Stray print()** calls in production code (not behind `if verbose:` guards)
- **Unused imports** (respects existing `# noqa: F401`)
- **Immediate overwrites** where a variable is assigned then immediately reassigned

After fixing, verify your code still works:

```bash
python -c "import ast, pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('src').rglob('*.py')]"
pytest
```

## 3. Review suggestions for the rest

```bash
detect-antipatterns src/ --suggest
```

This shows two sections:

**Auto-fixable with --fix** — preview of what `--fix` would delete (useful for dry-run review before applying).

**Manual review needed** — findings that require human judgment:
- **Single-use helpers (DAP005)**: tells you the function name, how many statements it has, and the line of its single call site. Decide whether inlining improves readability.
- **Wrap-then-unwrap (DAP008)**: tells you the original variable name and suggests passing it directly.

## 4. Suppress intentional findings

For patterns you've reviewed and want to keep, add a suppression comment:

```python
def my_well_named_helper():  # noqa: DAP005
    """This is intentionally extracted for readability."""
    ...

protected_odds = (1 - rate) / max(rate, 1e-5)  # noqa: DAP002
```

Codes:

| Code | Category |
|------|----------|
| DAP001 | Thin shims |
| DAP002 | Phantom guards |
| DAP003 | Unnecessary indirection |
| DAP004 | Over-commenting |
| DAP005 | Single-use helpers |
| DAP006 | Dead code |
| DAP007 | Stray prints |
| DAP008 | Write-then-discard |
| DAP | All of the above |

## 5. Bulk-suppress remaining findings

After auto-fixing and manually reviewing, you may want to suppress all remaining findings so the pre-commit hook passes on future commits. This one-liner adds `# noqa: DAPxxx` to every finding:

```bash
detect-antipatterns src/ --json | python3 -c "
import json, sys, re
from pathlib import Path
from collections import defaultdict

CODE_MAP = {
    'pure-rename': 'DAP001', 'arg-reshaper': 'DAP001', 'config-unpacker': 'DAP001',
    'epsilon-guard': 'DAP002', 'broad-except-swallowed': 'DAP002',
    'redundant-none-check': 'DAP002', 'redundant-isinstance': 'DAP002',
    'single-method-proxy': 'DAP003',
    'trivial-comment': 'DAP004', 'over-commented-file': 'DAP004',
    'single-use-helper': 'DAP005',
    'unused-import': 'DAP006', 'assigned-never-read': 'DAP006',
    'stray-print': 'DAP007', 'debug-logging': 'DAP007',
    'immediate-overwrite': 'DAP008', 'wrap-then-unwrap': 'DAP008',
}

data = json.load(sys.stdin)
by_file = defaultdict(list)
for d in data:
    by_file[d['file']].append((d['line'], CODE_MAP.get(d['subtype'], 'DAP')))

for filepath, items in sorted(by_file.items()):
    path = Path(filepath)
    lines = path.read_text().splitlines(keepends=True)
    for lineno, code in sorted(set(items), reverse=True):
        if lineno < 1 or lineno > len(lines):
            continue
        line = lines[lineno - 1]
        if re.search(r'#\s*noqa', line):
            continue
        lines[lineno - 1] = line.rstrip('\n') + f'  # noqa: {code}\n'
    path.write_text(''.join(lines))
    print(f'  {filepath}: {len(items)} suppression(s)')
"
```

Then verify: `detect-antipatterns src/` should report "No anti-patterns found."

## 6. Set up pre-commit

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

Now every commit is checked. The hook only runs on changed files, so it's fast.

To skip in CI:

```yaml
ci:
  skip: [detect-antipatterns]
```

## 7. Target a specific detector

If you only care about one category:

```bash
detect-antipatterns src/ --pattern phantom    # just epsilon guards and broad-except
detect-antipatterns src/ --pattern deadcode   # just unused imports and dead locals
detect-antipatterns src/ --pattern shim       # just thin wrapper functions
```

## 8. CI integration with JSON

For CI pipelines that consume structured output:

```bash
detect-antipatterns src/ --json > antipatterns.json
```

The JSON is an array of objects with fields: `file`, `line`, `pattern`, `subtype`, `description`, `code_snippet`.

Exit code is 0 if no findings, 1 if any findings exist.
