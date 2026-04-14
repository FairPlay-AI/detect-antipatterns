#!/usr/bin/env python3
"""
Detect common AI-generated code anti-patterns in Python source files.

Eight detectors:
  1. Thin shims — functions that just import-and-delegate to another module
  2. Phantom guards — defensive code for conditions that can't occur
  3. Unnecessary indirection — config unpackers, single-method proxy classes
  4. Over-commenting — comment-to-code ratio is suspiciously high
  5. Single-use helpers — named functions called from exactly one site
  6. Dead code — unused imports, assigned-but-never-read locals
  7. Stray prints — print()/logging.debug() left in non-CLI production code
  8. Write-then-discard — variables assigned, then immediately overwritten or unused

Usage:
    python tools/detect_antipatterns.py [path ...] [--json] [--pattern PATTERN]
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Generator, List, Optional, Sequence, Set, Tuple

@dataclass
class Finding:
    file: str
    line: int
    pattern: str  # "shim", "phantom", "indirection", "garbage"
    subtype: str
    description: str
    code_snippet: str = ""
    # Fix metadata — populated by detectors that support --fix or --suggest
    fix_action: str = ""  # "delete-lines", "replace-lines", "suggest"
    fix_lines: Tuple[int, int] = (0, 0)  # (start, end) inclusive 1-based
    fix_replacement: str = ""  # replacement text for "replace-lines"
    fix_suggestion: str = ""  # human-readable suggestion for --suggest

# Which subtypes support --fix (auto-apply) vs --suggest (emit diff)
FIXABLE_SUBTYPES = {
    "unused-import",
    "stray-print",
    "trivial-comment",
    "immediate-overwrite",
}
SUGGESTABLE_SUBTYPES = {
    "single-use-helper",
    "wrap-then-unwrap",
}

# noqa codes: use `# noqa: DAP001` to suppress a specific finding.
# `# noqa: DAP` suppresses all detect-antipatterns findings on that line.
# Codes map to subtype prefixes so multiple subtypes under one detector
# share a code.
_SUBTYPE_TO_CODE: Dict[str, str] = {
    # DAP001 — thin shims
    "pure-rename": "DAP001",
    "arg-reshaper": "DAP001",
    "config-unpacker": "DAP001",
    # DAP002 — phantom guards
    "epsilon-guard": "DAP002",
    "broad-except-swallowed": "DAP002",
    "redundant-none-check": "DAP002",
    "redundant-isinstance": "DAP002",
    # DAP003 — unnecessary indirection
    # (config-unpacker also appears here; indirection detector uses same subtype)
    "single-method-proxy": "DAP003",
    # DAP004 — over-commenting
    "trivial-comment": "DAP004",
    "over-commented-file": "DAP004",
    # DAP005 — single-use helpers
    "single-use-helper": "DAP005",
    # DAP006 — dead code
    "unused-import": "DAP006",
    "assigned-never-read": "DAP006",
    # DAP007 — stray prints
    "stray-print": "DAP007",
    "debug-logging": "DAP007",
    # DAP008 — write-then-discard
    "immediate-overwrite": "DAP008",
    "wrap-then-unwrap": "DAP008",
}

_NOQA_RE = re.compile(r"#\s*noqa\b(?::?\s*([A-Z0-9,\s]+))?", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    ".eggs",
    "*.egg-info",
}

def iter_python_files(paths: Sequence[str]) -> Generator[Path, None, None]:
    for p in paths:
        path = Path(p)
        if path.is_file() and path.suffix == ".py":
            yield path
        elif path.is_dir():
            for child in sorted(path.rglob("*.py")):
                if any(part in SKIP_DIRS for part in child.parts):
                    continue
                yield child

def parse_file(path: Path) -> Optional[ast.Module]:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return None

def _get_source_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []

def _snippet(lines: List[str], lineno: int, context: int = 1) -> str:
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    return "\n".join(lines[start:end])

def _func_body_no_docstring(node: ast.FunctionDef) -> List[ast.stmt]:
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, (ast.Constant, ast.Str))
    ):
        return body[1:]
    return body

def _call_name(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None

def _call_full_name(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        n = node.func
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
        return ".".join(reversed(parts))
    return None

# ---------------------------------------------------------------------------
# Detector 1: Thin Shims
# ---------------------------------------------------------------------------

def detect_thin_shims(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Find functions whose body is just: import something, return it."""

    # Collect module-level imports for fallback matching
    module_imports: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                name = alias.asname or alias.name
                module_imports[name] = node.module

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        body = _func_body_no_docstring(node)
        if not body or len(body) > 5:
            continue

        # Pattern A: local import + return delegating call
        local_imports: dict[str, str] = {}
        for stmt in body:
            if isinstance(stmt, ast.ImportFrom) and stmt.module:
                for alias in stmt.names:
                    name = alias.asname or alias.name
                    local_imports[name] = stmt.module

        last = body[-1]
        if not isinstance(last, ast.Return) or not isinstance(
            last.value, ast.Call
        ):
            # Pattern B: single return delegating to a module-level import
            if (
                len(body) == 1
                and isinstance(last, ast.Return)
                and isinstance(last.value, ast.Call)
            ):
                callee = _call_name(last.value)
                if callee and callee in module_imports:
                    subtype = _classify_shim(node, last.value)
                    yield Finding(
                        file=str(path),
                        line=node.lineno,
                        pattern="shim",
                        subtype=subtype,
                        description=(
                            f"{node.name}() delegates to "
                            f"{module_imports[callee]}.{callee}()"
                        ),
                        code_snippet=_snippet(lines, node.lineno),
                    )
            continue

        callee = _call_name(last.value)
        if callee and callee in local_imports:
            subtype = _classify_shim(node, last.value)
            yield Finding(
                file=str(path),
                line=node.lineno,
                pattern="shim",
                subtype=subtype,
                description=(
                    f"{node.name}() delegates to "
                    f"{local_imports[callee]}.{callee}()"
                ),
                code_snippet=_snippet(lines, node.lineno),
            )
        elif callee and callee in module_imports and len(body) <= 2:
            # Short body, returns a module-level import
            non_import = [
                s for s in body if not isinstance(s, (ast.Import, ast.ImportFrom))
            ]
            if len(non_import) == 1:
                subtype = _classify_shim(node, last.value)
                yield Finding(
                    file=str(path),
                    line=node.lineno,
                    pattern="shim",
                    subtype=subtype,
                    description=(
                        f"{node.name}() delegates to "
                        f"{module_imports[callee]}.{callee}()"
                    ),
                    code_snippet=_snippet(lines, node.lineno),
                )

def _classify_shim(
    func: ast.FunctionDef, call: ast.Call
) -> str:
    """Classify a shim as pure-rename, arg-reshaper, or config-unpacker."""
    func_args = {a.arg for a in func.args.args}
    has_attr_access = any(
        isinstance(a, ast.Attribute) for a in call.args
    ) or any(isinstance(kw.value, ast.Attribute) for kw in call.keywords)

    if has_attr_access:
        return "config-unpacker"

    call_arg_names = set()
    for a in call.args:
        if isinstance(a, ast.Name):
            call_arg_names.add(a.id)
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name):
            call_arg_names.add(kw.value.id)

    if call_arg_names and call_arg_names <= func_args:
        return "pure-rename"

    return "arg-reshaper"

# ---------------------------------------------------------------------------
# Detector 2: Phantom Guards
# ---------------------------------------------------------------------------

def detect_phantom_guards(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Find defensive code that likely guards against impossible conditions."""

    # Build a map of function params -> annotations for None-check detection
    func_param_annotations: dict[int, dict[str, ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            annotations = {}
            for arg in node.args.args:
                if arg.annotation:
                    annotations[arg.arg] = arg.annotation
            if annotations:
                func_param_annotations[id(node)] = annotations

    for node in ast.walk(tree):
        # --- Epsilon guards: max(expr, 1e-5) ---
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "max":
                if len(node.args) == 2:
                    for i, arg in enumerate(node.args):
                        if isinstance(arg, ast.Constant) and isinstance(
                            arg.value, (int, float)
                        ):
                            if 0 < arg.value < 0.01:
                                yield Finding(
                                    file=str(path),
                                    line=node.lineno,
                                    pattern="phantom",
                                    subtype="epsilon-guard",
                                    description=(
                                        f"max(..., {arg.value}) — epsilon "
                                        f"guard may mask real division-by-zero bugs"
                                    ),
                                    code_snippet=_snippet(lines, node.lineno),
                                )

        # --- Broad except with swallowed error ---
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                is_broad = handler.type is None  # bare except:
                if not is_broad and isinstance(handler.type, ast.Name):
                    is_broad = handler.type.id in (
                        "Exception",
                        "BaseException",
                    )
                if not is_broad and isinstance(handler.type, ast.Tuple):
                    for elt in handler.type.elts:
                        if isinstance(elt, ast.Name) and elt.id in (
                            "Exception",
                            "BaseException",
                        ):
                            is_broad = True
                            break

                if is_broad and handler.body:
                    first = handler.body[0]
                    is_swallowed = False
                    if isinstance(first, ast.Pass):
                        is_swallowed = True
                    elif isinstance(first, ast.Return):
                        is_swallowed = True
                    elif (
                        isinstance(first, ast.Expr)
                        and isinstance(first.value, ast.Constant)
                    ):
                        is_swallowed = True  # bare expression like `...`

                    if is_swallowed:
                        yield Finding(
                            file=str(path),
                            line=handler.lineno,
                            pattern="phantom",
                            subtype="broad-except-swallowed",
                            description=(
                                "Broad except clause swallows errors — "
                                "may hide real bugs"
                            ),
                            code_snippet=_snippet(lines, handler.lineno),
                        )

        # --- Redundant None checks on non-Optional params ---
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_annots = {}
            for arg in node.args.args:
                if arg.annotation:
                    param_annots[arg.arg] = arg.annotation

            for child in ast.walk(node):
                if isinstance(child, ast.Compare) and len(child.ops) == 1:
                    if isinstance(child.ops[0], ast.IsNot):
                        if (
                            len(child.comparators) == 1
                            and isinstance(
                                child.comparators[0], ast.Constant
                            )
                            and child.comparators[0].value is None
                        ):
                            if isinstance(child.left, ast.Name):
                                param_name = child.left.id
                                if param_name in param_annots:
                                    annot = param_annots[param_name]
                                    if not _annotation_allows_none(annot):
                                        yield Finding(
                                            file=str(path),
                                            line=child.lineno,
                                            pattern="phantom",
                                            subtype="redundant-none-check",
                                            description=(
                                                f"'{param_name} is not None' "
                                                f"check but type annotation "
                                                f"doesn't include Optional/None"
                                            ),
                                            code_snippet=_snippet(
                                                lines, child.lineno
                                            ),
                                        )

        # --- Redundant isinstance assertions on typed params ---
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_annots = {}
            for arg in node.args.args:
                if arg.annotation:
                    param_annots[arg.arg] = arg.annotation

            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Assert)
                    and isinstance(child.test, ast.Call)
                    and isinstance(child.test.func, ast.Name)
                    and child.test.func.id == "isinstance"
                    and len(child.test.args) >= 2
                ):
                    first_arg = child.test.args[0]
                    if (
                        isinstance(first_arg, ast.Name)
                        and first_arg.id in param_annots
                    ):
                        yield Finding(
                            file=str(path),
                            line=child.lineno,
                            pattern="phantom",
                            subtype="redundant-isinstance",
                            description=(
                                f"assert isinstance({first_arg.id}, ...) "
                                f"but parameter already has type annotation"
                            ),
                            code_snippet=_snippet(lines, child.lineno),
                        )

def _annotation_allows_none(annot: ast.expr) -> bool:
    """Check if a type annotation includes None/Optional."""
    if isinstance(annot, ast.Constant) and annot.value is None:
        return True
    if isinstance(annot, ast.Name) and annot.id == "None":
        return True
    # Optional[X] is Union[X, None] in modern Python
    if isinstance(annot, ast.Subscript):
        if isinstance(annot.value, ast.Name):
            if annot.value.id == "Optional":
                return True
            if annot.value.id == "Union":
                pass
                if isinstance(annot.slice, ast.Tuple):
                    for elt in annot.slice.elts:
                        if isinstance(elt, ast.Constant) and elt.value is None:
                            return True
                        if isinstance(elt, ast.Name) and elt.id == "None":
                            return True
    # X | None syntax (Python 3.10+)
    if isinstance(annot, ast.BinOp) and isinstance(annot.op, ast.BitOr):
        return _annotation_allows_none(annot.left) or _annotation_allows_none(
            annot.right
        )
    return False

# ---------------------------------------------------------------------------
# Detector 3: Unnecessary Indirection
# ---------------------------------------------------------------------------

def detect_unnecessary_indirection(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Find config-unpacker wrappers and single-method proxy classes."""

    # Method names that are inherently "config-unpacker shaped" but are
    # legitimate framework patterns (Luigi requires(), copy(), etc.)
    INDIRECTION_METHOD_SKIP = {"requires", "copy", "clone", "__copy__", "__deepcopy__"}

    for node in ast.walk(tree):
        # --- Config unpackers ---
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in INDIRECTION_METHOD_SKIP:
                continue

            body = _func_body_no_docstring(node)
            if not body or len(body) > 3:
                continue

            # Filter to just non-import statements
            non_import = [
                s
                for s in body
                if not isinstance(s, (ast.Import, ast.ImportFrom))
            ]
            if len(non_import) != 1:
                continue

            ret = non_import[0]
            if not isinstance(ret, ast.Return) or not isinstance(
                ret.value, ast.Call
            ):
                continue

            call = ret.value
            attr_sources = []
            for arg in list(call.args) + [kw.value for kw in call.keywords]:
                if isinstance(arg, ast.Attribute) and isinstance(
                    arg.value, ast.Name
                ):
                    attr_sources.append(arg.value.id)

            if len(attr_sources) >= 2:
                # Most args come from the same object
                counts = Counter(attr_sources)
                dominant_source, dominant_count = counts.most_common(1)[0]
                total_args = len(call.args) + len(call.keywords)
                if dominant_count >= 2 and dominant_count / total_args >= 0.5:
                    callee = _call_full_name(call) or "?"
                    yield Finding(
                        file=str(path),
                        line=node.lineno,
                        pattern="indirection",
                        subtype="config-unpacker",
                        description=(
                            f"{node.name}() unpacks '{dominant_source}' "
                            f"fields and delegates to {callee}()"
                        ),
                        code_snippet=_snippet(lines, node.lineno),
                    )

        # --- Single-purpose wrapper classes ---
        if isinstance(node, ast.ClassDef):
            methods = [
                n
                for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            public_methods = [
                m for m in methods if not m.name.startswith("_") or m.name == "__init__"
            ]
            non_init = [m for m in public_methods if m.name != "__init__"]

            if len(non_init) != 1:
                continue

            method = non_init[0]
            mbody = _func_body_no_docstring(method)
            if len(mbody) != 1:
                continue

            ret = mbody[0]
            if not isinstance(ret, ast.Return) or not isinstance(
                ret.value, ast.Call
            ):
                continue

            call = ret.value
            if isinstance(call.func, ast.Attribute):
                if isinstance(call.func.value, ast.Attribute):
                    if isinstance(call.func.value.value, ast.Name):
                        if call.func.value.value.id == "self":
                            delegate = call.func.value.attr
                            callee_method = call.func.attr
                            yield Finding(
                                file=str(path),
                                line=node.lineno,
                                pattern="indirection",
                                subtype="single-method-proxy",
                                description=(
                                    f"class {node.name} has one public method "
                                    f"({method.name}) that just delegates to "
                                    f"self.{delegate}.{callee_method}()"
                                ),
                                code_snippet=_snippet(lines, node.lineno),
                            )

# ---------------------------------------------------------------------------
# Detector 4: Over-Commenting
# ---------------------------------------------------------------------------

# Patterns that match trivial "paraphrase the code" comments
_TRIVIAL_COMMENT_RE = re.compile(
    r"^\s*#\s*("
    r"(import|loop|iterate|return|set|get|create|initialize|define|check|call|assign)"
    r"\s"
    r"|"
    r"(the\s+following|this\s+(is|function|method|class|variable|section|block))"
    r")",
    re.IGNORECASE,
)

def detect_over_commenting(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Flag files where comment density is suspiciously high, and individual
    comments that merely paraphrase the adjacent code line."""

    if not lines:
        return

    code_lines = 0
    comment_lines = 0
    trivial_comments: List[Tuple[int, str]] = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comment_lines += 1
            if _TRIVIAL_COMMENT_RE.match(stripped):
                trivial_comments.append((i, stripped))
        else:
            code_lines += 1
            # Inline comment
            if "  #" in line or "\t#" in line:
                comment_lines += 1

    # Flag individual trivial comments
    for lineno, text in trivial_comments:
        yield Finding(
            file=str(path),
            line=lineno,
            pattern="garbage",
            subtype="trivial-comment",
            description=f"Comment paraphrases code: {text[:60]}",
            code_snippet=_snippet(lines, lineno, context=0),
            fix_action="delete-lines",
            fix_lines=(lineno, lineno),
        )

    # Flag files with high comment-to-code ratio (> 40% and > 20 comments)
    total = code_lines + comment_lines
    if total > 30 and comment_lines > 20:
        ratio = comment_lines / total
        if ratio > 0.40:
            yield Finding(
                file=str(path),
                line=1,
                pattern="garbage",
                subtype="over-commented-file",
                description=(
                    f"Comment density {ratio:.0%} ({comment_lines} comments "
                    f"/ {code_lines} code lines) — review for tutorial-style "
                    f"comments"
                ),
            )

# ---------------------------------------------------------------------------
# Detector 5: Single-Use Helpers
# ---------------------------------------------------------------------------

def detect_single_use_helpers(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Find module-level functions that are called from exactly one site
    in the same file, suggesting premature extraction."""

    # Collect all module-level function defs (not methods)
    module_funcs: Dict[str, ast.FunctionDef] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Skip private/dunder and test helpers
            if node.name.startswith("__") or node.name.startswith("test_"):
                continue
            module_funcs[node.name] = node

    if not module_funcs:
        return

    # Count call sites for each function within this file
    call_counts: Dict[str, int] = {name: 0 for name in module_funcs}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _call_name(node)
            if callee in call_counts:
                call_counts[callee] += 1

    for name, count in call_counts.items():
        if count == 1:
            func_node = module_funcs[name]
            body = _func_body_no_docstring(func_node)
            # Only flag small functions (≤ 10 statements) — large ones
            # may be extracted for readability even if called once
            if len(body) <= 10:
                # Find the call site line for the suggestion
                call_line = None
                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Call)
                        and _call_name(node) == name
                    ):
                        call_line = node.lineno
                        break
                suggestion = (
                    f"Consider inlining {name}() at its single call site"
                    f" (L{call_line})" if call_line else
                    f"Consider inlining {name}()"
                )
                yield Finding(
                    file=str(path),
                    line=func_node.lineno,
                    pattern="garbage",
                    subtype="single-use-helper",
                    description=(
                        f"{name}() is called once in this file and has "
                        f"{len(body)} statement(s) — may be inlined"
                    ),
                    code_snippet=_snippet(lines, func_node.lineno),
                    fix_action="suggest",
                    fix_suggestion=suggestion,
                )

# ---------------------------------------------------------------------------
# Detector 6: Dead Code (unused imports, write-never-read locals)
# ---------------------------------------------------------------------------

def detect_dead_code(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Find unused imports and local variables that are assigned but never read."""

    # --- Unused imports ---
    # Collect all imported names at module level
    imported_names: Dict[str, int] = {}  # name -> lineno
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                imported_names[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module == "__future__":
                continue  # __future__ imports are side-effect-only
            if node.names and node.names[0].name == "*":
                continue  # skip star imports
            for alias in node.names:
                name = alias.asname or alias.name
                imported_names[name] = node.lineno

    # Walk the tree for Name references (excluding import statements themselves)
    referenced_names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            referenced_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            # Handle cases like module.func
            n = node
            while isinstance(n, ast.Attribute):
                n = n.value
            if isinstance(n, ast.Name):
                referenced_names.add(n.id)

    # Also count names used in decorators, type annotations, __all__
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # String references (e.g., in __all__ lists)
            if node.value in imported_names:
                referenced_names.add(node.value)

    for name, lineno in imported_names.items():
        if name not in referenced_names and not name.startswith("_"):
            # Skip imports that already have a # noqa comment (e.g., F401
            # for intentional re-exports)
            if lineno <= len(lines) and re.search(
                r"#\s*noqa\b", lines[lineno - 1]
            ):
                continue
            # Count how many imported names share this line number
            names_on_line = [
                n for n, ln in imported_names.items() if ln == lineno
            ]
            unused_on_line = [
                n
                for n in names_on_line
                if n not in referenced_names and not n.startswith("_")
            ]
            all_unused = len(unused_on_line) == len(names_on_line)

            # Find the full extent of a possibly multi-line import
            end_lineno = lineno
            if not all_unused:
                # Multi-name import with some names still used — can't
                # auto-delete the line; leave fix_action empty
                fix_action = ""
                fix_lines = (0, 0)
            else:
                # All names on this line are unused — delete the whole
                pass
                # or backslash continuation)
                for node in ast.iter_child_nodes(tree):
                    if (
                        isinstance(node, (ast.Import, ast.ImportFrom))
                        and node.lineno == lineno
                        and hasattr(node, "end_lineno")
                        and node.end_lineno
                    ):
                        end_lineno = node.end_lineno
                        break
                fix_action = "delete-lines"
                fix_lines = (lineno, end_lineno)

            yield Finding(
                file=str(path),
                line=lineno,
                pattern="garbage",
                subtype="unused-import",
                description=f"'{name}' is imported but never used",
                code_snippet=_snippet(lines, lineno, context=0),
                fix_action=fix_action,
                fix_lines=fix_lines,
            )

    # --- Assigned-but-never-read locals ---
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Simple scope: collect assignments and reads within this function
        assigned: Dict[str, List[int]] = {}  # name -> [linenos]
        read: Set[str] = set()

        for child in ast.walk(node):
            # Assignments
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        assigned.setdefault(target.id, []).append(
                            child.lineno
                        )
            elif isinstance(child, ast.AnnAssign) and child.target:
                if isinstance(child.target, ast.Name) and child.value:
                    assigned.setdefault(child.target.id, []).append(
                        child.lineno
                    )

            # Reads
            if isinstance(child, ast.Name) and isinstance(
                child.ctx, ast.Load
            ):
                read.add(child.id)

        # Parameters and loop variables are expected to be "assigned"
        param_names = {a.arg for a in node.args.args}
        param_names |= {a.arg for a in node.args.kwonlyargs}
        if node.args.vararg:
            param_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            param_names.add(node.args.kwarg.arg)

        for name, line_list in assigned.items():
            if name in read or name in param_names:
                continue
            if name.startswith("_"):
                continue  # convention for intentionally unused
            yield Finding(
                file=str(path),
                line=line_list[0],
                pattern="garbage",
                subtype="assigned-never-read",
                description=(
                    f"Local variable '{name}' is assigned but never read"
                ),
                code_snippet=_snippet(lines, line_list[0], context=0),
            )

# ---------------------------------------------------------------------------
# Detector 7: Stray Prints / Debug Logging
# ---------------------------------------------------------------------------

_STRAY_PRINT_FUNCS = {"print", "pprint", "pp"}
_DEBUG_LOG_METHODS = {"debug"}

def detect_stray_prints(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Flag bare print() calls and logging.debug() in non-CLI source files."""

    # Heuristic: skip files that look like CLI entry points or test utilities
    path_str = str(path)
    if any(
        s in path_str
        for s in ("__main__", "cli", "test_", "conftest", "scripts/")
    ):
        return

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.If):
            # Quick check for if __name__ == "__main__"
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
            ):
                return

    # Build child → parent map so we can check enclosing context
    _parents: Dict[int, ast.AST] = {}
    for parent_node in ast.walk(tree):
        for child in ast.iter_child_nodes(parent_node):
            _parents[id(child)] = parent_node

    def _is_inside_verbose_guard(n: ast.AST) -> bool:
        """Walk up the parent chain looking for `if verbose` / `if self._verbose`."""
        cur = n
        while id(cur) in _parents:
            p = _parents[id(cur)]
            if isinstance(p, ast.If):
                test = p.test
                if isinstance(test, ast.Name) and "verbose" in test.id.lower():
                    return True
                if (
                    isinstance(test, ast.Attribute)
                    and "verbose" in test.attr.lower()
                ):
                    return True
            cur = p
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # print() / pprint()
        if isinstance(node.func, ast.Name) and node.func.id in _STRAY_PRINT_FUNCS:
            if _is_inside_verbose_guard(node):
                continue
            # Only fixable if the print is a standalone Expr statement
            # (not embedded in an assignment or return)
            # Walk up: find the parent Expr statement
            fix_action = ""
            fix_lines: Tuple[int, int] = (0, 0)
            for parent in ast.walk(tree):
                if (
                    isinstance(parent, ast.Expr)
                    and isinstance(parent.value, ast.Call)
                    and parent.value is node
                ):
                    pend = getattr(parent, "end_lineno", parent.lineno)
                    fix_action = "delete-lines"
                    fix_lines = (parent.lineno, pend)
                    break

            yield Finding(
                file=str(path),
                line=node.lineno,
                pattern="garbage",
                subtype="stray-print",
                description=f"{node.func.id}() call in production code",
                code_snippet=_snippet(lines, node.lineno, context=0),
                fix_action=fix_action,
                fix_lines=fix_lines,
            )

        # logging.debug() or logger.debug()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _DEBUG_LOG_METHODS
        ):
            yield Finding(
                file=str(path),
                line=node.lineno,
                pattern="garbage",
                subtype="debug-logging",
                description="debug-level log in production code — review if intentional",
                code_snippet=_snippet(lines, node.lineno, context=0),
            )

# ---------------------------------------------------------------------------
# Detector 8: Write-Then-Discard
# ---------------------------------------------------------------------------

def detect_write_then_discard(
    path: Path, tree: ast.Module, lines: List[str]
) -> Generator[Finding, None, None]:
    """Find variables that are assigned and immediately overwritten on the
    next statement, or wrapped then unwrapped (e.g., DataFrame(x) then .iloc[:, 0])."""

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        body = node.body
        for i in range(len(body) - 1):
            stmt = body[i]
            next_stmt = body[i + 1]

            # Pattern: x = expr1 ; x = expr2 (immediate overwrite)
            if isinstance(stmt, ast.Assign) and isinstance(
                next_stmt, ast.Assign
            ):
                for target in stmt.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if target.id == "_":
                        continue  # bare _ is convention for discarded
                    for next_target in next_stmt.targets:
                        if (
                            isinstance(next_target, ast.Name)
                            and next_target.id == target.id
                        ):
                            pass
                            # the variable (e.g., x = x + 1 is fine)
                            refs = set()
                            for child in ast.walk(next_stmt.value):
                                if isinstance(child, ast.Name):
                                    refs.add(child.id)
                            if target.id not in refs:
                                stmt_end = getattr(
                                    stmt, "end_lineno", stmt.lineno
                                )
                                yield Finding(
                                    file=str(path),
                                    line=stmt.lineno,
                                    pattern="garbage",
                                    subtype="immediate-overwrite",
                                    description=(
                                        f"'{target.id}' is assigned on L{stmt.lineno} "
                                        f"then immediately overwritten on L{next_stmt.lineno}"
                                    ),
                                    code_snippet=_snippet(
                                        lines, stmt.lineno, context=0
                                    ),
                                    fix_action="delete-lines",
                                    fix_lines=(stmt.lineno, stmt_end),
                                )

            # Pattern: x = SomeWrapper(y); ... uses x.iloc[:, 0] or x.values
            # (wrap-then-unwrap within 3 lines)
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                if not isinstance(stmt.value, ast.Call):
                    continue

                wrapper_name = _call_name(stmt.value)
                if wrapper_name not in (
                    "DataFrame",
                    "pd.DataFrame",
                    "np.array",
                    "list",
                    "dict",
                    "set",
                    "tuple",
                ):
                    continue

                # Look ahead up to 3 statements for unwrapping access
                var_name = target.id
                for j in range(i + 1, min(i + 4, len(body))):
                    future = body[j]
                    for child in ast.walk(future):
                        if (
                            isinstance(child, ast.Subscript)
                            and isinstance(child.value, ast.Name)
                            and child.value.id == var_name
                        ):
                            # Build suggestion: pass the original arg
                            # directly instead of wrapping
                            orig_args = ""
                            if stmt.value.args:
                                a = stmt.value.args[0]
                                if isinstance(a, ast.Name):
                                    orig_args = a.id
                            suggestion = (
                                f"Pass the original value"
                                + (f" ({orig_args})" if orig_args else "")
                                + f" directly instead of wrapping with "
                                f"{wrapper_name}() then subscripting"
                            )
                            yield Finding(
                                file=str(path),
                                line=stmt.lineno,
                                pattern="garbage",
                                subtype="wrap-then-unwrap",
                                description=(
                                    f"'{var_name}' wrapped with "
                                    f"{wrapper_name}() on L{stmt.lineno} "
                                    f"then immediately subscripted on "
                                    f"L{child.lineno}"
                                ),
                                code_snippet=_snippet(
                                    lines, stmt.lineno, context=0
                                ),
                                fix_action="suggest",
                                fix_suggestion=suggestion,
                            )
                            break
                    else:
                        continue
                    break

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DETECTORS = {
    "shim": detect_thin_shims,
    "phantom": detect_phantom_guards,
    "indirection": detect_unnecessary_indirection,
    "overcomment": detect_over_commenting,
    "single-use": detect_single_use_helpers,
    "deadcode": detect_dead_code,
    "stray-print": detect_stray_prints,
    "write-discard": detect_write_then_discard,
}

def _is_suppressed(finding: Finding, source_lines: List[str]) -> bool:
    """Check if a finding is suppressed by a ``# noqa: DAPxxx`` comment."""
    if finding.line < 1 or finding.line > len(source_lines):
        return False
    line = source_lines[finding.line - 1]
    m = _NOQA_RE.search(line)
    if m is None:
        return False
    codes_str = m.group(1)
    if not codes_str:
        # Bare `# noqa: DAP` with no specific code
        return "DAP" in line.upper().split("NOQA")[1] if "NOQA" in line.upper() else False
    codes = {c.strip().upper() for c in codes_str.split(",")}
    if "DAP" in codes:
        return True
    finding_code = _SUBTYPE_TO_CODE.get(finding.subtype, "")
    return finding_code in codes


def scan(
    paths: Sequence[str], patterns: Sequence[str]
) -> List[Finding]:
    findings = []
    detectors = [DETECTORS[p] for p in patterns]

    for filepath in iter_python_files(paths):
        tree = parse_file(filepath)
        if tree is None:
            continue
        source_lines = _get_source_lines(filepath)
        for detector in detectors:
            for finding in detector(filepath, tree, source_lines):
                if not _is_suppressed(finding, source_lines):
                    findings.append(finding)

    findings.sort(key=lambda f: (f.file, f.line))
    return findings

# ---------------------------------------------------------------------------
# --fix: auto-apply safe fixes
# ---------------------------------------------------------------------------

def apply_fixes(findings: List[Finding]) -> Tuple[int, int]:
    """Apply delete-lines fixes in-place. Returns (fixed, skipped) counts."""
    fixable = [
        f
        for f in findings
        if f.fix_action == "delete-lines"
        and f.fix_lines != (0, 0)
        and f.subtype in FIXABLE_SUBTYPES
    ]

    # Group by file
    by_file: Dict[str, List[Finding]] = {}
    for f in fixable:
        by_file.setdefault(f.file, []).append(f)

    fixed = 0
    skipped = 0

    for filepath, file_findings in sorted(by_file.items()):
        path = Path(filepath)
        try:
            source = path.read_text(encoding="utf-8")
            original_lines = source.splitlines(keepends=True)
        except (OSError, UnicodeDecodeError):
            skipped += len(file_findings)
            continue

        # Parse the AST so we can detect "sole statement in block" cases
        tree = parse_file(path)

        # Build a set of lines that are the sole body statement of
        # a compound block (if/elif/else/for/while/with/try/except/finally).
        # Deleting these would produce a SyntaxError; replace with `pass`.
        sole_body_lines: Set[int] = set()
        if tree:
            for node in ast.walk(tree):
                # Collect all "body" lists from compound statements
                body_attrs = []
                for attr in ("body", "orelse", "finalbody", "handlers"):
                    block = getattr(node, attr, None)
                    if isinstance(block, list):
                        body_attrs.append(block)
                for block in body_attrs:
                    if len(block) == 1:
                        stmt = block[0]
                        end = getattr(stmt, "end_lineno", stmt.lineno)
                        for ln in range(stmt.lineno, end + 1):
                            sole_body_lines.add(ln)

        # Collect all line ranges to delete, then deduplicate
        lines_to_delete: Set[int] = set()
        needs_pass: Dict[int, str] = {}  # line -> indentation for `pass`
        for f in file_findings:
            start, end = f.fix_lines
            is_sole = any(
                ln in sole_body_lines for ln in range(start, end + 1)
            )
            if is_sole:
                # Replace with `pass` instead of deleting
                # Use the indentation of the first line
                if start <= len(original_lines):
                    indent = re.match(
                        r"(\s*)", original_lines[start - 1]
                    ).group(1)
                    needs_pass[start] = indent
                    # Delete all but the first line (which becomes `pass`)
                    for ln in range(start + 1, end + 1):
                        lines_to_delete.add(ln)
                else:
                    lines_to_delete.update(range(start, end + 1))
            else:
                for ln in range(start, end + 1):
                    lines_to_delete.add(ln)

        if not lines_to_delete and not needs_pass:
            skipped += len(file_findings)
            continue

        # Rebuild file
        new_lines = []
        for i, line in enumerate(original_lines, 1):
            if i in needs_pass:
                new_lines.append(f"{needs_pass[i]}pass\n")
            elif i not in lines_to_delete:
                new_lines.append(line)

        # Remove trailing blank-line clusters left by deletions
        # (two+ consecutive blank lines → one)
        cleaned: List[str] = []
        prev_blank = False
        for line in new_lines:
            is_blank = line.strip() == ""
            if is_blank and prev_blank:
                continue
            cleaned.append(line)
            prev_blank = is_blank

        path.write_text("".join(cleaned), encoding="utf-8")
        fixed += len(file_findings)

    return fixed, skipped

# ---------------------------------------------------------------------------
# --suggest: emit unified diffs for human review
# ---------------------------------------------------------------------------

def emit_suggestions(findings: List[Finding]) -> str:
    """Emit human-readable suggestions for findings that support --suggest."""
    suggestable = [
        f
        for f in findings
        if f.fix_action == "suggest" and f.subtype in SUGGESTABLE_SUBTYPES
    ]

    # Also include fixable findings as previews (show what --fix would do)
    fixable = [
        f
        for f in findings
        if f.fix_action == "delete-lines"
        and f.fix_lines != (0, 0)
        and f.subtype in FIXABLE_SUBTYPES
    ]

    if not suggestable and not fixable:
        return "No suggestions to emit."

    out: List[str] = []

    if fixable:
        out.append("=" * 70)
        out.append("  Auto-fixable with --fix:")
        out.append("=" * 70)
        by_file: Dict[str, List[Finding]] = {}
        for f in fixable:
            by_file.setdefault(f.file, []).append(f)

        for filepath, ffs in sorted(by_file.items()):
            out.append(f"\n  {filepath}")
            path = Path(filepath)
            lines = _get_source_lines(path)
            for f in sorted(ffs, key=lambda x: x.line):
                start, end = f.fix_lines
                out.append(f"    L{start}-{end}: DELETE  [{f.subtype}] {f.description}")
                for ln in range(start, end + 1):
                    if ln <= len(lines):
                        out.append(f"      - {lines[ln - 1]}")

    if suggestable:
        out.append("")
        out.append("=" * 70)
        out.append("  Manual review needed:")
        out.append("=" * 70)
        for f in suggestable:
            out.append(f"\n  {f.file}:{f.line}  [{f.subtype}]")
            out.append(f"    {f.description}")
            if f.fix_suggestion:
                out.append(f"    Suggestion: {f.fix_suggestion}")
            if f.code_snippet:
                for line in f.code_snippet.splitlines()[:3]:
                    out.append(f"    | {line}")

    return "\n".join(out)

def format_text(findings: List[Finding]) -> str:
    if not findings:
        return "No anti-patterns found."

    out = []
    current_file = None
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            out.append(f"\n{'=' * 70}")
            out.append(f"  {f.file}")
            out.append(f"{'=' * 70}")

        tag = f"[{f.pattern}/{f.subtype}]"
        out.append(f"\n  L{f.line:<5} {tag}")
        out.append(f"         {f.description}")
        if f.code_snippet:
            for line in f.code_snippet.splitlines()[:3]:
                out.append(f"         | {line}")

    out.append(f"\n--- {len(findings)} finding(s) ---")
    return "\n".join(out)

def format_json(findings: List[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect common AI-generated code anti-patterns."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Files or directories to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON",
    )
    all_patterns = list(DETECTORS.keys())
    parser.add_argument(
        "--pattern",
        choices=all_patterns + ["all"],
        default="all",
        help=f"Which pattern to detect (default: all). Choices: {', '.join(all_patterns)}",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Auto-fix safe issues in-place: unused imports, stray prints, "
            "trivial comments, immediate overwrites."
        ),
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        help=(
            "Emit actionable suggestions: preview what --fix would delete, "
            "plus manual-review items for single-use helpers and "
            "wrap-then-unwrap patterns."
        ),
    )
    args = parser.parse_args(argv)

    patterns = (
        list(DETECTORS.keys()) if args.pattern == "all" else [args.pattern]
    )
    findings = scan(args.paths, patterns)

    if args.suggest:
        print(emit_suggestions(findings))
        return 1 if findings else 0

    if args.fix:
        fixed, skipped = apply_fixes(findings)
        print(f"Fixed {fixed} issue(s), skipped {skipped}.")
        if skipped:
            # Re-scan and show remaining
            remaining = scan(args.paths, patterns)
            unfixed = [
                f
                for f in remaining
                if f.subtype not in FIXABLE_SUBTYPES
                or f.fix_action != "delete-lines"
            ]
            if unfixed:
                print(f"\n{len(unfixed)} issue(s) remain (not auto-fixable):")
                print(format_text(unfixed))
        return 0 if fixed else 1

    if args.json:
        print(format_json(findings))
    else:
        print(format_text(findings))

    return 1 if findings else 0

if __name__ == "__main__":
    sys.exit(main())
