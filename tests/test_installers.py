# SPDX-License-Identifier: EUPL-1.2
"""The installers' helper calls fit their helpers: a keyword the helper does not take fails here, not on a lab box
(full-stack run 5: the edge installer called write(..., keep=False), which only the core installer's write takes)."""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted((ROOT / "deploy").glob("*/*.py"))


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_local_helper_call_uses_its_parameters(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    defs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            a = node.args
            if a.kwarg is None:   # a **kwargs helper takes anything
                defs[node.name] = {x.arg for x in a.args + a.kwonlyargs + a.posonlyargs}
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in defs:
            for kw in node.keywords:
                if kw.arg is not None and kw.arg not in defs[node.func.id]:
                    bad.append(f"line {node.lineno}: {node.func.id}(..., {kw.arg}=...)")
    assert not bad, f"{path.name}: " + "; ".join(bad)
