"""Keep the user-facing docs honest: snippets parse, names exist, the API table is complete."""

import ast
import inspect
import re
import textwrap
import tomllib
from pathlib import Path

import pytest

import dbsc
from dbsc import Config, DbscServer

ROOT = Path(__file__).parent.parent
README = (ROOT / "README.md").read_text()
PYTHON_BLOCKS = [
    textwrap.dedent(block)
    for block in re.findall(r"```python\n(.*?)^ *```", README, re.DOTALL | re.MULTILINE)
]


def test_readme_has_python_examples() -> None:
    assert len(PYTHON_BLOCKS) >= 5


@pytest.mark.parametrize("block", PYTHON_BLOCKS, ids=lambda b: b.splitlines()[0][:40])
def test_readme_python_blocks_parse(block: str) -> None:
    # Some snippets use top-level `await`, as they'd appear inside a request handler.
    compile(block, "<README>", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT, dont_inherit=True)


@pytest.mark.parametrize("block", PYTHON_BLOCKS, ids=lambda b: b.splitlines()[0][:40])
def test_readme_imports_from_dbsc_exist(block: str) -> None:
    tree = compile(
        block, "<README>", "exec", flags=ast.PyCF_ONLY_AST | ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "dbsc":
            for alias in node.names:
                assert alias.name in dbsc.__all__, alias.name


def test_readme_names_every_public_export() -> None:
    missing = [name for name in dbsc.__all__ if f"`{name}" not in README]
    assert not missing


def test_readme_api_table_covers_every_server_method() -> None:
    public = [name for name, _ in inspect.getmembers(DbscServer) if not name.startswith("_")]
    missing = [name for name in public if f"`{name}(" not in README]
    assert not missing


def test_readme_config_table_covers_every_field() -> None:
    missing = [name for name in Config.__dataclass_fields__ if f"| `{name}` |" not in README]
    assert not missing


def test_changelog_documents_the_current_version() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert f"## [{version}]" in changelog
    assert f"[{version}]: " in changelog, "comparison link at the bottom"
