# Ported from soc_defender.
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOTS = (PROJECT_ROOT / "smart_soc_agent", PROJECT_ROOT / "scripts", PROJECT_ROOT / "tests")


def test_no_sibling_repo_runtime_imports_or_path_insertion():
    forbidden = (
        "from " + "defender.",
        "import " + "defender.",
        "../" + "soc_defender",
        "..\\" + "soc_defender",
        "../" + "SecRL",
        "..\\" + "SecRL",
        "../" + "opensec-env",
        "..\\" + "opensec-env",
    )
    offenders: list[str] = []
    for root in PYTHON_ROOTS:
        for path in root.rglob("*.py"):
            if path.name == "test_standalone_artifact.py":
                continue
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                if marker in text:
                    offenders.append(f"{path.relative_to(PROJECT_ROOT)} contains {marker!r}")
    assert offenders == []
