"""Install instructions must go through the hashed/locked dependency sets."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = [*ROOT.glob("*.md"), *ROOT.glob("*/README.md"), *ROOT.glob("docs/*.md"), *ROOT.glob("qa/*.py")]


def test_no_unlocked_install_instructions() -> None:
    offenders = []
    for path in DOC_FILES:
        if path.name == Path(__file__).name:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bnpm install\s*$", line) or re.search(r"\bnpm i\s*$", line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}: bare npm install (use npm ci)")
            if "pip install" in line and "--require-hashes" not in line and "--no-deps" not in line:
                offenders.append(f"{path.relative_to(ROOT)}:{number}: pip install without --require-hashes")
    assert not offenders, "\n".join(offenders)
