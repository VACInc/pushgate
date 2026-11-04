"""Container images must be referenced by immutable digest."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_container_image_reference_is_digest_pinned():
    sources = [ROOT / "server" / "Dockerfile", *sorted((ROOT / "deploy").glob("docker-compose*.yml"))]
    refs = []
    for path in sources:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*(?:FROM|image:)\s+(\S+)", line)
            if match:
                refs.append((path.name, match.group(1)))
    assert refs
    for name, ref in refs:
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{name}: {ref} is not pinned by digest"
