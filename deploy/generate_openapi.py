from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.app.config import Settings
from server.app.main import create_app


def main() -> int:
    # Schema generation must not create or inspect a database in the checkout.
    spec = create_app(Settings(database_url="sqlite:///:memory:")).openapi()
    (ROOT / "server/openapi.json").write_text(json.dumps(spec, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
