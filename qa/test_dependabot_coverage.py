"""Every dependency manifest in the repo must be watched by Dependabot."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))


def covered(ecosystem: str) -> set[str]:
    dirs: set[str] = set()
    for update in CONFIG["updates"]:
        if update["package-ecosystem"] == ecosystem:
            dirs.update(update.get("directories", []))
            if "directory" in update:
                dirs.add(update["directory"])
    return dirs


def rel_dir(path: Path) -> str:
    rel = path.parent.relative_to(ROOT).as_posix()
    return "/" if rel == "." else f"/{rel}"


def manifests(pattern: str) -> set[str]:
    return {rel_dir(p) for p in ROOT.rglob(pattern) if "node_modules" not in p.parts and ".git" not in p.parts}


def test_every_update_has_a_cooldown() -> None:
    for update in CONFIG["updates"]:
        assert update.get("cooldown", {}).get("default-days", 0) >= 7, update["package-ecosystem"]


def test_github_actions_covered() -> None:
    assert "/" in covered("github-actions")


def test_python_locks_covered() -> None:
    assert manifests("requirements*.lock") <= covered("pip")


def test_npm_lockfiles_covered() -> None:
    assert manifests("package-lock.json") <= covered("npm")


def test_gradle_projects_covered() -> None:
    assert manifests("settings.gradle.kts") <= covered("gradle")


def test_dockerfiles_and_compose_covered() -> None:
    assert manifests("Dockerfile") <= covered("docker")
    compose_dirs = {d for d in manifests("docker-compose*.yml") if d != "/"}  # root file only `include:`s deploy/
    assert compose_dirs <= covered("docker-compose")
