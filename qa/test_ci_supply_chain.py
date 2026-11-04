"""Supply-chain guard rails for GitHub Actions workflows."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
PINNED_USES = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\d+(\.\d+)*\s*$")
READ_ONLY_SCOPES = {"contents", "actions", "checks", "packages", "pull-requests", "security-events", "statuses"}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps(workflow: dict):
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            yield job_name, step


def test_workflows_exist() -> None:
    assert WORKFLOWS, "expected at least one workflow under .github/workflows"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_commit_sha(path: Path) -> None:
    for job_name, step in steps(load(path)):
        uses = step.get("uses")
        if uses is None or uses.startswith("./"):
            continue
        assert not uses.startswith("docker://") or "@sha256:" in uses, f"{job_name}: {uses}"
        if uses.startswith("docker://"):
            continue
        assert PINNED_USES.match(uses), f"{path.name}:{job_name} uses an unpinned action: {uses}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_pinned_action_carries_a_version_comment_for_updaters(path: Path) -> None:
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.search(r"^\s*(-\s+)?uses:\s*[^.\s]", line) and "docker://" not in line:
            assert VERSION_COMMENT.search(line), f"{path.name}: missing '# vX.Y.Z' comment: {line.strip()}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_default_token_has_no_permissions(path: Path) -> None:
    workflow = load(path)
    assert workflow.get("permissions") == {}, f"{path.name} must set top-level 'permissions: {{}}'"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_job_declares_least_privilege_permissions(path: Path) -> None:
    for job_name, job in load(path)["jobs"].items():
        permissions = job.get("permissions")
        assert isinstance(permissions, dict), f"{path.name}:{job_name} must declare explicit permissions"
        for scope, level in permissions.items():
            assert level in {"read", "none"}, f"{path.name}:{job_name} grants {scope}: {level}"
            assert scope in READ_ONLY_SCOPES, f"{path.name}:{job_name} requests unexpected scope {scope}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkout_never_persists_the_token(path: Path) -> None:
    for job_name, step in steps(load(path)):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, f"{path.name}:{job_name}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_privileged_triggers(path: Path) -> None:
    workflow = load(path)
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    triggers = workflow.get("on", workflow.get(True))
    names = set(triggers) if isinstance(triggers, (list, dict)) else {triggers}
    assert not names & {"pull_request_target", "workflow_run"}, f"{path.name} uses a privileged trigger"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_jobs_have_timeouts(path: Path) -> None:
    for job_name, job in load(path)["jobs"].items():
        assert isinstance(job.get("timeout-minutes"), int), f"{path.name}:{job_name} needs timeout-minutes"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_setup_node_does_not_restore_shared_caches(path: Path) -> None:
    for job_name, step in steps(load(path)):
        if str(step.get("uses", "")).startswith("actions/setup-node@"):
            assert step.get("with", {}).get("package-manager-cache") is False, f"{path.name}:{job_name}"
