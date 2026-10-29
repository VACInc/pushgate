#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "server", ROOT / "sdk"):
    sys.path.insert(0, str(path))

HOST_ALIAS = "10.0.2.2"
DISPOSABLE_ACK = "PUSHGATE_ANDROID_E2E_DISPOSABLE"


class E2EFailure(RuntimeError):
    pass


def load_runtime_dependencies() -> None:
    global PushGateAdminClient, Settings, create_app, httpx, integration_signature, uvicorn

    try:
        import httpx as httpx_module
        import uvicorn as uvicorn_module
        from sdk.pushgate import PushGateAdminClient as admin_client_class
        from server.app.config import Settings as settings_class
        from server.app.main import create_app as create_app_func
        from server.app.security import integration_signature as integration_signature_func
    except ModuleNotFoundError as exc:
        raise E2EFailure(
            "missing Python runtime dependency; run `python -m pip install -e '.[test]'` "
            "from the repo root before the Android E2E smoke"
        ) from exc

    httpx = httpx_module
    uvicorn = uvicorn_module
    PushGateAdminClient = admin_client_class
    Settings = settings_class
    create_app = create_app_func
    integration_signature = integration_signature_func


def log(message: str) -> None:
    print(f"[android-e2e] {message}", flush=True)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])


def compact_json(raw: str) -> str:
    return json.dumps(json.loads(raw), separators=(",", ":"))


def normalized(value: str | None) -> str:
    return " ".join((value or "").split()).casefold()


@dataclass(frozen=True)
class Bounds:
    left: int
    top: int
    right: int
    bottom: int

    @property
    def center(self) -> tuple[int, int]:
        return ((self.left + self.right) // 2, (self.top + self.bottom) // 2)


@dataclass(frozen=True)
class UiNode:
    text: str
    content_desc: str
    class_name: str
    package_name: str
    enabled: bool
    bounds: Bounds | None

    def labels(self) -> tuple[str, ...]:
        return (self.text, self.content_desc)


def parse_bounds(value: str | None) -> Bounds | None:
    if not value:
        return None
    try:
        left_top, right_bottom = value.split("][", 1)
        left, top = left_top.strip("[]").split(",", 1)
        right, bottom = right_bottom.strip("[]").split(",", 1)
        return Bounds(int(left), int(top), int(right), int(bottom))
    except ValueError:
        return None


def parse_ui(xml: str) -> list[UiNode]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise E2EFailure(f"could not parse uiautomator XML: {exc}\n{xml[:1200]}") from exc

    nodes: list[UiNode] = []
    for elem in root.iter("node"):
        attrs = elem.attrib
        nodes.append(
            UiNode(
                text=attrs.get("text", ""),
                content_desc=attrs.get("content-desc", ""),
                class_name=attrs.get("class", ""),
                package_name=attrs.get("package", ""),
                enabled=attrs.get("enabled", "false").casefold() == "true",
                bounds=parse_bounds(attrs.get("bounds")),
            )
        )
    return nodes


def find_text(
    nodes: list[UiNode],
    text: str,
    *,
    exact: bool = True,
    enabled: bool | None = None,
    package_name: str | None = None,
) -> UiNode | None:
    want = normalized(text)
    for node in nodes:
        if package_name is not None and node.package_name != package_name:
            continue
        if enabled is not None and node.enabled != enabled:
            continue
        if not node.bounds:
            continue
        for label in node.labels():
            candidate = normalized(label)
            if (exact and candidate == want) or (not exact and want in candidate):
                return node
    return None


def find_text_containing(nodes: list[UiNode], text: str, *, package_name: str | None = None) -> UiNode | None:
    return find_text(nodes, text, exact=False, package_name=package_name)


def find_edittexts(nodes: list[UiNode]) -> list[UiNode]:
    return [node for node in nodes if node.bounds and node.class_name.endswith("EditText")]


@dataclass(frozen=True)
class DeviceTarget:
    kind: str
    serial: str
    package: str
    activity: str
    apk: Path
    enroll_label: str
    title: str


class AdbDevice:
    def __init__(self, adb_path: Path, target: DeviceTarget):
        self.adb_path = adb_path
        self.target = target
        self._screen_size: tuple[int, int] | None = None

    def adb(
        self,
        *args: str,
        timeout: float = 60.0,
        check: bool = False,
        sensitive: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [str(self.adb_path), "-s", self.target.serial, *args]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode != 0:
            command_detail = "<redacted sensitive adb command>" if sensitive else " ".join(shlex.quote(part) for part in cmd)
            output_detail = "" if sensitive else f"\nstdout:\n{result.stdout[-2000:]}\nstderr:\n{result.stderr[-2000:]}"
            raise E2EFailure(
                f"adb command failed for {self.target.kind}: {command_detail}{output_detail}"
            )
        return result

    def shell(
        self,
        command: str,
        *,
        timeout: float = 60.0,
        check: bool = False,
        sensitive: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return self.adb("shell", command, timeout=timeout, check=check, sensitive=sensitive)

    def ensure_ready(self) -> None:
        self.adb("wait-for-device", timeout=180, check=True)
        if not self.shell(f"pm path {shlex.quote(self.target.package)}", timeout=20).stdout.strip():
            raise E2EFailure(
                f"{self.target.package} is not installed on {self.target.serial}; "
                "run deploy/android-emulator-e2e-smoke.sh so the debug APKs are installed first"
            )

    def prepare_app(self) -> None:
        log(f"{self.target.kind}: clearing app state and logcat")
        self.shell(f"am force-stop {shlex.quote(self.target.package)}", timeout=20)
        self.shell(f"pm clear {shlex.quote(self.target.package)}", timeout=30, check=True)
        self.grant_notifications()
        self.adb("logcat", "-c", timeout=20)

    def grant_notifications(self) -> None:
        self.shell(
            f"pm grant {shlex.quote(self.target.package)} android.permission.POST_NOTIFICATIONS",
            timeout=20,
        )

    def screen_size(self) -> tuple[int, int]:
        if self._screen_size:
            return self._screen_size
        out = self.shell("wm size", timeout=20, check=True).stdout
        for token in out.replace("\r", " ").split():
            if "x" not in token:
                continue
            width, height = token.split("x", 1)
            if width.isdigit() and height.isdigit():
                self._screen_size = (int(width), int(height))
                break
        if not self._screen_size:
            self._screen_size = (1080, 2400)
        return self._screen_size

    def tap(self, node: UiNode) -> None:
        if not node.bounds:
            raise E2EFailure("cannot tap a node without bounds")
        x, y = node.bounds.center
        self.shell(f"input tap {x} {y}", timeout=20, check=True)

    def input_text(self, text: str) -> None:
        self.shell(f"input text {shlex.quote(text)}", timeout=20, check=True)

    def back(self) -> None:
        self.shell("input keyevent 4", timeout=20, check=True)

    def scroll_down(self) -> None:
        width, height = self.screen_size()
        self.shell(
            f"input swipe {width // 2} {int(height * 0.78)} {width // 2} {int(height * 0.22)} 300",
            timeout=20,
            check=True,
        )

    def scroll_up(self) -> None:
        width, height = self.screen_size()
        self.shell(
            f"input swipe {width // 2} {int(height * 0.22)} {width // 2} {int(height * 0.78)} 300",
            timeout=20,
            check=True,
        )

    def dismiss_overlay(self) -> None:
        if self.target.kind == "wear":
            width, height = self.screen_size()
            self.shell("input keyevent 4", timeout=20)
            time.sleep(0.25)
            self.shell(
                f"input swipe {max(10, width // 6)} {height // 2} {int(width * 0.95)} {height // 2} 250",
                timeout=20,
                check=True,
            )
        else:
            self.back()

    def dump_nodes(self) -> tuple[str, list[UiNode]]:
        self.shell("uiautomator dump /sdcard/pushgate-window.xml", timeout=20, check=True)
        xml = self.shell("cat /sdcard/pushgate-window.xml", timeout=20, check=True).stdout
        return xml, parse_ui(xml)

    def tap_text_scroll(
        self,
        label: str,
        *,
        exact: bool = True,
        enabled: bool | None = None,
        timeout: float = 45.0,
    ) -> UiNode:
        deadline = time.monotonic() + timeout
        attempts = 0
        last_xml = ""
        while time.monotonic() < deadline:
            last_xml, nodes = self.dump_nodes()
            node = find_text(nodes, label, exact=exact, enabled=enabled)
            if node and node.bounds:
                _, height = self.screen_size()
                _x, y = node.bounds.center
                if 0 <= y <= height:
                    self.tap(node)
                    return node
            if attempts and attempts % 7 == 0:
                self.scroll_up()
            else:
                self.scroll_down()
            attempts += 1
            time.sleep(0.45)
        raise E2EFailure(f"{self.target.kind}: could not find tappable text {label!r}; last UI:\n{last_xml[:2500]}")

    def launch_with_enrollment_payload(self, payload: str) -> None:
        payload = compact_json(payload)
        component = f"{self.target.package}/{self.target.activity}"
        command = (
            f"am start -S -n {shlex.quote(component)} "
            "-a android.intent.action.SEND -t text/plain "
            f"--es android.intent.extra.TEXT {shlex.quote(payload)}"
        )
        for attempt in range(3):
            result = self.shell(command, timeout=30, check=True, sensitive=True)
            detail = (result.stdout or result.stderr).strip().splitlines()
            if detail:
                suffix = "" if attempt == 0 else f" (retry {attempt})"
                log(f"{self.target.kind}: launch result{suffix}: {detail[-1]}")
            time.sleep(2.0)
            self.tap_optional_text("Allow", exact=True, timeout=2.0)
            if self.ensure_target_visible():
                return
        raise E2EFailure(f"{self.target.kind}: launched but app UI was not visible above system overlays")

    def relaunch_main_activity_after_force_stop(self) -> None:
        component = f"{self.target.package}/{self.target.activity}"
        self.shell(f"am force-stop {shlex.quote(self.target.package)}", timeout=20, check=True)
        time.sleep(1.0)
        result = self.shell(f"am start -n {shlex.quote(component)}", timeout=30, check=True)
        detail = (result.stdout or result.stderr).strip().splitlines()
        if detail:
            log(f"{self.target.kind}: restart launch result: {detail[-1]}")
        time.sleep(3.0)
        self.tap_optional_text("Allow", exact=True, timeout=2.0)
        if not self.ensure_target_visible():
            result = self.shell(f"am start -n {shlex.quote(component)}", timeout=30, check=True)
            detail = (result.stdout or result.stderr).strip().splitlines()
            if detail:
                log(f"{self.target.kind}: restart relaunch result: {detail[-1]}")
            time.sleep(2.0)
            if not self.ensure_target_visible():
                raise E2EFailure(f"{self.target.kind}: relaunched but app UI was not visible above system overlays")

    def tap_optional_text(self, label: str, *, exact: bool = True, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _xml, nodes = self.dump_nodes()
            except E2EFailure:
                time.sleep(0.25)
                continue
            node = find_text(nodes, label, exact=exact, enabled=True)
            if node and node.bounds:
                self.tap(node)
                return True
            time.sleep(0.25)
        return False

    def ensure_target_visible(self, *, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _xml, nodes = self.dump_nodes()
            except E2EFailure:
                time.sleep(0.3)
                continue
            if any(node.package_name == self.target.package for node in nodes):
                return True
            self.dismiss_overlay()
            time.sleep(0.6)
        return False

    def enter_server_url(self, server_url: str) -> None:
        last_xml = ""
        for attempt in range(8):
            last_xml, nodes = self.dump_nodes()
            edittexts = find_edittexts(nodes)
            if edittexts:
                self.tap(edittexts[0])
                time.sleep(0.4)
                self.input_text(server_url)
                time.sleep(0.4)
                self.back()
                time.sleep(0.8)
                return
            if attempt % 2:
                self.scroll_up()
            else:
                self.scroll_down()
            time.sleep(0.4)
        raise E2EFailure(f"{self.target.kind}: no server URL EditText found; last UI:\n{last_xml[:2500]}")

    def wait_for_challenge(self, system_name: str, action_label: str | None, *, timeout: float = 60.0) -> UiNode | None:
        deadline = time.monotonic() + timeout
        challenge_seen = False
        attempts = 0
        last_xml = ""
        while time.monotonic() < deadline:
            last_xml, nodes = self.dump_nodes()
            if find_text_containing(nodes, system_name, package_name=self.target.package):
                challenge_seen = True
            elif find_text_containing(nodes, system_name):
                self.dismiss_overlay()
                time.sleep(0.7)
                continue
            if challenge_seen and action_label:
                node = find_text(nodes, action_label, exact=True, enabled=True, package_name=self.target.package)
                if node and node.bounds:
                    _, height = self.screen_size()
                    _x, y = node.bounds.center
                    if 0 <= y <= height:
                        return node
            elif challenge_seen:
                return None

            if attempts and attempts % 8 == 0:
                self.scroll_up()
            else:
                self.scroll_down()
            attempts += 1
            time.sleep(0.5)

        if action_label:
            raise E2EFailure(
                f"{self.target.kind}: challenge for {system_name!r} did not expose enabled {action_label!r}; "
                f"last UI:\n{last_xml[:2500]}"
            )
        raise E2EFailure(f"{self.target.kind}: challenge for {system_name!r} did not appear; last UI:\n{last_xml[:2500]}")

    def fatal_exception_report(self) -> str | None:
        output = self.adb("logcat", "-d", "-v", "time", timeout=30).stdout
        package_marker = f"Process: {self.target.package}"
        fatal_index = output.find("FATAL EXCEPTION")
        while fatal_index != -1:
            window = output[fatal_index : fatal_index + 3000]
            if package_marker in window or self.target.package in window[:1200]:
                return window
            fatal_index = output.find("FATAL EXCEPTION", fatal_index + 1)
        return None


class PushGateE2EServer:
    def __init__(self, db_path: Path, initial_ttl: int, admin_token: str):
        self.db_path = db_path
        self.port = free_port()
        settings = Settings(
            database_url=f"sqlite:///{db_path}",
            bootstrap_token=admin_token,
            auth_ttl_seconds=initial_ttl,
            push_retry_count=0,
            require_biometric=False,
            global_fail_mode="closed",
            rate_limit_per_minute=2000,
        )
        self.server = uvicorn.Server(uvicorn.Config(create_app(settings), host="0.0.0.0", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def local_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def emulator_url(self) -> str:
        return f"http://{HOST_ALIAS}:{self.port}"

    def __enter__(self) -> "PushGateE2EServer":
        self.thread.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"{self.local_url}/healthz", timeout=0.3).status_code == 200:
                    log(f"server listening on 0.0.0.0:{self.port}; emulators use {self.emulator_url}")
                    return self
            except httpx.HTTPError:
                time.sleep(0.1)
        raise E2EFailure("PushGate server did not become healthy")

    def __exit__(self, *_exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=8)


@dataclass
class IntegrationAuth:
    client_id: str
    secret: str
    client: httpx.Client

    def headers(self, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        return {
            "X-PushGate-Client-Id": self.client_id,
            "X-PushGate-Timestamp": timestamp,
            "X-PushGate-Nonce": nonce,
            "X-PushGate-Signature": integration_signature(self.secret, method, path, body, timestamp, nonce),
        }

    def start_request(self, username: str, system_name: str, pam_service: str = "sshd") -> dict[str, Any]:
        path = "/api/v1/auth/requests"
        payload = {
            "username": username,
            "system": system_name,
            "pam_service": pam_service,
            "source_ip": "203.0.113.42",
            "offline_code": None,
        }
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = self.headers("POST", path, body)
        headers["Content-Type"] = "application/json"
        response = self.client.post(path, content=body, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]
        if data["status"] != "pending":
            raise E2EFailure(f"auth request for {username}/{system_name} was not pending: {data}")
        return data

    def poll_request(self, request_id: str) -> dict[str, Any]:
        path = f"/api/v1/auth/requests/{request_id}"
        response = self.client.get(path, headers=self.headers("GET", path), timeout=10)
        response.raise_for_status()
        return response.json()["data"]


def wait_for(
    description: str,
    predicate: Callable[[], Any],
    *,
    timeout: float,
    interval: float = 0.5,
) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as exc:  # noqa: BLE001 - retained for diagnostic context.
            last_error = exc
        time.sleep(interval)
    if last_error:
        raise E2EFailure(f"timed out waiting for {description}; last error: {last_error}") from last_error
    raise E2EFailure(f"timed out waiting for {description}")


def wait_for_status(auth: IntegrationAuth, request_id: str, expected: str, timeout: float) -> dict[str, Any]:
    last: dict[str, Any] | None = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        last = auth.poll_request(request_id)
        if last["status"] == expected:
            return last
        if last["status"] != "pending":
            raise E2EFailure(f"request {request_id} resolved to {last['status']!r}, expected {expected!r}: {last}")
        time.sleep(0.5)
    raise E2EFailure(f"request {request_id} did not resolve to {expected!r}; last status: {last}")


def assert_valid_device_public_key(device: dict[str, Any]) -> str:
    public_key = device.get("public_key")
    if not public_key:
        raise E2EFailure(f"device {device.get('id')} has no public_key after enrollment")
    key_type = device.get("key_type") or "ed25519"
    try:
        raw = base64.b64decode(public_key, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise E2EFailure(f"device {device.get('id')} public_key is not base64: {public_key!r}") from exc
    if key_type == "ed25519":
        if len(raw) != 32:
            raise E2EFailure(f"device {device.get('id')} public_key decoded to {len(raw)} bytes, expected raw 32-byte Ed25519")
    elif key_type == "ecdsa_p256":
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            key = serialization.load_der_public_key(raw)
        except Exception as exc:  # noqa: BLE001 - preserve exact parser failure in E2E diagnostics.
            raise E2EFailure(f"device {device.get('id')} public_key is not a parseable SPKI DER key") from exc
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise E2EFailure(f"device {device.get('id')} public_key is not a P-256 EC SPKI key")
    else:
        raise E2EFailure(f"device {device.get('id')} enrolled with unsupported key_type {key_type!r}")
    if not device.get("enrolled_at"):
        raise E2EFailure(f"device {device.get('id')} has public_key but no enrolled_at timestamp")
    return key_type


def enroll_device(
    admin: PushGateAdminClient,
    adb_device: AdbDevice,
    username: str,
    run_id: str,
    server_url: str,
) -> dict[str, Any]:
    target = adb_device.target
    user = admin.create_user(username, display_name=f"Android E2E {target.kind}", fail_mode="closed")
    device = admin.create_device(user["id"], f"{target.kind}-emulator-{run_id}", target.kind, require_biometric=False)
    payload = device.get("enrollment_qr_payload")
    if not payload:
        raise E2EFailure(f"server did not return enrollment_qr_payload for {target.kind} device")

    adb_device.prepare_app()
    adb_device.launch_with_enrollment_payload(payload)
    adb_device.enter_server_url(server_url)
    adb_device.tap_text_scroll(target.enroll_label, exact=True, enabled=True, timeout=60)
    log(f"{target.kind}: tapped {target.enroll_label!r}, waiting for server enrollment")

    def enrolled_device() -> dict[str, Any] | None:
        current = admin.get_device(device["id"])
        return current if current.get("public_key") else None

    enrolled = wait_for(
        f"{target.kind} device enrollment",
        enrolled_device,
        timeout=45,
        interval=0.75,
    )
    key_type = assert_valid_device_public_key(enrolled)
    log(f"{target.kind}: enrolled device {device['id']} with {key_type} public key")
    time.sleep(2.5)
    return {"user": user, "device": enrolled}


def run_decision_scenario(
    adb_device: AdbDevice,
    auth: IntegrationAuth,
    username: str,
    run_id: str,
    scenario: str,
    action_label: str,
    expected_status: str,
    status_timeout: float,
) -> dict[str, Any]:
    system_name = f"{adb_device.target.kind}-{scenario}-{run_id}"
    request = auth.start_request(username, system_name)
    request_id = request["id"]
    log(f"{adb_device.target.kind}: {scenario} request {request_id} started")
    action_node = adb_device.wait_for_challenge(system_name, action_label, timeout=60)
    if not action_node:
        raise E2EFailure(f"{adb_device.target.kind}: no {action_label} node returned for {scenario}")
    adb_device.tap(action_node)
    log(f"{adb_device.target.kind}: tapped {action_label} for {request_id}")
    final = wait_for_status(auth, request_id, expected_status, timeout=status_timeout)
    log(f"{adb_device.target.kind}: {scenario} resolved to {final['status']}")
    time.sleep(1.0)
    return final


def assert_same_enrolled_device(before: dict[str, Any], after: dict[str, Any], target: DeviceTarget) -> None:
    if after.get("id") != before.get("id"):
        raise E2EFailure(f"{target.kind}: device id changed after restart: {before.get('id')} -> {after.get('id')}")
    if after.get("public_key") != before.get("public_key"):
        raise E2EFailure(f"{target.kind}: enrolled public key changed after restart")
    if (after.get("key_type") or "ed25519") != (before.get("key_type") or "ed25519"):
        raise E2EFailure(f"{target.kind}: enrolled key_type changed after restart")
    if not after.get("public_key"):
        raise E2EFailure(f"{target.kind}: enrolled public key missing after restart")
    if after.get("enrolled_at") != before.get("enrolled_at"):
        raise E2EFailure(f"{target.kind}: enrolled_at changed after restart, indicating a re-enroll")


def run_restart_persistence_scenario(
    admin: PushGateAdminClient,
    adb_device: AdbDevice,
    auth: IntegrationAuth,
    username: str,
    run_id: str,
    enrolled_device: dict[str, Any],
    approve_ttl: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target = adb_device.target
    log(f"{target.kind}: force-stopping and relaunching without enrollment payload to prove persistence")
    adb_device.relaunch_main_activity_after_force_stop()

    after_restart = admin.get_device(enrolled_device["id"])
    assert_same_enrolled_device(enrolled_device, after_restart, target)

    approved = run_decision_scenario(
        adb_device,
        auth,
        username,
        run_id,
        "restart-approve",
        "Approve",
        "approved",
        status_timeout=approve_ttl,
    )

    after_approval = admin.get_device(enrolled_device["id"])
    assert_same_enrolled_device(enrolled_device, after_approval, target)
    log(f"{target.kind}: restart persistence kept device {enrolled_device['id']} and public key stable")
    return approved, after_approval


def run_timeout_scenario(
    admin: PushGateAdminClient,
    adb_device: AdbDevice,
    auth: IntegrationAuth,
    username: str,
    run_id: str,
    timeout_ttl: int,
) -> dict[str, Any]:
    admin.update_global_settings(auth_ttl_seconds=timeout_ttl, push_retry_count=0, require_biometric=False)
    system_name = f"{adb_device.target.kind}-timeout-{run_id}"
    request = auth.start_request(username, system_name)
    request_id = request["id"]
    log(f"{adb_device.target.kind}: timeout request {request_id} started with auth_ttl_seconds={timeout_ttl}; leaving it unanswered")
    try:
        adb_device.wait_for_challenge(system_name, None, timeout=min(4.0, max(1.0, timeout_ttl - 1.0)))
        log(f"{adb_device.target.kind}: timeout challenge appeared in app")
    except E2EFailure:
        log(f"{adb_device.target.kind}: timeout challenge was not observed before TTL; status polling will still prove expiry")
    final = wait_for_status(auth, request_id, "timeout", timeout=timeout_ttl + 12)
    log(f"{adb_device.target.kind}: timeout resolved to {final['status']}")
    return final


def run_target(
    admin: PushGateAdminClient,
    adb_device: AdbDevice,
    auth: IntegrationAuth,
    run_id: str,
    server_url: str,
    approve_ttl: int,
    timeout_ttl: int,
) -> dict[str, Any]:
    target = adb_device.target
    adb_device.ensure_ready()
    username = f"android-e2e-{target.kind}-{run_id}"
    enrolled = enroll_device(admin, adb_device, username, run_id, server_url)

    admin.update_global_settings(auth_ttl_seconds=approve_ttl, push_retry_count=0, require_biometric=False)
    restart_approved, persisted_device = run_restart_persistence_scenario(
        admin,
        adb_device,
        auth,
        username,
        run_id,
        enrolled["device"],
        approve_ttl,
    )
    admin.update_global_settings(auth_ttl_seconds=approve_ttl, push_retry_count=0, require_biometric=False)
    denied = run_decision_scenario(
        adb_device,
        auth,
        username,
        run_id,
        "deny",
        "Deny",
        "denied",
        status_timeout=approve_ttl,
    )
    timed_out = run_timeout_scenario(admin, adb_device, auth, username, run_id, timeout_ttl)

    crash = adb_device.fatal_exception_report()
    if crash:
        raise E2EFailure(f"{target.kind}: app logged a fatal exception:\n{crash[:3000]}")

    return {
        "kind": target.kind,
        "serial": target.serial,
        "user_id": enrolled["user"]["id"],
        "device_id": enrolled["device"]["id"],
        "key_type": enrolled["device"].get("key_type") or "ed25519",
        "approved_request_id": restart_approved["id"],
        "restart_approved_request_id": restart_approved["id"],
        "restart_device_id": persisted_device["id"],
        "denied_request_id": denied["id"],
        "timeout_request_id": timed_out["id"],
    }


def target_from_args(args: argparse.Namespace, kind: str) -> DeviceTarget:
    if kind == "phone":
        return DeviceTarget(
            kind="phone",
            serial=args.phone_serial,
            package="org.pushgate.phone",
            activity=".MainActivity",
            apk=Path(args.phone_apk),
            enroll_label="Enroll",
            title="PushGate",
        )
    return DeviceTarget(
        kind="wear",
        serial=args.wear_serial,
        package="org.pushgate.wear",
        activity="org.pushgate.wear.MainActivity",
        apk=Path(args.wear_apk),
        enroll_label="Enroll watch",
        title="PushGate",
    )


def validate_emulator_serial(serial: str) -> None:
    if not re.fullmatch(r"emulator-[0-9]+", serial):
        raise E2EFailure(f"refusing Android E2E mutation on non-emulator serial: {serial}")


def reserve_new_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise E2EFailure(f"refusing to reuse existing Android E2E database path: {path}") from None
    except OSError as exc:
        raise E2EFailure(f"cannot securely create Android E2E database: {exc.__class__.__name__}") from None
    else:
        os.close(descriptor)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run PushGate Android phone and Wear OS end-to-end emulator push MFA smoke tests.")
    default_adb = os.environ.get("PUSHGATE_ADB") or os.environ.get("ADB") or "adb"
    parser.add_argument("--adb", default=default_adb, help="adb executable path")
    parser.add_argument(
        "--phone-serial",
        default=os.environ.get("PUSHGATE_PHONE_SERIAL") or "emulator-5554",
    )
    parser.add_argument(
        "--wear-serial",
        default=os.environ.get("PUSHGATE_WEAR_SERIAL") or "emulator-5556",
    )
    parser.add_argument(
        "--phone-apk",
        default=os.environ.get("PUSHGATE_PHONE_APK")
        or str(ROOT / "dist/apks/pushgate-phone-debug.apk"),
    )
    parser.add_argument(
        "--wear-apk",
        default=os.environ.get("PUSHGATE_WEAR_APK")
        or str(ROOT / "dist/apks/pushgate-wear-debug.apk"),
    )
    parser.add_argument(
        "--approve-ttl",
        type=int,
        default=int(os.environ.get("PUSHGATE_E2E_APPROVE_TTL") or "45"),
    )
    parser.add_argument(
        "--timeout-ttl",
        type=int,
        default=int(os.environ.get("PUSHGATE_E2E_TIMEOUT_TTL") or "5"),
    )
    parser.add_argument(
        "--db-path",
        default=os.environ.get("PUSHGATE_E2E_DB_PATH"),
    )
    parser.add_argument(
        "--only",
        choices=("phone", "wear", "both"),
        default=os.environ.get("PUSHGATE_E2E_ONLY") or "both",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.environ.get(DISPOSABLE_ACK) != "1":
        raise E2EFailure(
            "Android E2E refuses to clear app state without the guarded emulator wrapper"
        )
    approve_ttl = max(10, args.approve_ttl)
    timeout_ttl = max(5, args.timeout_ttl)
    adb_path = Path(args.adb)
    run_id = secrets.token_hex(4)
    admin_token = secrets.token_urlsafe(32)

    selected = ["phone", "wear"] if args.only == "both" else [args.only]
    targets = [target_from_args(args, kind) for kind in selected]
    for target in targets:
        validate_emulator_serial(target.serial)
    if len({target.serial for target in targets}) != len(targets):
        raise E2EFailure("phone and Wear emulator serials must be distinct")
    for target in targets:
        if not target.apk.exists():
            raise E2EFailure(f"expected APK does not exist: {target.apk}")
    load_runtime_dependencies()

    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    if args.db_path:
        db_path = Path(args.db_path)
    else:
        temp_dir = tempfile.TemporaryDirectory(prefix="pushgate-android-e2e-")
        db_path = Path(temp_dir.name) / "pushgate.db"
    reserve_new_database(db_path)

    try:
        with PushGateE2EServer(db_path, approve_ttl, admin_token) as server:
            admin = PushGateAdminClient(server.local_url, admin_token)
            try:
                integration = admin.create_integration(
                    f"Android emulator E2E {run_id}",
                    client_id=f"android-e2e-{run_id}",
                    fail_mode="closed",
                )
                signed = IntegrationAuth(
                    client_id=integration["client_id"],
                    secret=integration["secret"],
                    client=httpx.Client(base_url=server.local_url, timeout=10),
                )
                try:
                    results = [
                        run_target(
                            admin,
                            AdbDevice(adb_path, target),
                            signed,
                            run_id,
                            server.emulator_url,
                            approve_ttl,
                            timeout_ttl,
                        )
                        for target in targets
                    ]
                finally:
                    signed.client.close()
            finally:
                admin.close()
    finally:
        if temp_dir:
            temp_dir.cleanup()

    print("RESULT_JSON:" + json.dumps({"run_id": run_id, "results": results}, sort_keys=True))
    log("Android emulator E2E push MFA checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except E2EFailure as exc:
        print(f"[android-e2e] FAIL: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(2) from exc
