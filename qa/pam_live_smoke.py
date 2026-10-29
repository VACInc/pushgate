from __future__ import annotations

import base64
import os
import pty
import select
import shlex
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdk.pushgate import PushGateAdminClient
from server.app.config import Settings
from server.app.main import create_app


ADMIN_TOKEN = "pushgate-pam-live-admin-0123456789"
TEST_PASSWORD = "CorrectHorseBatteryStaple1!"
PUSHGATE_CONFIG_DIR = Path("/etc/pushgate")
PUSHGATE_CACHE_DIR = PUSHGATE_CONFIG_DIR / "failmode.d"
PUSHGATE_CONFIG_FILE = PUSHGATE_CONFIG_DIR / "pushgate.env"
PUSHGATE_PAM_LAUNCHER = Path("/usr/local/libexec/pushgate_pam")
PUSHGATE_PAM_HELPER = ROOT / "pam" / "pushgate_pam.py"
SSHD_PAM_FILE = Path("/etc/pam.d/sshd")
LIMA_CIDATA_DIR = Path("/mnt/lima-cidata")
LIMA_BOOT_MARKER = Path("/run/lima-boot-done")
DISPOSABLE_ACK = "PUSHGATE_PAM_SMOKE_DISPOSABLE"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(db_path: Path):
    port = free_port()
    app = create_app(Settings(database_url=f"sqlite:///{db_path}", bootstrap_token=ADMIN_TOKEN, auth_ttl_seconds=8))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            if httpx.get(f"{base_url}/healthz", timeout=0.2).status_code == 200:
                return server, thread, base_url
        except httpx.HTTPError:
            time.sleep(0.05)
    raise RuntimeError("server did not start")


def stop_server(server, thread: threading.Thread) -> None:
    server.should_exit = True
    thread.join(timeout=5)


def device_keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, base64.b64encode(public_key).decode()


def sign_decision(device: dict, request_id: str, decision: str, biometric_verified: bool) -> str:
    message = f"{request_id}.{decision}.{str(biometric_verified).lower()}".encode("utf-8")
    return base64.b64encode(device["private_key"].sign(message)).decode()


def decide(base_url: str, request_id: str, device: dict, decision: str, biometric_verified: bool = True) -> None:
    response = httpx.post(
        f"{base_url}/api/v1/auth/requests/{request_id}/decision",
        json={
            "device_id": device["id"],
            "decision": decision,
            "biometric_verified": biometric_verified,
            "signature": sign_decision(device, request_id, decision, biometric_verified),
        },
        timeout=5,
    )
    response.raise_for_status()


def wait_pending(admin: PushGateAdminClient, username: str, service: str) -> str:
    for _ in range(80):
        terminal_ids = set()
        for row in admin.auth_logs(user=username, limit=50):
            if row["status"] != "pending":
                terminal_ids.add(row["id"])
                continue
            if row["id"] in terminal_ids:
                continue
            if row["pam_service"] == service and row["status"] == "pending":
                return row["id"]
        time.sleep(0.1)
    raise AssertionError(f"no pending request for {username}/{service}")


def write_config(server_url: str, integration: dict) -> None:
    PUSHGATE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PUSHGATE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for directory in (PUSHGATE_CONFIG_DIR, PUSHGATE_CACHE_DIR):
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o700)

    payload = (
        "\n".join(
            [
                f"PUSHGATE_SERVER={server_url}",
                f"PUSHGATE_CLIENT_ID={integration['client_id']}",
                f"PUSHGATE_CLIENT_SECRET={integration['secret']}",
                f"PUSHGATE_CACHE_DIR={PUSHGATE_CACHE_DIR}",
                "PUSHGATE_TIMEOUT=6",
                "PUSHGATE_CACHE_MAX_AGE=300",
                "",
            ]
        )
    ).encode("utf-8")
    descriptor = os.open(
        PUSHGATE_CONFIG_FILE,
        os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    config_metadata = os.lstat(PUSHGATE_CONFIG_FILE)
    cache_metadata = os.lstat(PUSHGATE_CACHE_DIR)
    if config_metadata.st_uid != 0 or config_metadata.st_mode & 0o777 != 0o600:
        raise PermissionError("PushGate PAM config must be root-owned with mode 0600")
    if cache_metadata.st_uid != 0 or cache_metadata.st_mode & 0o777 != 0o700:
        raise PermissionError("PushGate PAM cache must be root-owned with mode 0700")


def write_pam_launcher() -> None:
    PUSHGATE_PAM_LAUNCHER.parent.mkdir(parents=True, exist_ok=True)
    os.chown(PUSHGATE_PAM_LAUNCHER.parent, 0, 0)
    launcher = "\n".join(
        [
            "#!/bin/sh",
            "exec /usr/bin/env -i \\",
            "  PUSHGATE_PAM_LAUNCHER=1 \\",
            '  PAM_USER="${PAM_USER-}" \\',
            '  PAM_SERVICE="${PAM_SERVICE-}" \\',
            '  PAM_RHOST="${PAM_RHOST-}" \\',
            '  PAM_RUSER="${PAM_RUSER-}" \\',
            '  PAM_TTY="${PAM_TTY-}" \\',
            '  PAM_TYPE="${PAM_TYPE-}" \\',
            f"  {shlex.quote(sys.executable)} -I {shlex.quote(str(PUSHGATE_PAM_HELPER))} \"$@\"",
            "",
        ]
    )
    PUSHGATE_PAM_LAUNCHER.write_text(launcher, encoding="utf-8")
    os.chown(PUSHGATE_PAM_LAUNCHER, 0, 0)
    os.chmod(PUSHGATE_PAM_LAUNCHER, 0o755)


def write_pam_services() -> None:
    write_pam_launcher()
    for service in ("sshd", "sudo", "login", "cache-prime"):
        Path(f"/etc/pam.d/pushgate-{service}").write_text(
            "\n".join(
                [
                    pam_line(service).rstrip("\n"),
                    "account required pam_permit.so",
                    "",
                ]
            ),
            encoding="utf-8",
        )


def pam_line(service: str) -> str:
    return f"auth required pam_exec.so expose_authtok seteuid {PUSHGATE_PAM_LAUNCHER} --service {service}\n"


def install_pam_line(path: Path, service: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    filtered = [line for line in lines if "pushgate_pam" not in line]
    filtered.append(pam_line(service).rstrip("\n"))
    path.write_text("\n".join(filtered) + "\n", encoding="utf-8")


def pam_start(service: str, username: str, stdin: str | None = None) -> subprocess.Popen:
    return subprocess.Popen(
        ["pamtester", f"pushgate-{service}", username, "authenticate"],
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def wait_pam(proc: subprocess.Popen, expected: int, label: str, stdin: str | None = None) -> None:
    stdout, stderr = proc.communicate(stdin, timeout=12)
    if proc.returncode != expected:
        raise AssertionError(f"{label} returned {proc.returncode}, expected {expected}\nstdout={stdout}\nstderr={stderr}")


def assert_blocked(proc: subprocess.Popen, label: str) -> None:
    time.sleep(0.2)
    if proc.poll() is not None:
        stdout, stderr = proc.communicate(timeout=1)
        raise AssertionError(f"{label} completed before approval/denial\nstdout={stdout}\nstderr={stderr}")


def run_pam_decision(admin: PushGateAdminClient, base_url: str, service: str, username: str, device: dict, decision: str, expected: int) -> None:
    proc = pam_start(service, username)
    try:
        request_id = wait_pending(admin, username, service)
        assert_blocked(proc, f"pamtester {service}")
        decide(base_url, request_id, device, decision, biometric_verified=decision == "approve")
        wait_pam(proc, expected, f"{service} {decision}")
    finally:
        stop_process(proc)


def prime_principal_bound_cache(admin: PushGateAdminClient, base_url: str, username: str, device: dict) -> dict:
    client_id = f"pam-live-offline-{username}"
    integration = admin.create_integration(
        client_id,
        client_id=client_id,
        fail_mode="closed",
        principal_username=username,
    )
    write_config(base_url, integration)
    run_pam_decision(admin, base_url, "cache-prime", username, device, "approve", 0)
    return integration


def run_offline_outage_checks(base_url: str, open_integration: dict, closed_integration: dict, backup_code: str) -> None:
    write_config(base_url, open_integration)
    wait_pam(pam_start("cache-prime", "openuser"), 0, "offline fail-open")

    write_config(base_url, closed_integration)
    wait_pam(pam_start("cache-prime", "closeduser"), 1, "offline fail-closed")
    wait_pam(pam_start("login", "closeduser", stdin=backup_code + "\n"), 0, "offline backup code", stdin=backup_code + "\n")


def create_device(admin: PushGateAdminClient, user_id: str, name: str, kind: str, require_biometric: bool = False) -> dict:
    private_key, public_key = device_keypair()
    device = admin.create_device(user_id, name, kind, require_biometric=require_biometric, public_key=public_key)
    device["private_key"] = private_key
    return device


def is_disposable_runtime() -> bool:
    if os.environ.get(DISPOSABLE_ACK) != "1":
        return False
    in_container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    in_lima = (
        os.path.ismount(LIMA_CIDATA_DIR)
        and (LIMA_CIDATA_DIR / "lima.env").is_file()
        and LIMA_BOOT_MARKER.is_file()
    )
    return in_container or in_lima


def require_disposable_context() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("live PAM smoke must run as root inside a disposable container or Lima VM")
    if not is_disposable_runtime():
        raise RuntimeError("live PAM smoke refuses to modify host PAM configuration; run it in a disposable container or the guarded Lima wrapper")
    if not shutil.which("pamtester"):
        raise RuntimeError("pamtester is required")


def require_real_service_tools() -> None:
    for command in ("login", "sshd", "ssh", "sshpass", "sudo", "runuser", "useradd", "chpasswd", "ssh-keygen"):
        if not shutil.which(command):
            raise RuntimeError(f"{command} is required for live service smoke")


def ensure_os_user(username: str) -> None:
    subprocess.run(["useradd", "-m", "-s", "/bin/sh", username], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["chpasswd"], input=f"{username}:{TEST_PASSWORD}\n", text=True, check=True)


def sshd_pam_stack() -> str:
    return "\n".join(
        [
            "auth required pam_unix.so",
            pam_line("sshd").rstrip("\n"),
            "account required pam_permit.so",
            "session required pam_permit.so",
            "",
        ]
    )


def sshd_config(port: int) -> str:
    return (
        "\n".join(
            [
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                "UsePAM yes",
                "AuthenticationMethods password",
                "PasswordAuthentication yes",
                "PermitEmptyPasswords no",
                "KbdInteractiveAuthentication no",
                "PubkeyAuthentication no",
                "PermitRootLogin no",
                "ChallengeResponseAuthentication no",
                "PidFile /tmp/pushgate-sshd.pid",
                "LogLevel ERROR",
                "",
            ]
        )
    )


def configure_sshd() -> tuple[subprocess.Popen, int]:
    Path("/run/sshd").mkdir(parents=True, exist_ok=True)
    subprocess.run(["ssh-keygen", "-A"], check=True, stdout=subprocess.DEVNULL)
    SSHD_PAM_FILE.write_text(sshd_pam_stack(), encoding="utf-8")
    port = free_port()
    config = Path("/tmp/pushgate-sshd_config")
    config.write_text(sshd_config(port), encoding="utf-8")
    subprocess.run(["/usr/sbin/sshd", "-t", "-f", str(config)], check=True)
    proc = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return proc, port
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=1)
            raise AssertionError(f"sshd exited early\nstdout={stdout}\nstderr={stderr}")
        time.sleep(0.05)
    proc.terminate()
    raise AssertionError("sshd did not start")


def stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def ssh_start(port: int, username: str, command: str = "true") -> subprocess.Popen:
    return subprocess.Popen(
        [
            "sshpass",
            "-p",
            TEST_PASSWORD,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-p",
            str(port),
            f"{username}@127.0.0.1",
            command,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_ssh_decision(admin: PushGateAdminClient, base_url: str, port: int, username: str, device: dict, decision: str, expected: int) -> None:
    proc = ssh_start(port, username)
    try:
        request_id = wait_pending(admin, username, "sshd")
        assert_blocked(proc, "real sshd login")
        decide(base_url, request_id, device, decision, biometric_verified=decision == "approve")
        wait_pam(proc, expected, f"sshd {decision}")
    finally:
        stop_process(proc)


def configure_sudo(username: str) -> None:
    install_pam_line(Path("/etc/pam.d/sudo"), "sudo")
    sudoers = Path("/etc/sudoers.d/pushgate-smoke")
    sudoers.write_text(f"Defaults:{username} lecture=never\n{username} ALL=(ALL) ALL\n", encoding="utf-8")
    os.chmod(sudoers, 0o440)


def sudo_start(username: str) -> subprocess.Popen:
    command = f"sudo -K && printf '%s\\n' '{TEST_PASSWORD}' | sudo -S -p '' true"
    return subprocess.Popen(
        ["runuser", "-u", username, "--", "sh", "-lc", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_sudo_decision(admin: PushGateAdminClient, base_url: str, username: str, device: dict, decision: str, expected: int) -> None:
    proc = sudo_start(username)
    try:
        request_id = wait_pending(admin, username, "sudo")
        assert_blocked(proc, "real sudo")
        decide(base_url, request_id, device, decision, biometric_verified=decision == "approve")
        wait_pam(proc, expected, f"sudo {decision}")
    finally:
        stop_process(proc)


class PtyLogin:
    def __init__(self) -> None:
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(["/bin/login"], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        os.close(slave)
        self.buffer = b""

    def read_until(self, patterns: tuple[bytes, ...], timeout: float = 8.0) -> bytes:
        deadline = time.time() + timeout
        lower_patterns = tuple(pattern.lower() for pattern in patterns)
        while time.time() < deadline:
            if any(pattern in self.buffer.lower() for pattern in lower_patterns):
                return self.buffer
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(self.master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                self.buffer += chunk
        raise AssertionError(f"timed out waiting for {patterns!r}; output={self.buffer[-800:]!r}")

    def write(self, value: str) -> None:
        os.write(self.master, value.encode("utf-8"))

    def close(self) -> None:
        try:
            os.close(self.master)
        except OSError:
            pass
        stop_process(self.proc)


def configure_login() -> None:
    install_pam_line(Path("/etc/pam.d/login"), "login")


def login_start(username: str) -> PtyLogin:
    session = PtyLogin()
    session.read_until((b"login:",))
    session.write(username + "\n")
    session.read_until((b"password:",))
    session.write(TEST_PASSWORD + "\n")
    return session


def run_login_decision(admin: PushGateAdminClient, base_url: str, username: str, device: dict, decision: str) -> None:
    session = login_start(username)
    try:
        request_id = wait_pending(admin, username, "login")
        assert_blocked(session.proc, "real console login")
        decide(base_url, request_id, device, decision, biometric_verified=decision == "approve")
        if decision == "approve":
            session.read_until((b"$ ", b"# "))
            session.write("exit\n")
            session.proc.wait(timeout=8)
            if session.proc.returncode != 0:
                raise AssertionError(f"login shell exited with {session.proc.returncode}; output={session.buffer[-800:]!r}")
        else:
            session.read_until((b"login incorrect", b"login:"))
            if b"$ " in session.buffer or b"# " in session.buffer:
                raise AssertionError(f"denied login reached a shell; output={session.buffer[-800:]!r}")
    finally:
        session.close()


def main() -> int:
    require_disposable_context()
    require_real_service_tools()
    write_pam_services()
    with tempfile.TemporaryDirectory() as tmp:
        server, thread, base_url = start_server(Path(tmp) / "pushgate.db")
        admin = PushGateAdminClient(base_url, ADMIN_TOKEN)
        try:
            integration = admin.create_integration("pam-live-linux", client_id="pam-live-linux", fail_mode="closed")
            write_config(base_url, integration)

            alice = admin.create_user("alice", fail_mode="closed")
            phone = create_device(admin, alice["id"], "Pixel", "phone", require_biometric=True)
            wear = create_device(admin, alice["id"], "Pixel Watch", "wear")
            ensure_os_user("alice")

            run_pam_decision(admin, base_url, "sshd", "alice", phone, "approve", 0)
            run_pam_decision(admin, base_url, "sudo", "alice", phone, "deny", 1)
            run_pam_decision(admin, base_url, "login", "alice", wear, "approve", 0)
            sshd_proc, sshd_port = configure_sshd()
            try:
                run_ssh_decision(admin, base_url, sshd_port, "alice", phone, "approve", 0)
            finally:
                stop_process(sshd_proc)
            configure_sudo("alice")
            run_sudo_decision(admin, base_url, "alice", phone, "approve", 0)
            run_sudo_decision(admin, base_url, "alice", phone, "deny", 1)
            configure_login()
            run_login_decision(admin, base_url, "alice", wear, "approve")
            run_login_decision(admin, base_url, "alice", phone, "deny")

            open_user = admin.create_user("openuser", fail_mode="open")
            closed_user = admin.create_user("closeduser", fail_mode="closed")
            open_phone = create_device(admin, open_user["id"], "Open Phone", "phone")
            closed_phone = create_device(admin, closed_user["id"], "Closed Phone", "phone")
            backup_code = admin.create_backup_codes(closed_user["id"], count=1)["codes"][0]

            run_pam_decision(admin, base_url, "cache-prime", "openuser", open_phone, "approve", 0)
            closed_integration = prime_principal_bound_cache(admin, base_url, "closeduser", closed_phone)
        finally:
            admin.close()
            stop_server(server, thread)

        run_offline_outage_checks(base_url, integration, closed_integration, backup_code)

    print("Live PAM smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
