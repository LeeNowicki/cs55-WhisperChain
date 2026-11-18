"""Helpers shared by demo.py and tamper_demo.py.

They drive the REAL programs: `python -m whisperchain.server` runs as a
subprocess with TLS, and every user action is a real CLI command
(`python -m whisperchain.client ...`), each user with its own --config-dir.
Secrets come from WC_DEMO_* environment variables (demo mode only).
"""

import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
DEMO_PASSWORD = "demo-account-password"     # used by every demo account
DEMO_PASSPHRASE = "demo-key-passphrase"     # must differ from the password
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def demo_env() -> dict:
    """A copy of our environment variables, plus the demo-mode settings."""
    env = dict(os.environ)
    env["WC_DEMO_MODE"] = "1"
    env["WC_DEMO_PASSWORD"] = DEMO_PASSWORD
    env["WC_DEMO_PASSPHRASE"] = DEMO_PASSPHRASE
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def banner(text: str) -> None:
    line = "=" * 78  # a line of 78 "=" characters
    print()
    print(line)
    print("  " + text)
    print(line, flush=True)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DemoServer:
    """init + init-admin + run, in a private data directory."""

    def __init__(self, base_dir: Path, admin_username: str = "admin"):
        self.data_dir = base_dir / "server_data"
        self.port = free_port()
        self.url = f"https://localhost:{self.port}"
        self.cert = self.data_dir / "tls" / "cert.pem"
        self.db = self.data_dir / "whisperchain.db"
        self.admin_username = admin_username
        self.process = None

    def _server_cmd(self, arguments: list[str]) -> list[str]:
        """The full command line for `python -m whisperchain.server ... <arguments>`."""
        command = [sys.executable, "-m", "whisperchain.server", "--data-dir", str(self.data_dir)]
        for argument in arguments:
            command.append(argument)
        return command

    def setup_and_start(self) -> None:
        print(f"$ python -m whisperchain.server --data-dir {self.data_dir} init")
        subprocess.run(self._server_cmd(["init"]), check=True, env=demo_env(), cwd=REPO)
        print(f"$ python -m whisperchain.server --data-dir {self.data_dir} init-admin")
        # The username is typed on stdin; the password comes from WC_DEMO_PASSWORD.
        subprocess.run(self._server_cmd(["init-admin"]), input=self.admin_username + "\n", text=True,
                       check=True, env=demo_env(), cwd=REPO)
        print(f"\n$ python -m whisperchain.server --data-dir {self.data_dir} run --port {self.port} &")
        self.process = subprocess.Popen(self._server_cmd(["run", "--port", str(self.port)]),
                                        env=demo_env(), cwd=REPO, stdout=subprocess.DEVNULL)
        self._wait_until_healthy()

    def _wait_until_healthy(self, timeout: float = 20.0) -> None:
        context = ssl.create_default_context(cafile=str(self.cert))  # pinned, like the CLI
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("server exited during startup")
            try:
                if httpx.get(f"{self.url}/health", verify=context, timeout=2).status_code == 200:
                    print(f"(server is up at {self.url}, TLS certificate pinned)")
                    return
            except httpx.TransportError:
                time.sleep(0.3)
        raise RuntimeError("server did not become healthy in time")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()


class DemoUser:
    """One CLI user = one config directory."""

    def __init__(self, base_dir: Path, name: str, server: DemoServer):
        self.name = name
        self.config_dir = base_dir / "clients" / name
        self.server = server

    def run(self, arguments: list[str], expect_failure: bool = False, quiet: bool = False) -> str:
        """Run `python -m whisperchain.client <arguments>` as this user.

        Prints the command and its output (indented), and returns the output.
        Raises RuntimeError if the command failed when it should have
        worked, or worked when it should have failed.
        """
        # Show the command the way you would type it in a shell.
        quoted = []
        for argument in arguments:
            quoted.append(shlex.quote(argument))
        shown = " ".join(quoted)
        print(f"\n[{self.name}]$ whisperchain {shown}", flush=True)

        command = [sys.executable, "-m", "whisperchain.client", "--config-dir", str(self.config_dir)]
        for argument in arguments:
            command.append(argument)
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                env=demo_env(), cwd=REPO)

        output = (result.stdout + result.stderr).rstrip()
        if not quiet:
            for line in output.splitlines():
                print("    " + line)

        failed = (result.returncode != 0)
        if failed and not expect_failure:
            raise RuntimeError(f"unexpected failure of: {shown}")
        if expect_failure and not failed:
            raise RuntimeError(f"unexpected success of: {shown}")
        return output

    def setup(self, admin: "DemoUser", roles: list[str]) -> None:
        """configure, get an invite from the admin, register, log in."""
        self.run(["configure", "--server", self.server.url, "--ca-cert", str(self.server.cert)], quiet=True)
        invite_command = ["admin", "invite"]
        for role in roles:
            invite_command.append("--role")
            invite_command.append(role)
        output = admin.run(invite_command)
        # The invite code is on the second line of the output.
        code = output.splitlines()[1].strip()
        self.run(["register", "--invite", code, "--username", self.name])
        self.run(["login"])
