#!/usr/bin/env python3
"""Single entry point for JOES Threat Intelligence.

Brings the whole tree up from a bare clone: provisions the two virtualenvs
(the Flask app and Scriba's PDF renderer), seeds config from the checked-in
examples, then hands off to the app.

Runs on the system interpreter with only the standard library, so it works
before any dependency is installed.

    python start.py                 # provision if needed, then serve
    python start.py --setup-only    # provision and exit
    python start.py --reinstall     # force dependency reinstall
    python start.py --port 8080     # override the listen port
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 10)

ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "EmergingJoes"
SCRIBA_DIR = ROOT / "scriba"

# (label, project dir, venv dir) — Scriba keeps the dotted name its own
# tooling expects; advisory_generator.py resolves it by that path.
VENVS = [
    ("app", APP_DIR, APP_DIR / "venv"),
    ("scriba", SCRIBA_DIR, SCRIBA_DIR / ".venv"),
]


def info(msg: str) -> None:
    print(f"  {msg}", flush=True)


def step(msg: str) -> None:
    print(f"\n>> {msg}", flush=True)


def fail(msg: str) -> "None":
    print(f"\nERROR: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def venv_python(venv: Path) -> Path:
    """Interpreter path inside a venv, for either platform layout."""
    candidates = [venv / "Scripts" / "python.exe", venv / "bin" / "python"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0] if os.name == "nt" else candidates[1]


def run(cmd: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run([str(part) for part in cmd], cwd=str(cwd) if cwd else None)
    if result.returncode != 0:
        fail(f"command failed ({result.returncode}): {' '.join(str(p) for p in cmd)}")


def check_python() -> None:
    if sys.version_info < MIN_PYTHON:
        fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required, "
            f"found {sys.version.split()[0]}"
        )
    info(f"Python {sys.version.split()[0]}")


def provision_venv(label: str, project: Path, venv: Path, reinstall: bool) -> None:
    requirements = project / "requirements.txt"
    if not requirements.exists():
        fail(f"missing {requirements}")

    python = venv_python(venv)
    created = False

    if not python.exists():
        info(f"creating {label} virtualenv at {venv.relative_to(ROOT)}")
        run([sys.executable, "-m", "venv", str(venv)])
        python = venv_python(venv)
        created = True
        if not python.exists():
            fail(f"virtualenv creation did not produce an interpreter at {python}")

    # A stamp of the requirements file lets repeat launches skip pip entirely.
    stamp = venv / ".requirements-stamp"
    current = requirements.read_bytes()
    up_to_date = stamp.exists() and stamp.read_bytes() == current

    if up_to_date and not reinstall and not created:
        info(f"{label} dependencies already up to date")
        return

    info(f"installing {label} dependencies (this can take a few minutes)")
    run([python, "-m", "pip", "install", "--upgrade", "pip", "--quiet"])
    run([python, "-m", "pip", "install", "-r", str(requirements), "--quiet"])
    stamp.write_bytes(current)
    info(f"{label} dependencies installed")


def seed_from_example(target: Path, example: Path, description: str) -> None:
    if target.exists():
        info(f"{description} present")
        return
    if not example.exists():
        info(f"no example for {description}, skipping")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(example, target)
    info(f"created {description} from {example.name}")


def seed_config() -> None:
    seed_from_example(APP_DIR / ".env", APP_DIR / ".env.example", ".env")
    seed_from_example(
        APP_DIR / "data" / "config.json",
        APP_DIR / "data" / "config.json.example",
        "data/config.json",
    )


def serve(host: str | None, port: str | None) -> int:
    """Hand off to the app.

    Only explicit overrides are injected: left alone, app.py resolves HOST and
    PORT from EmergingJoes/.env and falls back to a free port.
    """
    python = venv_python(APP_DIR / "venv")
    env = dict(os.environ)
    if host:
        env["HOST"] = host
    if port:
        env["PORT"] = port

    target = f"{host or env.get('HOST', '127.0.0.1')}:{port}" if port else (host or "the configured address")
    print(f"\nStarting JOES Threat Intelligence on {target}", flush=True)
    print("(the app logs its final URL below)\n", flush=True)

    try:
        return subprocess.call([str(python), "app.py"], cwd=str(APP_DIR), env=env)
    except KeyboardInterrupt:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="start.py",
        description="Provision and launch JOES Threat Intelligence.",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="provision virtualenvs and config, then exit without serving",
    )
    parser.add_argument(
        "--reinstall",
        action="store_true",
        help="reinstall dependencies even if they look current",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="bind address (default: HOST from EmergingJoes/.env, else 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        default=None,
        help="listen port (default: PORT from EmergingJoes/.env, else a free port)",
    )
    parser.add_argument(
        "--skip-scriba",
        action="store_true",
        help="skip the Scriba virtualenv; advisory PDF generation will not work",
    )
    args = parser.parse_args()

    print("JOES Threat Intelligence - startup")

    step("Checking interpreter")
    check_python()

    step("Provisioning environments")
    for label, project, venv in VENVS:
        if label == "scriba" and args.skip_scriba:
            info("skipping scriba virtualenv (--skip-scriba)")
            continue
        if not project.exists():
            fail(f"missing project directory {project}")
        provision_venv(label, project, venv, args.reinstall)

    step("Seeding configuration")
    seed_config()

    if args.setup_only:
        print("\nSetup complete. Run 'python start.py' to launch.", flush=True)
        return 0

    step("Starting application")
    return serve(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
