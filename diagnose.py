# -*- coding: utf-8 -*-
"""
=============================================================
  CYBER THREAT INTELLIGENCE PLATFORM - Auto Diagnostic Tool
=============================================================
Run this script anytime to get a full health report of your
local development environment.

Usage:
    python diagnose.py
    python diagnose.py --fix        # auto-install missing packages
    python diagnose.py --docker     # also check running containers
=============================================================
"""
import io
sys_stdout_reconfigured = False

import sys
import os
import subprocess
import importlib
import socket
import argparse
from pathlib import Path

# Force UTF-8 output on Windows to handle all characters safely
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# ── ANSI color codes ──────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

OK   = f"{GREEN}[OK]{RESET}"
FAIL = f"{RED}[FAIL]{RESET}"
WARN = f"{YELLOW}[WARN]{RESET}"
INFO = f"{CYAN}[INFO]{RESET}"

ROOT = Path(__file__).parent

# ── All services and their requirements ──────────────────────────────────────
SERVICES = {
    "backend": {
        "path": ROOT / "services" / "backend",
        "requirements": ROOT / "services" / "backend" / "requirements.txt",
        "key_modules": [
            ("fastapi",           "fastapi"),
            ("jose",              "python-jose[cryptography]"),
            ("passlib",           "passlib[bcrypt]"),
            ("pydantic_settings", "pydantic-settings"),
            ("pydantic",          "pydantic"),
            ("sqlalchemy",        "sqlalchemy"),
            ("asyncpg",           "asyncpg"),
            ("alembic",           "alembic"),
            ("elasticsearch",     "elasticsearch"),
            ("confluent_kafka",   "confluent-kafka"),
            ("httpx",             "httpx"),
            ("dotenv",            "python-dotenv"),
            ("multipart",         "python-multipart"),
            ("email_validator",   "email-validator"),
        ],
    },
    "ml-engine": {
        "path": ROOT / "services" / "ml-engine",
        "requirements": ROOT / "services" / "ml-engine" / "requirements.txt",
        "key_modules": [
            ("sklearn",         "scikit-learn"),
            ("xgboost",         "xgboost"),
            ("numpy",           "numpy"),
            ("pandas",          "pandas"),
            ("joblib",          "joblib"),
            ("confluent_kafka",  "confluent-kafka"),
            ("fastapi",         "fastapi"),
            ("httpx",           "httpx"),
            ("elasticsearch",   "elasticsearch"),
            ("sqlalchemy",      "sqlalchemy"),
            ("dotenv",          "python-dotenv"),
        ],
    },
    "ingestion": {
        "path": ROOT / "services" / "ingestion",
        "requirements": ROOT / "services" / "ingestion" / "requirements.txt",
        "key_modules": [
            ("confluent_kafka", "confluent-kafka"),
            ("faker",           "faker"),
            ("requests",        "requests"),
            ("dotenv",          "python-dotenv"),
        ],
    },
}

# ── Docker services and their ports ──────────────────────────────────────────
DOCKER_SERVICES = {
    "PostgreSQL":      ("localhost", 5432),
    "Kafka":           ("localhost", 9092),
    "Elasticsearch":   ("localhost", 9200),
    "Backend API":     ("localhost", 8000),
    "ML Engine":       ("localhost", 8001),
    "Frontend":        ("localhost", 3000),
    "Kafka UI":        ("localhost", 8090),
}

# ── ENV keys expected in .env ─────────────────────────────────────────────────
REQUIRED_ENV_KEYS = [
    "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
    "JWT_SECRET_KEY", "JWT_ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES", "REFRESH_TOKEN_EXPIRE_DAYS",
    "ELASTICSEARCH_URL", "KAFKA_BOOTSTRAP_SERVERS",
    "ADMIN_EMAIL", "ADMIN_PASSWORD",
]

INSECURE_VALUES = {
    "JWT_SECRET_KEY": ["change-this-to-a-secure-random-256-bit-key", "change-this-in-production", "super-secret-jwt-key-change-in-production"],
    "POSTGRES_PASSWORD": ["cti_secure_pass_change_me"],
    "ADMIN_PASSWORD": ["Admin@CTI2024!"],
}

issues_found = []

# ─────────────────────────────────────────────────────────────────────────────

def header(title):
    width = 60
    print(f"\n{BOLD}{CYAN}{'-' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'-' * width}{RESET}")


def check(label, ok, detail="", fix_hint=""):
    status = OK if ok else FAIL
    label_padded = label.ljust(45)
    print(f"  {status}  {label_padded} {DIM}{detail}{RESET}")
    if not ok:
        issues_found.append((label, fix_hint or detail))


def warn(label, detail="", fix_hint=""):
    label_padded = label.ljust(45)
    print(f"  {WARN}  {label_padded} {DIM}{detail}{RESET}")
    if fix_hint:
        issues_found.append((f"[WARN] {label}", fix_hint))


# ── 1. Python version ─────────────────────────────────────────────────────────

def check_python():
    header("Python Environment")
    v = sys.version_info
    ok = v.major == 3 and v.minor >= 10
    check(f"Python {v.major}.{v.minor}.{v.micro}",
          ok, "" if ok else "Python 3.10+ required",
          "Download from https://python.org/downloads")

    venv_active = sys.prefix != sys.base_prefix
    venv_exists = (ROOT / ".venv").exists()
    if venv_active:
        check("Virtual environment active", True, sys.prefix)
    elif venv_exists:
        warn("Virtual environment exists but NOT active",
             str(ROOT / ".venv"),
             "Run: .venv\\Scripts\\Activate.ps1")
    else:
        warn("No virtual environment found",
             "Running in global Python environment",
             "Run: python -m venv .venv && .venv\\Scripts\\Activate.ps1")


# ── 2. Per-service package checks ────────────────────────────────────────────

def check_packages(fix_mode=False):
    header("Python Package Availability")
    missing_by_service = {}

    for svc_name, svc in SERVICES.items():
        print(f"\n  {BOLD}[{svc_name}]{RESET}")
        missing = []
        for module, pkg in svc["key_modules"]:
            try:
                importlib.import_module(module)
                check(f"  {pkg}", True)
            except ImportError:
                check(f"  {pkg}", False, "NOT INSTALLED",
                      f"pip install \"{pkg}\"")
                missing.append(pkg)

        if missing:
            missing_by_service[svc_name] = missing

    if fix_mode and missing_by_service:
        header("Auto-Fix: Installing Missing Packages")
        for svc_name, pkgs in missing_by_service.items():
            req_file = SERVICES[svc_name]["requirements"]
            print(f"\n  Installing from {req_file.name} for [{svc_name}]...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"  {OK}  [{svc_name}] packages installed successfully")
            else:
                print(f"  {FAIL}  [{svc_name}] install failed:")
                print(f"  {DIM}{result.stderr[-500:]}{RESET}")


# ── 3. .env file checks ───────────────────────────────────────────────────────

def check_env():
    header(".env Configuration")
    env_file = ROOT / ".env"
    example_file = ROOT / ".env.example"

    if not env_file.exists():
        check(".env file exists", False,
              "Missing — copy from .env.example",
              f"Run: copy {example_file} {env_file}")
        return

    check(".env file exists", True)

    # Parse .env
    env_vars = {}
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env_vars[k.strip()] = v.strip()

    # Check required keys
    for key in REQUIRED_ENV_KEYS:
        present = key in env_vars and env_vars[key] != ""
        check(f"  {key}", present,
              "" if present else "Missing or empty",
              f"Add '{key}=<value>' to your .env file")

    # Warn on insecure defaults
    print()
    for key, bad_vals in INSECURE_VALUES.items():
        if key in env_vars and env_vars[key] in bad_vals:
            warn(f"  {key} uses insecure default",
                 env_vars[key],
                 f"Replace {key} with a secure value in .env")

    # Check .env vs .env.example drift
    if example_file.exists():
        example_vars = set()
        with open(example_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    example_vars.add(line.partition("=")[0].strip())
        missing_from_env = example_vars - set(env_vars.keys())
        for k in sorted(missing_from_env):
            warn(f"  {k} in .env.example but missing from .env",
                 fix_hint=f"Add '{k}' to your .env file")


# ── 4. Source file syntax checks ─────────────────────────────────────────────

def check_syntax():
    header("Python Source File Syntax")
    py_dirs = [
        ROOT / "services" / "backend",
        ROOT / "services" / "ingestion",
    ]
    any_file = False
    for d in py_dirs:
        for py_file in sorted(d.rglob("*.py")):
            any_file = True
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(py_file)],
                capture_output=True, text=True
            )
            rel = py_file.relative_to(ROOT)
            ok = result.returncode == 0
            check(str(rel), ok,
                  "" if ok else result.stderr.strip().split("\n")[-1],
                  f"Fix syntax error in {rel}")
    if not any_file:
        print(f"  {INFO}  No Python files found in checked directories")


# ── 5. Key file existence checks ─────────────────────────────────────────────

def check_structure():
    header("Project File Structure")
    expected_files = [
        ROOT / "docker-compose.yml",
        ROOT / ".env.example",
        ROOT / "services" / "backend" / "main.py",
        ROOT / "services" / "backend" / "requirements.txt",
        ROOT / "services" / "backend" / "core" / "config.py",
        ROOT / "services" / "backend" / "core" / "security.py",
        ROOT / "services" / "backend" / "core" / "database.py",
        ROOT / "services" / "backend" / "Dockerfile",
        ROOT / "services" / "ml-engine" / "requirements.txt",
        ROOT / "services" / "ml-engine" / "Dockerfile",
        ROOT / "services" / "ingestion" / "requirements.txt",
        ROOT / "services" / "ingestion" / "Dockerfile",
    ]
    for f in expected_files:
        rel = f.relative_to(ROOT)
        check(str(rel), f.exists(),
              "" if f.exists() else "MISSING",
              f"Create or restore {rel}")


# ── 6. Network / Docker port checks ──────────────────────────────────────────

def check_ports():
    header("Docker Service Ports (localhost)")
    for name, (host, port) in DOCKER_SERVICES.items():
        try:
            with socket.create_connection((host, port), timeout=1):
                check(f"{name} :{port}", True, "reachable")
        except (ConnectionRefusedError, OSError):
            warn(f"{name} :{port}", "not reachable",
                 "Run: docker compose up -d")


# ── 7. Docker containers ──────────────────────────────────────────────────────

def check_docker_containers():
    header("Docker Container Status")
    result = subprocess.run(
        ["docker", "compose", "ps", "--format", "table {{.Name}}\t{{.Status}}\t{{.Ports}}"],
        capture_output=True, text=True, cwd=ROOT
    )
    if result.returncode != 0:
        check("docker compose available", False,
              result.stderr.strip() or "docker not found",
              "Install Docker Desktop: https://docs.docker.com/desktop/windows/")
        return

    lines = result.stdout.strip().split("\n")
    if len(lines) <= 1:
        warn("No containers running", fix_hint="Run: docker compose up -d")
        return

    for line in lines[1:]:  # skip header
        parts = line.split("\t")
        if len(parts) >= 2:
            name   = parts[0].strip()
            status = parts[1].strip()
            ok     = "Up" in status or "running" in status.lower()
            check(name, ok, status,
                  f"docker compose restart {name}")


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary():
    header("DIAGNOSTIC SUMMARY")
    if not issues_found:
        print(f"\n  {GREEN}{BOLD}All checks passed! Your environment looks healthy.{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}Found {len(issues_found)} issue(s):{RESET}\n")
        for i, (label, hint) in enumerate(issues_found, 1):
            print(f"  {i:2}. {RED}{label}{RESET}")
            if hint:
                print(f"      {DIM}Fix: {hint}{RESET}")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTI Platform Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--fix",    action="store_true", help="Auto-install missing Python packages")
    parser.add_argument("--docker", action="store_true", help="Also check running Docker containers")
    args = parser.parse_args()

    # Enable ANSI colors on Windows
    os.system("")

    print(f"\n{BOLD}{CYAN}{'=' * 60}")
    print("  CTI PLATFORM - AUTO DIAGNOSTIC TOOL")
    print(f"{'=' * 60}{RESET}")
    print(f"  Project root : {ROOT}")
    print(f"  Python       : {sys.executable}")
    print(f"  Version      : {sys.version.split()[0]}")

    check_python()
    check_structure()
    check_env()
    check_packages(fix_mode=args.fix)
    check_syntax()

    if args.docker:
        check_docker_containers()
    else:
        check_ports()
        print(f"\n  {DIM}Tip: Run with --docker to check container status via docker compose{RESET}")

    print_summary()


if __name__ == "__main__":
    main()
