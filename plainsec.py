#!/usr/bin/env python3
"""plainsec - plain-English security reports for code projects.

Runs the scanners you have installed and rewrites what they find as a short
report a beginner can act on:
    bandit       risky patterns in Python code
    gitleaks     leaked keys and passwords, including old git commits
    osv-scanner  known vulnerabilities in every dependency file (any language)
    pip-audit    fallback for requirements.txt when osv-scanner isn't installed
    cargo        tells Rust crates used only by tests apart from shipped ones
A missing scanner is reported as NOT CHECKED, never as an all-clear.

Usage:
    python plainsec.py ~/my-project                # scan a folder
    python plainsec.py ~/my-project --out report.md   # also save the report
    python plainsec.py ~/my-project --all          # include skipped / test-file findings
    python plainsec.py ~/my-project --no-save      # don't update "since last scan"

Skipping old drafts or copies: put a `.plainsec` file in the project folder,
one path per line (folders end with /, # starts a comment), e.g.

    # old experiments, not used any more
    old/
    drafts/
    *_backup.py

Skipped findings are still COUNTED in the report (and HIGH ones are called
out), so nothing disappears silently. Secrets are never skipped.
"""

import fnmatch

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Plain-English explanations for common bandit checks.
# Each entry: (what it means, how to fix it). Unknown IDs fall back to
# bandit's own text, so the report never silently drops a finding.
# ---------------------------------------------------------------------------
BANDIT_PLAIN = {
    "B101": ("An `assert` is used as a safety check. Python skips asserts when "
             "run with -O, so the check can vanish.",
             "Use `if not ...: raise ValueError(...)` for checks that matter."),
    "B102": ("`exec()` runs any text as code, with full access to your files. "
             "`exec(code, {})` is NOT a sandbox. If the text comes from a user, "
             "a file or an AI model, it can do anything you can.",
             "If you don't need it: use normal function calls or a lookup dict. "
             "If running generated code is the point (an agent tool): ask before "
             "running, or run it in a separate process/folder with no access to "
             "your keys."),
    "B103": ("A file is given loose permissions (chmod), so other users or apps "
             "on the device may be able to read or change it.",
             "Use 0o600 for private files, 0o700 for private scripts/folders."),
    "B105": ("A password or secret looks hard-coded in the source. Anyone who "
             "sees the file (or the git history) sees the secret.",
             "Load it from keyring or an environment variable instead."),
    "B106": ("A password is passed as a literal string to a function.",
             "Load it from keyring or an environment variable instead."),
    "B107": ("A function has a default password value.",
             "Remove the default; require the caller to supply it."),
    "B108": ("A fixed temp-file path (like /tmp/x) is used. Another program can "
             "create or swap that file first.",
             "Use `tempfile.NamedTemporaryFile()` or `tempfile.mkdtemp()`."),
    "B110": ("`except: pass` hides every error, so real failures go unnoticed.",
             "Catch the specific exception and at least log it."),
    "B112": ("`except: continue` hides every error inside a loop.",
             "Catch the specific exception and log it before continuing."),
    "B113": ("A web request has no timeout, so it can hang forever.",
             "Add `timeout=10` (or similar) to the requests call."),
    "B201": ("A Flask app runs with debug=True, which lets visitors run code.",
             "Turn debug off outside your own machine."),
    "B301": ("`pickle` loading can run code hidden in the file.",
             "Only unpickle files you created; prefer JSON for data."),
    "B303": ("MD5 or SHA1 is used. They are broken for security purposes.",
             "Use `hashlib.sha256()`; fine to ignore if it's just a checksum."),
    "B307": ("`eval()` runs text as code. Same danger as exec().",
             "Use `ast.literal_eval()` for data, or parse it yourself. If "
             "evaluating generated code is the point, see the B102 advice."),
    "B311": ("`random` is predictable. Fine for games, unsafe for tokens, "
             "passwords or anything secret.",
             "Use the `secrets` module for anything security-related."),
    "B324": ("A weak hash (MD5/SHA1) is used.",
             "Use `hashlib.sha256()`, or pass `usedforsecurity=False` if it's "
             "only a checksum."),
    "B404": ("The `subprocess` module is imported. Not a bug by itself; it's a "
             "reminder that running commands needs care.",
             "Usually safe to whitelist if inputs are fixed strings."),
    "B501": ("A request turns off SSL checks (verify=False). Someone on the "
             "network could read or change the traffic.",
             "Remove `verify=False`."),
    "B506": ("`yaml.load()` can build arbitrary Python objects from a file.",
             "Use `yaml.safe_load()`."),
    "B602": ("A command runs with shell=True. If any part comes from input, "
             "it can be hijacked into running other commands.",
             "If the command is fixed and only a value changes: pass a list "
             "(`['ls', path]`) and drop shell=True. If the whole command comes "
             "from a user or an AI model (an agent tool), a list won't help: "
             "ask before running, or only allow a fixed set of programs. "
             "Blocking 'bad' words like 'rm -rf /' is easy to slip past."),
    "B603": ("A command runs without a shell. Low risk; flagged so you check "
             "the inputs are trusted.",
             "Safe if the command list is built from fixed strings."),
    "B605": ("A command is started through the shell (os.system etc.).",
             "Use `subprocess.run([...])` with a list instead."),
    "B607": ("A program is started by name only (e.g. 'git'), so whichever "
             "'git' is first on PATH gets run.",
             "Usually fine on your own device; use a full path if worried."),
    "B608": ("SQL is built by gluing strings together. That's how SQL "
             "injection happens.",
             "Use placeholders: `cur.execute('... WHERE id = ?', (id,))`."),
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Checks that are normal inside test files: pytest is built on assert, and
# tests use fake passwords, temp paths and subprocess on purpose.
NORMAL_IN_TESTS = {"B101", "B105", "B106", "B107", "B108", "B404", "B603"}

# Packages you should NOT upgrade with pip itself on some systems.
SELF_UPGRADE_NOTE = {
    # Termux: upgrading pip with pip can break the setup; use the system package.
    "pip": ("Don't upgrade pip with pip on Termux (it can break your setup). "
            "Run `pkg upgrade python-pip`, then `pip --version`; if it's still below "
            "the fixed version, Termux hasn't packaged the fix yet, so check again later."),
}

MAX_LINES_SHOWN = 8


# ---------------------------------------------------------------------------
# Running the scanners
# ---------------------------------------------------------------------------
def run_tool(cmd):
    """Run a scanner and return its parsed JSON, or (None, error text).

    bandit and pip-audit both exit with code 1 when they FIND problems,
    so a non-zero exit is not a failure here. Only missing/invalid JSON is.
    """
    if shutil.which(cmd[0]) is None:
        return None, missing_tool(cmd[0])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)  # list form, no shell
    except OSError as e:
        return None, f"{cmd[0]} couldn't run ({e.strerror or e})"
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        err = (proc.stderr or proc.stdout).strip().splitlines()
        return None, err[-1] if err else f"{cmd[0]} gave no output"


def scan_code(folder):
    # bandit's -x matches by substring of the path, so build/dist are written
    # with slashes (plain "build" would also skip a file like rebuild.py).
    # build/ is where `pip install .` copies your code; scanning it doubled
    # every finding in plainsec's own Action run.
    cmd = ["bandit", "-r", str(folder), "-f", "json", "-q",
           "-x", ".venv,venv,.git,node_modules,/build/,/dist/,.egg-info"]
    cfg = Path(folder) / "bandit.yaml"
    if cfg.exists():
        cmd += ["-c", str(cfg)]
    return run_tool(cmd)


NO_REQS = ("no requirements.txt at the top of this folder, so your dependencies "
           "weren't checked. Best fix: install osv-scanner, which finds dependency "
           "files anywhere in the project (any language). " )


def no_reqs_message():
    return (NO_REQS + install_hint("osv-scanner") +
            " Or make a requirements.txt with `pip freeze > requirements.txt` inside the "
            "project's venv. (Adding `--audit-env` to the plainsec command checks the "
            "Python that pip-audit runs in instead, which may not be your project's.)")


def on_termux():
    return "com.termux" in os.environ.get("PREFIX", "")


INSTALL = {
    # tool: (what it's for, Ubuntu/Debian command, Termux command)
    "gitleaks": ("finds leaked keys and passwords, including in old commits",
                 "sudo apt install gitleaks",
                 "pkg install golang && go install github.com/zricethezav/gitleaks/v8@latest"),
    "osv-scanner": ("checks every dependency file for known vulnerabilities",
                    "download it from github.com/google/osv-scanner/releases",
                    "pkg install golang && GOTOOLCHAIN=local go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0"),
    "bandit": ("checks your Python code for risky patterns",
               "pipx install bandit", "pip install bandit"),
    "pip-audit": ("checks requirements.txt for known vulnerabilities",
                  "pipx install pip-audit", "pip install pip-audit"),
}


def install_hint(tool):
    if tool not in INSTALL:
        return ""
    _, ubuntu, termux = INSTALL[tool]
    how = termux if on_termux() else ubuntu
    extra = (" (Go programs are built on the phone, which takes a few minutes; they end "
             "up in `~/go/bin`, so add `export PATH=\"$HOME/go/bin:$PATH\"` to ~/.bashrc)"
             if on_termux() and "go install" in how else "")
    return f"To install: `{how}`{extra}."


def missing_tool(tool):
    what = INSTALL.get(tool, ("", "", ""))[0]
    return f"{tool} is not installed" + (f" ({tool} {what})" if what else "") + ". " + install_hint(tool)


def scan_deps(folder, audit_env=False):
    """Audit the project's requirements.txt.

    Without one, pip-audit would check whatever Python IT runs in (with pipx
    that's pip-audit's own private venv), which says nothing about the project.
    So we refuse instead of giving a false all-clear, unless --audit-env asks
    for exactly that."""
    req = Path(folder) / "requirements.txt"
    cmd = ["pip-audit", "-f", "json", "--progress-spinner", "off"]
    if req.exists():
        cmd += ["-r", str(req)]
    elif not audit_env:
        return None, no_reqs_message()
    return run_tool(cmd)


def scan_deps_osv(folder):
    """osv-scanner v2: every dependency file in the project (requirements*.txt,
    pyproject/poetry/uv locks, Cargo.lock, package-lock.json, go.mod, ...).
    Exit 0 = clean, 1 = vulnerabilities, 128 = no dependency files at all."""
    # Options BEFORE the folder: older osv-scanner (seen with 2.0.0 on Termux)
    # stops reading options at the first path and took "--format" as a folder.
    cmd = ["osv-scanner", "scan", "source", "--format", "json", "-r", str(folder)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)  # list form, no shell
    except OSError as e:
        return None, f"osv-scanner couldn't run ({e.strerror or e})"
    if proc.returncode == 128:
        # Don't trust "none found" blindly: on Termux, osv-scanner 2.4.0 walks
        # from / , can't read it, and reports nothing for a repo full of files.
        ours = find_dep_files(folder, limit=50)
        if not ours:
            return {"results": [], "no_sources": True}, None
        usable = [f for f in ours if lockfile_ok(f)]
        rest = [f for f in ours if not lockfile_ok(f)]
        if not usable and all(Path(f).name == "pyproject.toml" for f in rest):
            declared = {f: pyproject_dependencies(Path(folder) / f) for f in rest}
            if all(d == [] for d in declared.values()):
                # e.g. a package with no dependencies: really nothing to check
                return {"results": [], "no_sources": True,
                        "no_deps_declared": rest}, None
            with_deps = [f for f, d in declared.items() if d != []]
            return None, (", ".join(with_deps) + " lists dependencies but there's no lock "
                          "file, and osv-scanner checks lock files (exact versions). Make one "
                          "(`uv lock`, `poetry lock`, or `pip freeze > requirements.txt` inside "
                          "the project's venv) and run plainsec again.")
        if usable:
            # Route that worked on Termux: hand osv-scanner each file with -L.
            cmd = ["osv-scanner", "scan", "source", "--format", "json"]
            for f in usable:
                cmd += ["-L", str(Path(folder) / f)]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)  # list form
            except OSError as e:
                return None, f"osv-scanner couldn't run ({e.strerror or e})"
            if proc.returncode in (0, 1):
                try:
                    data = json.loads(proc.stdout)
                except ValueError:
                    data = None
                if data is not None:
                    data["file_by_file"] = usable
                    data["not_checked_files"] = [f for f in ours if f not in usable]
                    return data, None
        return None, ("osv-scanner said it found no dependency files, but these exist: "
                      + ", ".join(ours[:5]) + (", …" if len(ours) > 5 else "")
                      + ". It probably couldn't read the folder (seen on Termux/Android). "
                      "Treat dependencies as unchecked.")
    try:
        return json.loads(proc.stdout), None
    except ValueError:
        err = (proc.stderr or proc.stdout).strip().splitlines()
        return None, err[-1] if err else f"osv-scanner exited with {proc.returncode}"


DEP_FILE_NAMES = {"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
                  "uv.lock", "Cargo.lock", "package-lock.json", "yarn.lock",
                  "pnpm-lock.yaml", "go.mod", "Gemfile.lock", "composer.lock"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "target", "__pycache__", ".tox"}


# Files osv-scanner reliably accepts one by one with -L (pyproject.toml left
# out: one unsupported file makes the whole run fail).
LOCKFILE_NAMES = {"Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                  "poetry.lock", "Pipfile.lock", "go.mod", "Gemfile.lock", "composer.lock"}


def lockfile_ok(rel):
    name = Path(rel).name
    return name in LOCKFILE_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def pyproject_dependencies(path):
    """Declared runtime dependencies in a pyproject.toml ([project] and Poetry).
    None if it can't be read (treated as 'has dependencies' to stay safe)."""
    try:
        import tomllib
    except ImportError:
        return None
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    deps = list((data.get("project") or {}).get("dependencies") or [])
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    deps += [k for k in poetry if k.lower() != "python"]
    return deps


def find_dep_files(folder, limit=20):
    """Our own quick look for common dependency files (used to double-check
    an osv-scanner 'none found'). Returns relative paths, at most `limit`."""
    found = []
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in DEP_FILE_NAMES or (name.startswith("requirements") and name.endswith(".txt")):
                found.append(str(Path(dirpath, name).relative_to(folder)))
                if len(found) >= limit:
                    return found
    return found


def vkey(version):
    """Rough version order across ecosystems: 1.10 > 1.9, 2.0rc1 < 2.0."""
    parts = re.findall(r"\d+|[A-Za-z]+", str(version))
    return tuple((1, int(x)) if x.isdigit() else (0, x.lower()) for x in parts) + ((1, -1),)


def sev_label(score):
    try:
        x = float(score)
    except (TypeError, ValueError):
        return "NO SCORE"
    return ("CRITICAL" if x >= 9 else "HIGH" if x >= 7 else
            "MEDIUM" if x >= 4 else "LOW")


DEP_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NO SCORE": 4, "": 5}
ECOSYSTEM_NAME = {"PyPI": "Python", "crates.io": "Rust", "npm": "Node",
                  "Go": "Go", "RubyGems": "Ruby", "Maven": "Java", "Packagist": "PHP"}


def _first_fix(vulns, name, current):
    """Smallest fixed version above the current one, for this package."""
    fixed = []
    for v in vulns:
        for a in v.get("affected", []):
            if (a.get("package") or {}).get("name", "").lower() != name.lower():
                continue
            for r in a.get("ranges", []):
                fixed += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    above = [f for f in fixed if vkey(f) > vkey(current)]
    return min(above, key=vkey) if above else None


UNMAINTAINED_WORDS = re.compile(r"\bunmaintained\b|no longer maintained|is not maintained",
                                re.IGNORECASE)


def _informational_kind(v):
    """RustSec informational advisories: 'unsound', 'unmaintained', 'notice'...
    The marker lives in each affected[].database_specific in real data; top
    level is checked too. Summary wording is a backstop for 'unmaintained',
    only when the advisory has no fixed version. Returns "" if not informational."""
    places = [v.get("database_specific") or {}]
    places += [a.get("database_specific") or {} for a in v.get("affected", [])]
    for p in places:
        if p.get("informational"):
            return str(p["informational"]).lower()
    has_fix = any("fixed" in e for a in v.get("affected", [])
                  for r in a.get("ranges", []) for e in r.get("events", []))
    if not has_fix and UNMAINTAINED_WORDS.search(v.get("summary") or ""):
        return "unmaintained"
    return ""


def _is_informational(v):
    return bool(_informational_kind(v))


def _label(ids, aliases):
    allids = list(ids) + list(aliases)
    for prefix in ("CVE-", "GHSA-", "RUSTSEC-", "PYSEC-"):
        for i in allids:
            if i.startswith(prefix):
                return i
    return allids[0] if allids else "?"


def parse_osv(data, root=None):
    """-> (risky, notices). One entry per package per dependency file.
    OSV lists one problem under several IDs (GHSA, CVE, PYSEC); `groups`
    bundles them, so we count groups. Rust 'unmaintained' notices are
    informational, not vulnerabilities, so they're kept apart."""
    risky, notices = [], []
    for res in (data or {}).get("results", []) or []:
        src = (res.get("source") or {}).get("path", "?")
        if root:
            try:
                src = str(Path(src).resolve().relative_to(Path(root).resolve()))
            except ValueError:
                pass
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package") or {}
            name, version, eco = p.get("name", "?"), p.get("version", "?"), p.get("ecosystem", "?")
            by_id = {v.get("id"): v for v in pkg.get("vulnerabilities", []) or []}
            groups = pkg.get("groups") or [
                {"ids": [i], "aliases": v.get("aliases", []), "max_severity": ""}
                for i, v in by_id.items()]
            real, info = [], []
            for g in groups:
                vs = [by_id[i] for i in g.get("ids", []) if i in by_id]
                entry = {
                    "label": _label(g.get("ids", []), g.get("aliases", [])),
                    "severity": sev_label(g.get("max_severity")),
                    "fix": _first_fix(vs, name, version),
                    "summary": next((first_sentence(v.get("summary") or v.get("details") or "")
                                     for v in vs if v.get("summary") or v.get("details")), ""),
                }
                kind = next((k for k in map(_informational_kind, vs) if k), "")
                entry["kind"] = kind
                (info if kind else real).append(entry)
            base = {"name": name, "version": version, "ecosystem": eco, "source": src}
            if real:
                real.sort(key=lambda e: DEP_SEV_ORDER.get(e["severity"], 9))
                fixes = [e["fix"] for e in real if e["fix"]]
                risky.append(dict(base,
                    ids=[e["label"] for e in real],
                    severity=real[0]["severity"],
                    summary=real[0]["summary"],
                    fix_to=max(fixes, key=vkey) if fixes else None,
                    no_fix=[e["label"] for e in real if not e["fix"]]))
            for e in info:
                notices.append(dict(base, ids=[e["label"]], summary=e["summary"],
                                    kind=e["kind"], fix_to=e["fix"], no_fix=[]))
    risky.sort(key=lambda d: (d["source"], DEP_SEV_ORDER.get(d["severity"], 9), d["name"]))
    return risky, notices


def ship_order(items):
    """Within a file: crates that ship first, test-only last (stable otherwise)."""
    return sorted(items, key=lambda d: d.get("ships") is False)


def is_prerelease(v):
    return bool(re.search(r"[A-Za-z]", str(v).split("+")[0]))


def stable_of(v):
    """'1.0.0-alpha.1' -> '1.0.0'."""
    return re.split(r"[-+]|(?<=\d)(?=[A-Za-z])", str(v), maxsplit=1)[0]


def fix_text(v):
    if is_prerelease(v):
        return f"{stable_of(v)} or later (first fixed in pre-release {v})"
    return f"{v} or later"


def semver_compatible(current, target):
    """Would `cargo update` reach target without a Cargo.toml change?
    Cargo's rule: same major (>=1), or same minor for 0.x."""
    a = [int(x) for x in re.findall(r"\d+", stable_of(current))[:2]] + [0, 0]
    b = [int(x) for x in re.findall(r"\d+", stable_of(target))[:2]] + [0, 0]
    return a[0] == b[0] if a[0] > 0 else (b[0] == 0 and a[1] == b[1])


def cargo_direct_deps(root, source):
    """Names listed in any Cargo.toml next to / under the Cargo.lock
    (workspace members included, target/ skipped)."""
    base = (Path(root) / source).parent if root else Path(source).parent
    names = set()
    try:
        import tomllib
    except ImportError:          # Python < 3.11
        tomllib = None
    for toml in base.rglob("Cargo.toml"):
        if "target" in toml.relative_to(base).parts:
            continue
        try:
            text = toml.read_text(encoding="utf-8")
        except OSError:
            continue
        if tomllib:
            try:
                data = tomllib.loads(text)
            except ValueError:
                continue
            tables = [data, data.get("workspace", {})]
            tables += list((data.get("target") or {}).values())
            for t in tables:
                for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                    names.update((t.get(key) or {}).keys())
        else:
            names.update(re.findall(r"^\s*([A-Za-z0-9_-]+)\s*=", text, re.MULTILINE))
    return {n.replace("_", "-").lower() for n in names}


def cargo_shipping(root, source):
    """Set of (name, version) that are built WITHOUT dev-dependencies, from
    `cargo tree -e no-dev` run next to the Cargo.lock. None if cargo is missing
    or fails (then nothing is labelled)."""
    if shutil.which("cargo") is None:
        return None
    folder = (Path(root) / source).parent if root else Path(source).parent
    cmd = ["cargo", "tree", "-e", "no-dev", "--target", "all", "--prefix", "none",
           "--format", "{p}", "--locked"]
    try:
        proc = subprocess.run(cmd, cwd=folder, capture_output=True, text=True,
                              timeout=180)  # list form, no shell
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    ship = set()
    for line in proc.stdout.splitlines():
        m = re.match(r"\s*(\S+) v(\S+)", line)       # "borsh v0.10.4 (*)"
        if m:
            ship.add((m.group(1).replace("_", "-").lower(), m.group(2)))
    return ship


def cargo_via(root, source, name, version, direct, ships=None):
    """Which crates from YOUR Cargo.toml pull in name@version. Real case:
    `cargo tree -i borsh@0.10.4` printed 846 lines; the answer a beginner
    needs is one name (solana-program). Shipping crates are traced without
    dev-dependencies, so the answer is the crate that puts it in the program.
    Returns a sorted list, or None if cargo is missing or fails."""
    if shutil.which("cargo") is None or not direct:
        return None
    folder = (Path(root) / source).parent if root else Path(source).parent
    cmd = ["cargo", "tree", "-i", f"{name}@{version}", "--target", "all",
           "--prefix", "none", "--format", "{p}", "--locked"]
    if ships:
        cmd[3:3] = ["-e", "no-dev"]
    try:
        proc = subprocess.run(cmd, cwd=folder, capture_output=True, text=True,
                              timeout=120)  # list form, no shell
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    me = name.replace("_", "-").lower()
    found = set()
    for line in proc.stdout.splitlines():
        m = re.match(r"\s*(\S+) v\S+", line)
        if m:
            n = m.group(1).replace("_", "-").lower()
            if n != me and n in direct:
                found.add(n)
    return sorted(found)


def dep_how(d, root=None):
    """Ecosystem-specific upgrade advice."""
    if d.get("ships") is False:
        return ("only your tests / dev tools use this (dev-dependencies), so it isn't "
                "built into your program. Lower priority: " + _dep_how(d, root))
    return _dep_how(d, root)


def _run_in(root, folder):
    """'cd <folder> && ' so a printed command works wherever it's pasted
    (real case: a check command run from the wrong repo failed). Without a
    root, the old relative wording is used."""
    if root is None:
        return None
    return f"cd {shell_path(Path(root) / folder)} && "


def _dep_how(d, root=None):
    name, to, eco = d["name"], d.get("fix_to"), d.get("ecosystem", "PyPI")
    source = d.get("source", "requirements.txt")
    folder = str(Path(source).parent)
    cd = _run_in(root, folder)
    where = "" if folder in ("", ".") else f"in `{folder}`: "
    if cd is not None:
        where = ""
    shown_source = (display_path(Path(root) / source) if root is not None else source)
    if eco == "PyPI" and name.lower() in SELF_UPGRADE_NOTE and on_termux():
        return SELF_UPGRADE_NOTE[name.lower()]
    if eco == "PyPI" and name.lower() == "pip":
        return ("inside your project's venv, run `python -m pip install --upgrade pip`. "
                "If pip came from your system's package manager, upgrade it there instead.")
    if not to:
        return ("no fixed version yet; consider an alternative package, or watch "
                "for an update.")
    if eco == "PyPI":
        return (f"`pip install '{name}>={to}'`, then update its pin in "
                f"`{shown_source}`")
    if eco == "crates.io":
        target = stable_of(to)
        loc = "" if folder in ("", ".") or cd is not None else f" in `{folder}`"
        pre = cd or ""
        toml = (f"`{display_path(Path(root) / folder / 'Cargo.toml')}`" if root is not None
                else "Cargo.toml")
        if semver_compatible(d["version"], to):
            return (f"run `{pre}cargo update -p {name}`{loc}; {to} is a compatible version, "
                    "so no Cargo.toml change is needed")
        if d.get("direct"):
            return (f"raise `{name}` to {target} in {toml}, then run "
                    f"`{pre}cargo update -p {name}`{loc} (a bigger version jump can need code changes)")
        via = d.get("via")
        if via:
            names = ", ".join(f"`{v}`" for v in via[:3]) + (" and others" if len(via) > 3 else "")
            one = len(via) == 1
            return (f"`{name}` isn't in your Cargo.toml: it comes in through {names} "
                    f"({'which is' if one else 'which are'} in your Cargo.toml). Updating "
                    f"{'that crate' if one else 'those crates'} is how it gets fixed. If the "
                    f"newest version still uses {name} {d['version']}, there's nothing to do "
                    "on your side but wait for its authors.")
        return (f"`{name}` isn't in your Cargo.toml: another crate pulls it in. To see "
                f"which, run `{pre}cargo tree -i {name}@{d['version']} --depth 1`{loc}, then "
                "update that crate instead" + (" (here that's usually one of your solana / anchor crates)"
                                   if d.get("solana") else ""))
    if eco == "npm":
        return f"{where}`{cd or ''}npm install {name}@{to}`"
    if eco == "Go":
        return f"{where}`{cd or ''}go get {name}@v{to}`"
    return f"upgrade `{name}` to {to} or later"


# ---------------------------------------------------------------------------
# Turning raw output into simple records
# ---------------------------------------------------------------------------
def is_test_file(path):
    parts = Path(path).parts
    name = parts[-1] if parts else ""
    return (any(p in ("tests", "test") for p in parts[:-1])
            or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py")


def flagged_line(code, line_number):
    """bandit's "code" field is a few numbered lines ("51  command, shell=True");
    return the text of the flagged one, or "" if it isn't there."""
    for raw in (code or "").splitlines():
        m = re.match(r"\s*(\d+)[ \t]?(.*)$", raw)
        if m and int(m.group(1)) == line_number:
            return " ".join(m.group(2).split())
    return ""


def parse_bandit(data, root=None):
    findings = []
    seen = set()
    for r in (data or {}).get("results", []):
        tid = r.get("test_id", "?")
        meaning, fix = BANDIT_PLAIN.get(
            tid, (r.get("issue_text", "No description."),
                  f"See {r.get('more_info', 'bandit docs')}"))
        path = r.get("filename", "?")
        if root:
            try:
                path = str(Path(path).resolve().relative_to(Path(root).resolve()))
            except ValueError:
                pass
        line = r.get("line_number", 0)
        if (tid, path, line) in seen:      # bandit can report a line twice
            continue
        seen.add((tid, path, line))
        findings.append({
            "id": tid,
            "severity": r.get("issue_severity", "LOW").upper(),
            "file": path,
            "line": line,
            "text": flagged_line(r.get("code", ""), line),
            "in_test": is_test_file(path),
            "meaning": meaning,
            "fix": fix,
        })
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                 f["file"], f["line"]))
    return findings


def parse_audit(data):
    # Newer pip-audit: {"dependencies": [...]}; older: a bare list.
    deps = data.get("dependencies", []) if isinstance(data, dict) else (data or [])
    risky = []
    for d in deps:
        vulns = d.get("vulns", [])
        if not vulns:
            continue
        fixes = sorted({v for vu in vulns for v in vu.get("fix_versions", [])})
        risky.append({
            "name": d.get("name", "?"),
            "version": d.get("version", "?"),
            "ids": list(dict.fromkeys(vu.get("id", "?") for vu in vulns)),
            "summary": first_sentence(vulns[0].get("description", "")),
            "fix_to": fixes[-1] if fixes else None,
            "ecosystem": "PyPI", "source": "requirements.txt",
            "severity": "", "no_fix": [],
        })
    return risky


def first_sentence(text, limit=240):
    text = " ".join(text.split())
    cut = text.find(". ")
    if 0 < cut < limit:
        return text[:cut + 1]
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"   # don't cut mid-word


# ---------------------------------------------------------------------------
# Secrets (gitleaks)
# ---------------------------------------------------------------------------
# Never print the secret itself: gitleaks runs with --redact, and the report
# only uses rule, file, line, commit and date.
SECRET_PLAIN = [
    # (substring of gitleaks RuleID, what it is)
    ("private-key", "A private key (SSH, TLS or wallet). Whoever has it can act as you."),
    ("github", "A GitHub token. It can read and change your repositories."),
    ("gcp", "A Google Cloud / Gemini API key. Others can run up usage on your account."),
    ("google", "A Google API key. Others can run up usage on your account."),
    ("aws", "An AWS key. It can create resources that you pay for."),
    ("openai", "An OpenAI API key. Others can spend your credit."),
    ("anthropic", "An Anthropic API key. Others can spend your credit."),
    ("slack", "A Slack token or webhook. It can post or read messages as you."),
    ("discord", "A Discord token or webhook."),
    ("telegram", "A Telegram bot token. Others can control your bot."),
    ("stripe", "A Stripe key. It can touch payments."),
    ("jwt", "A JSON Web Token. It may log someone in as you."),
    ("generic", "Something that looks like a password or API key. This is a pattern "
                "guess, so it can also be a fake or test value."),
]
SECRET_FIX_HISTORY = ("Rotate it first: make a new key and revoke the old one. Deleting "
                      "the line is not enough, because old commits still contain it. "
                      "Then load it from an environment variable or keyring.")
SECRET_FIX_GENERIC = ("Check whether it's real first: look at the line in YOUR terminal "
                      "(command below; don't paste the value anywhere). Placeholders, "
                      "test values, IDs and hashes aren't secrets. If it is a real key: ")
SECRET_FIX_FILES = ("Move it out of the code into an environment variable or keyring. "
                    "If this folder was ever pushed or shared, rotate the key too.")


def name_hint(match):
    """Look only at the setting's NAME (before : or =) in gitleaks' redacted
    match, never the value. Returns a short note, or ""."""
    name = re.split(r"[:=]", match or "", maxsplit=1)[0].strip().strip("\"'` ").lower()
    if not name or len(name) > 60:
        return ""
    if re.search(r"hash|sha\d*|digest|checksum|fingerprint", name):
        return ("the name says it's a hash: a one-way fingerprint, not the key itself. "
                "Usually fine")
    if re.search(r"(^|[^a-z])(id|uuid)$", name) or name.endswith("_id"):
        return "the name says it's an ID: IDs usually aren't secret"
    return ""


def shell_path(path):
    """The folder as you'd type it: ~/proj, or "$HOME/my proj" when it has a
    space (~ doesn't expand inside quotes)."""
    where = display_path(path)
    if " " not in where:
        return where
    return '"' + ("$HOME" + where[1:] if where.startswith("~") else where) + '"'


def view_command(f, root=None):
    """Command to look at the flagged line yourself (prints it locally only).
    With root, it works from any folder: `git -C` names the repo. Real case:
    the user ran the check from another repo and got "invalid object name"."""
    if f["commit"]:
        repo = f"-C {shell_path(root)} " if root is not None else ""
        return f"git {repo}show {f['commit']}:'{f['file']}' | sed -n {f['line']}p"
    prefix = shell_path(root) + "/" if root is not None else ""
    return f"sed -n {f['line']}p {prefix}'{f['file']}'"


def secret_meaning(rule, description):
    rule = (rule or "").lower()
    for key, text in SECRET_PLAIN:
        if key in rule:
            return text
    return description or "Something that looks like a secret."


def scan_secrets(folder):
    """Run gitleaks. In a git repo it scans the HISTORY (committed files);
    otherwise it scans the files as they are now."""
    if shutil.which("gitleaks") is None:
        return None, missing_tool("gitleaks")
    history = (Path(folder) / ".git").exists()
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "leaks.json"
        cmd = ["gitleaks", "detect", "--source", str(folder), "--report-format", "json",
               "--report-path", str(report), "--redact", "--no-banner", "--exit-code", "0"]
        if not history:
            cmd.append("--no-git")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)  # list form, no shell
        except OSError as e:
            return None, f"gitleaks couldn't run ({e.strerror or e})"
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout).strip().splitlines()
            return None, err[-1] if err else "gitleaks failed"
        try:
            text = report.read_text(encoding="utf-8").strip()
            leaks = json.loads(text) if text else []
        except (OSError, ValueError):
            return None, "couldn't read gitleaks' report"
    return {"history": history, "leaks": leaks or []}, None


def parse_gitleaks(data, root=None):
    """-> list of secret findings (never containing the secret)."""
    findings, seen = [], {}
    for r in (data or {}).get("leaks", []):
        path = r.get("File", "?")
        if root:
            try:
                p = Path(path)
                full = p if p.is_absolute() else Path(root) / p
                path = str(full.resolve().relative_to(Path(root).resolve()))
            except ValueError:
                pass
        commit = (r.get("Commit") or "")[:8]
        date = (r.get("Date") or "")[:10]
        line = r.get("StartLine", 0)
        rule = r.get("RuleID", "?")
        # Identity WITHOUT the commit ID: rewriting history (git filter-repo)
        # gives every commit a new ID, and the same leak in many commits is
        # one problem. Keep the EARLIEST commit as "first committed".
        fp = f"{rule}|{path}|{line}"
        if fp in seen:
            prev = seen[fp]
            if date and (not prev["date"] or date < prev["date"]):
                prev.update(commit=commit, date=date)
            continue
        findings.append({
            "id": rule, "file": path, "line": line, "commit": commit,
            "date": date, "fp": fp,
            "in_test": is_test_file(path),
            "still_there": bool(root) and (Path(root) / path).exists(),
            "meaning": secret_meaning(rule, r.get("Description")),
            "generic": "generic" in rule.lower(),
            "hint": name_hint(r.get("Match", "")),
        })
        seen[fp] = findings[-1]
    findings.sort(key=lambda f: (f["in_test"], f["file"], f["line"]))
    return findings


# ---------------------------------------------------------------------------
# .plainsec ignore file
# ---------------------------------------------------------------------------
IGNORE_FILE = ".plainsec"


def load_ignore(folder):
    """Read patterns from <folder>/.plainsec. Missing file = no patterns."""
    path = Path(folder) / IGNORE_FILE
    if not path.is_file():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            patterns.append(line)
    return patterns


def path_matches(path, pattern):
    """'tools/' matches tools/x.py and tools/a/b.py (not toolsx/). 'cv.py'
    matches that file. Patterns with * ? [ use shell-style matching, where
    * can also cross folders (so '*_old.py' matches a/b_old.py)."""
    def tidy(p):
        p = p.replace("\\", "/")          # Windows paths -> forward slashes
        while p.startswith("./"):
            p = p[2:]
        return p.lstrip("/")
    path, pat = tidy(path), tidy(pattern)
    if any(c in pat for c in "*?["):
        return (fnmatch.fnmatch(path, pat)
                or fnmatch.fnmatch(path, pat.rstrip("/") + "/*"))
    pat = pat.rstrip("/")
    return path == pat or path.startswith(pat + "/")


def apply_ignore(code, patterns):
    """Return (kept, skipped, unused).
    skipped = {pattern: [findings]} (first matching pattern wins);
    unused  = patterns that matched nothing (probably a typo)."""
    kept, skipped = [], {p: [] for p in patterns}
    for f in code:
        hit = next((p for p in patterns if path_matches(f["file"], p)), None)
        (skipped[hit] if hit else kept).append(f)
    unused = [p for p in patterns if not skipped[p]]
    return kept, {p: v for p, v in skipped.items() if v}, unused


# ---------------------------------------------------------------------------
# "What changed since last scan"
# ---------------------------------------------------------------------------
# Each scan's findings are saved OUTSIDE the project (so repos stay clean) in
# ~/.local/state/plainsec/<folder>-<hash>.json, or $PLAINSEC_STATE_DIR.
STATE_VERSION = 1
MAX_CHANGES_SHOWN = 15


def state_path(folder):
    base = os.environ.get("PLAINSEC_STATE_DIR") or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
        "plainsec")
    resolved = str(Path(folder).resolve())
    # Only names a file, not security; saying so keeps bandit (B324) quiet honestly.
    tag = hashlib.sha1(resolved.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
    return Path(base) / f"{Path(resolved).name or 'root'}-{tag}.json"


def fingerprint(f):
    """Identity of a code finding that survives line numbers moving:
    check + file + the flagged line's text (line number only as a fallback)."""
    where = f["text"] if f.get("text") else f"L{f['line']}"
    return f"{f['id']}|{f['file']}|{where}"


def dep_fingerprints(deps):
    return [f"{d.get('source', 'requirements.txt')}|{d['name'].lower()}|{v}"
            for d in deps for v in d["ids"]]


def _upgrade_dep_fp(fp):
    """Saved before Nov 20 as name|id (pip-audit, top-level requirements.txt)."""
    return f"requirements.txt|{fp}" if fp.count("|") == 1 else fp


def snapshot(code, deps, code_ok, deps_ok, secrets=None, secrets_ok=False):
    """What gets saved. A part that wasn't checked is None, so it can't be
    mistaken for 'no findings'."""
    return {
        "version": STATE_VERSION,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "code": [{"fp": fingerprint(f), "id": f["id"], "severity": f["severity"],
                  "file": f["file"], "line": f["line"]} for f in code] if code_ok else None,
        "deps": dep_fingerprints(deps) if deps_ok else None,
        "secrets": [f["fp"] for f in secrets or []] if secrets_ok else None,
    }


def load_state(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if data.get("version") == STATE_VERSION else None
    except (OSError, ValueError):
        return None


def save_state(path, new, old=None):
    """Write atomically. Parts not checked this time keep the old values,
    so one failed scan doesn't wipe the baseline."""
    if old:
        for part in ("code", "deps", "secrets"):
            if new[part] is None:
                new[part] = old.get(part)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(new, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def _upgrade_secret_fp(fp):
    """Saved before Nov 20 as rule|file|commit|line; now rule|file|line."""
    parts = fp.split("|")
    return "|".join([parts[0], parts[1], parts[3]]) if len(parts) == 4 else fp


def compare(old, code, deps, code_ok, deps_ok, secrets=None, secrets_ok=False):
    """Return a dict describing changes, or {"first": True} with no history."""
    if not old:
        return {"first": True}
    out = {"first": False, "since": old.get("scanned_at", "?"),
           "code_compared": code_ok and old.get("code") is not None,
           "deps_compared": deps_ok and old.get("deps") is not None,
           "secrets_compared": secrets_ok and old.get("secrets") is not None,
           "checked": {"code": code_ok, "deps": deps_ok, "secrets": secrets_ok},
           "new": [], "fixed": [], "new_deps": [], "fixed_deps": [],
           "new_secrets": [], "gone_secrets": []}
    if out["secrets_compared"]:
        before = {_upgrade_secret_fp(fp) for fp in old["secrets"]}
        out["new_secrets"] = [f for f in secrets or [] if f["fp"] not in before]
        now = {f["fp"] for f in secrets or []}
        out["gone_secrets"] = sorted(before - now)
    if out["code_compared"]:
        before = Counter(item["fp"] for item in old["code"])
        now = Counter(fingerprint(f) for f in code)
        added, gone = now - before, before - now
        for f in code:                     # current findings that are new
            fp = fingerprint(f)
            if added[fp]:
                added[fp] -= 1
                out["new"].append(f)
        for item in old["code"]:           # old findings no longer reported
            if gone[item["fp"]]:
                gone[item["fp"]] -= 1
                out["fixed"].append(item)
    if out["deps_compared"]:
        before = {_upgrade_dep_fp(fp) for fp in old["deps"]}
        now = set(dep_fingerprints(deps))
        out["new_deps"] = sorted(now - before)
        out["fixed_deps"] = sorted(before - now)
    return out


def render_changes(ch, hidden_ids, skipped_ids):
    out = ["## Since last scan"]
    if ch["first"]:
        if not ch.get("saved", True):
            return out + ["No earlier scan of this folder to compare with, and this "
                          "run used --no-save, so nothing was saved for next time.", ""]
        return out + ["First scan of this folder. Saved as the starting point; "
                      "the next scan will show what changed.", ""]
    out.append(f"Compared with the scan from {ch['since'].replace('T', ' ')}.")
    names = {"code": "Code", "deps": "Dependencies", "secrets": "Secrets"}
    for part, label in names.items():
        # Only mention a part this scan DID check but the last one didn't;
        # parts not checked now are already flagged NOT CHECKED elsewhere.
        if ch["checked"][part] and not ch[f"{part}_compared"]:
            out.append(f"- {label}: no earlier result to compare with yet.")
    any_change = (ch["new"] or ch["fixed"] or ch["new_deps"] or ch["fixed_deps"]
                  or ch["new_secrets"] or ch["gone_secrets"])
    if not any_change:
        if ch["code_compared"] or ch["deps_compared"] or ch["secrets_compared"]:
            out.append("Nothing changed in what was checked.")
        return out + [""]

    def capped(lines):
        extra = len(lines) - MAX_CHANGES_SHOWN
        return lines[:MAX_CHANGES_SHOWN] + ([f"  - …and {extra} more"] if extra > 0 else [])

    if ch["new"] or ch["new_deps"] or ch["new_secrets"]:
        total = len(ch["new"]) + len(ch["new_deps"]) + len(ch["new_secrets"])
        out.append(f"**New ({total}):**")
        lines = [f"  - ⚠ possible secret: {f['id']} `{f['file']}` line {f['line']}"
                 for f in ch["new_secrets"]]
        for f in sorted(ch["new"], key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"])):
            tag = (" — skipped by .plainsec" if id(f) in skipped_ids
                   else " — test file, hidden" if id(f) in hidden_ids else "")
            lines.append(f"  - [{f['severity']}] {f['id']} `{f['file']}` line {f['line']}{tag}")
        lines += [f"  - dependency {d.split('|')[1]} {d.split('|')[2]} (`{d.split('|')[0]}`)"
                  for d in ch["new_deps"]]
        out += capped(lines)
    if ch["fixed"] or ch["fixed_deps"] or ch["gone_secrets"]:
        total = len(ch["fixed"]) + len(ch["fixed_deps"]) + len(ch["gone_secrets"])
        out.append(f"**Gone since last time ({total}):**")
        lines = [f"  - {i['id']} `{i['file']}` (was line {i['line']})" for i in ch["fixed"]]
        lines += [f"  - possible secret {fp.split('|')[0]} `{fp.split('|')[1]}` "
                  "(no longer found — if it was real, it still needed rotating)"
                  for fp in ch["gone_secrets"]]
        lines += [f"  - dependency {d.split('|')[1]} {d.split('|')[2]} (`{d.split('|')[0]}`)"
                  for d in ch["fixed_deps"]]
        out += capped(lines)
    return out + [""]


def changes_headline(ch):
    if ch["first"]:
        return ("first scan (baseline saved)" if ch.get("saved", True)
                else "first scan (not saved: --no-save)")
    n = len(ch["new"]) + len(ch["new_deps"]) + len(ch["new_secrets"])
    g = len(ch["fixed"]) + len(ch["fixed_deps"]) + len(ch["gone_secrets"])
    if not (ch["code_compared"] or ch["deps_compared"] or ch["secrets_compared"]):
        return "no comparison possible"
    return f"{n} new, {g} gone since last scan"


# ---------------------------------------------------------------------------
# Writing the report
# ---------------------------------------------------------------------------
def split_findings(code, show_all=False):
    """Return (shown, hidden). Hidden = normal-in-tests findings."""
    if show_all:
        return code, []
    shown, hidden = [], []
    for f in code:
        (hidden if f["in_test"] and f["id"] in NORMAL_IN_TESTS else shown).append(f)
    return shown, hidden


def group_by_check(findings):
    """{test_id: [findings]} ordered worst severity first, then most places."""
    groups = {}
    for f in findings:
        groups.setdefault(f["id"], []).append(f)
    return dict(sorted(
        groups.items(),
        key=lambda kv: (min(SEVERITY_ORDER.get(f["severity"], 9) for f in kv[1]),
                        -len(kv[1]), kv[0])))


PASSWORD_CHECKS = {"B105", "B106", "B107"}
# A password-like name whose value is None / "" / '' / False: an empty slot,
# not a secret. Real case: `{"status": False, "port": None, "password": None}`.
_EMPTY_VALUE = re.compile(
    r"""(?i)(pass|pwd|secret|token|key)\w*['"]?\s*[:=]\s*(None|False|""|'')\s*([,})\]#]|$)""")


def empty_password_value(finding):
    return (finding["id"] in PASSWORD_CHECKS
            and bool(_EMPTY_VALUE.search(finding.get("text") or "")))


def where_lines(findings):
    """One line per file: 'path — lines 3, 9, 12 (+4 more)'."""
    per_file, empty = {}, set()
    for f in findings:
        per_file.setdefault(f["file"], []).append(f["line"])
        if empty_password_value(f):
            empty.add((f["file"], f["line"]))
    out = []
    for path, lines in sorted(per_file.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines = sorted(set(lines))
        shown = ", ".join(str(n) + (" (empty value, likely not a secret)"
                                    if (path, n) in empty else "")
                          for n in lines[:MAX_LINES_SHOWN])
        extra = len(lines) - MAX_LINES_SHOWN
        label = "line" if len(lines) == 1 else "lines"
        tag = " — test file, often harmless there" if is_test_file(path) else ""
        out.append(f"  - `{path}` — {label} {shown}" + (f" (+{extra} more)" if extra > 0 else "") + tag)
    return out


def headline(shown, hidden, deps, skipped=None, deps_checked=True, secrets=None,
             unsound=0):
    urgent = sum(1 for f in shown if f["severity"] in ("HIGH", "MEDIUM"))
    high = sum(1 for f in shown if f["severity"] == "HIGH")
    low = len(shown) - urgent
    serious = sum(1 for d in deps if d.get("severity") in ("CRITICAL", "HIGH"))
    test_only = sum(1 for d in deps if d.get("ships") is False)
    dep_part = (f"{len(deps)} risky dependenc{'y' if len(deps) == 1 else 'ies'}"
                + (f" ({', '.join(x for x in [f'{serious} high/critical' if serious else '', f'{test_only} test-only' if test_only else ''] if x)})"
                   if serious or test_only else "")
                + (f" + {unsound} unsound" if unsound else "")
                if deps_checked else "dependencies NOT CHECKED")
    parts = []
    if secrets is not None:          # None = secrets feature not in this report
        parts.append("secrets NOT CHECKED" if secrets == "not-checked" else
                     f"{len(secrets)} possible secret{'s' if len(secrets) != 1 else ''}")
    parts += [dep_part,
             f"{urgent} to fix first" + (f" ({high} high)" if high else ""),
             f"{low} low-priority"]
    if hidden:
        parts.append(f"{len(hidden)} normal-in-tests hidden")
    if skipped:
        all_skipped = [f for items in skipped.values() for f in items]
        high_sk = sum(1 for f in all_skipped if f["severity"] == "HIGH")
        parts.append(f"{len(all_skipped)} skipped by .plainsec"
                     + (f" (incl. {high_sk} HIGH)" if high_sk else ""))
    return " · ".join(parts)


def display_path(path):
    """~/project instead of /home/me/project, so it's short and copyable."""
    path = Path(path).resolve()
    try:
        return "~/" + path.relative_to(Path.home()).as_posix() if path != Path.home() else "~"
    except ValueError:
        return path.as_posix()


def build_report(name, code, deps, errors, show_all=False, skipped=None, unused=None,
                 changes=None, hidden_ids=frozenset(), skipped_ids=frozenset(),
                 secrets=None, secrets_info=None, dep_info=None, root=None):
    """secrets: None = not part of this report; "not-checked"; or a list.
    root: the scanned folder; when given, the report says paths start there."""
    deps_failed = any(e.startswith("dependency scan") for e in errors)
    code_failed = any(e.startswith("code scan") for e in errors)
    shown, hidden = split_findings(code, show_all)
    urgent = [f for f in shown if f["severity"] in ("HIGH", "MEDIUM")]
    low = [f for f in shown if f["severity"] not in ("HIGH", "MEDIUM")]

    n_unsound = sum(1 for n in (dep_info or {}).get("notices") or []
                    if n.get("kind") != "unmaintained")
    head = headline(shown, hidden, deps, skipped, not deps_failed, secrets, n_unsound)
    if changes:
        head += " · " + changes_headline(changes)
    out = [f"# Security report: {name}", "", f"**{head}**", ""]
    if root is not None:
        out += [f"File paths below start from `{display_path(root)}`. To open one, "
                f"first run `cd {shell_path(root)}`.", ""]
    for e in errors:
        out.append(f"> ⚠ Not checked: {e}")
    if errors:
        out.append("")
    if changes:
        out += render_changes(changes, hidden_ids, skipped_ids)
    if secrets is not None:
        out += render_secrets(secrets, secrets_info or {}, root)

    out += render_deps(deps, deps_failed, dep_info or {}, root)

    if code_failed:
        out += ["## 2. Your code",
                "NOT CHECKED (see warning above). This is not an all-clear.", ""]
        return "\n".join(out)

    out.append("## 2. Fix first (high / medium)")
    if not urgent:
        out.append("Nothing high or medium. 👍")
    out += render_groups(urgent)
    out.append("")

    out.append("## 3. Low priority (worth a look when you have time)")
    if not low:
        out.append("None.")
    out += render_groups(low)
    out.append("")

    if hidden:
        out.append("## 4. Hidden: normal in test files")
        out.append("These checks are expected inside tests (pytest uses `assert`, "
                   "tests use fake passwords). Run with `--all` to list them.")
        counts = {}
        for f in hidden:
            counts[f["id"]] = counts.get(f["id"], 0) + 1
        for tid, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            out.append(f"- {tid}: {n}")
        out.append("")

    dep_skipped = (dep_info or {}).get("skipped") or {}
    if skipped or unused or dep_skipped:
        out.append("## 5. Skipped by your .plainsec file")
        out.append("Not checked in detail because you listed these paths. "
                   "Run with `--all` to include them.")
        for pat, items in (skipped or {}).items():
            sev = {}
            for f in items:
                sev[f["severity"]] = sev.get(f["severity"], 0) + 1
            detail = ", ".join(f"{n} {k.lower()}" for k, n in
                               sorted(sev.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
            warn = " ⚠ includes HIGH — make sure this code is never run" if "HIGH" in sev else ""
            out.append(f"- `{pat}` — {len(items)} finding{'s' if len(items) != 1 else ''} ({detail}){warn}")
        for pat, items in dep_skipped.items():
            out.append(f"- `{pat}` — {len(items)} vulnerable dependenc"
                       f"{'y' if len(items) == 1 else 'ies'} in "
                       f"{', '.join(sorted({d['source'] for d in items}))}")
        for pat in unused or []:
            out.append(f"- `{pat}` — matched nothing. Typo, or the path moved?")
        out.append("")
    return "\n".join(out)


def render_secrets(secrets, info, root=None):
    out = ["## 0. Possible secrets (check these first)"]
    if secrets == "not-checked":
        return out + ["NOT CHECKED (see warning above). This is not an all-clear.", ""]
    where = ("git history (every committed version; files never committed aren't included)"
             if info.get("history") else "the files as they are now (not a git repo)")
    out.append(f"Scanned: {where}. Secrets are never printed here.")
    if not secrets:
        return out + ["No secrets found.", ""]
    by_rule = {}
    for f in secrets:
        by_rule.setdefault(f["id"], []).append(f)
    for rule, items in by_rule.items():
        out.append(f"### {rule} · {len(items)} place{'s' if len(items) != 1 else ''}")
        out.append(f"- What it means: {items[0]['meaning']}")
        base_fix = SECRET_FIX_HISTORY if info.get("history") else SECRET_FIX_FILES
        if items[0].get("generic"):
            out.append(f"- Fix: {SECRET_FIX_GENERIC}{base_fix[0].lower()}{base_fix[1:]}")
        else:
            out.append(f"- Fix: {base_fix}")
        out.append("- Where:")
        for f in items:
            bits = [f"`{f['file']}` line {f['line']}"]
            if f["commit"]:
                bits.append(f"first committed in {f['commit']}" + (f" ({f['date']})" if f["date"] else ""))
                if not f["still_there"]:
                    bits.append("file no longer exists, but it's still in history")
            if f["in_test"]:
                bits.append("test file: probably a fake value, but check")
            if f.get("hint"):
                bits.append(f["hint"])
            out.append("  - " + " — ".join(bits))
            if f.get("generic"):
                out.append(f"    - check: `{view_command(f, root)}`")
    return out + [""]


def render_deps(deps, failed, info, root=None):
    out = ["## 1. Dependencies"]
    if failed:
        return out + ["NOT CHECKED (see warning above). This is not an all-clear.", ""]
    if info.get("tool") == "osv-scanner" and info.get("file_by_file"):
        files = info["file_by_file"]
        out.append(f"Checked with osv-scanner, file by file ({len(files)}: "
                   + ", ".join(f"`{f}`" for f in files[:6]) + (", …" if len(files) > 6 else "")
                   + "), because its folder scan couldn't read this folder (seen on Termux).")
        if info.get("not_checked_files"):
            out.append("NOT checked (osv-scanner can't take these one by one): "
                       + ", ".join(f"`{f}`" for f in info["not_checked_files"]))
    elif info.get("tool") == "osv-scanner":
        out.append("Checked with osv-scanner: every dependency file in the project.")
        if info.get("no_deps_declared"):
            return out + [", ".join(f"`{f}`" for f in info["no_deps_declared"])
                          + " declares no dependencies, so there was nothing to check.", ""]
        if info.get("no_sources"):
            return out + ["No dependency files found, so there was nothing to check.", ""]
    else:
        out.append("Checked with pip-audit: the top-level requirements.txt only. "
                   "Install osv-scanner to check every dependency file (Rust, Node, "
                   "subfolders too).")
    if info.get("cargo_checked"):
        out.append("Rust crates were checked with `cargo tree`: \"tests only\" means a crate "
                   "comes in only through dev-dependencies, so it isn't built into your program.")
    elif info.get("cargo_missing"):
        out.append("Install Rust's `cargo` (or fix `cargo tree` in that folder) to tell "
                   "test-only crates apart from ones that ship in your program.")
    if not deps:
        out.append("No known vulnerabilities in your dependencies.")
    by_src = {}
    for d in deps:
        by_src.setdefault(d.get("source", "requirements.txt"), []).append(d)
    for src, items in by_src.items():
        eco = ECOSYSTEM_NAME.get(items[0].get("ecosystem"), items[0].get("ecosystem", ""))
        out.append(f"### `{src}` ({eco}) · {len(items)} package{'s' if len(items) != 1 else ''}")
        for d in ship_order(items):
            sev = (" · no severity score" if d.get("severity") == "NO SCORE"
                   else f" · {d['severity']}" if d.get("severity") else "")
            sev += (" · tests only" if d.get("ships") is False else
                    " · ships in your program" if d.get("ships") else "")
            n = len(d["ids"])
            out.append(f"- **{d['name']} {d['version']}**{sev} · {n} issue{'s' if n != 1 else ''} "
                       f"({', '.join(d['ids'][:4])}{', …' if n > 4 else ''})")
            if d["summary"]:
                out.append(f"  - What it means: {d['summary']}")
            if d.get("fix_to"):
                out.append(f"  - Fixed in: {fix_text(d['fix_to'])}"
                           + (f" (no fix yet for {', '.join(d['no_fix'])})" if d.get("no_fix") else ""))
            out.append(f"  - How: {dep_how(d, root)}")
    notices = info.get("notices") or []
    unsound = [n for n in notices if n.get("kind") != "unmaintained"]
    unmaint = [n for n in notices if n.get("kind") == "unmaintained"]
    if unsound:
        out.append(f"### Unsound code ({len(unsound)}): no known attack, but not safe")
        out.append("\"Unsound\" means the code can break Rust's memory-safety guarantees "
                   "if it's used in certain ways. No real attack is known, so it isn't "
                   "scored as a vulnerability, but it's worth fixing when a fix exists.")
        for d in ship_order(unsound):
            kind = "" if d.get("kind") in ("unsound", "") else f" [{d['kind']}]"
            kind += (" · tests only" if d.get("ships") is False else
                     " · ships in your program" if d.get("ships") else "")
            out.append(f"- **{d['name']} {d['version']}**{kind} (`{d['source']}`): "
                       f"{d['summary'] or d['ids'][0]}")
            if d.get("fix_to"):
                out.append(f"  - Fixed in: {fix_text(d['fix_to'])}")
            out.append(f"  - How: {dep_how(d, root)}")
    if unmaint:
        out.append(f"### Unmaintained ({len(unmaint)}): not vulnerabilities")
        out.append("Nobody maintains these any more, so future security problems won't "
                   "get fixed. Nothing is broken today; plan to replace them over time.")
        for d in unmaint:
            out.append(f"- {d['name']} {d['version']} (`{d['source']}`): {d['summary'] or d['ids'][0]}")
    skipped = info.get("skipped") or {}
    for pat, items in skipped.items():
        out.append(f"- Skipped by .plainsec `{pat}`: {len(items)} vulnerable package"
                   f"{'s' if len(items) != 1 else ''} (see section 5)")
    return out + [""]


def render_groups(findings):
    out = []
    for tid, items in group_by_check(findings).items():
        sev = items[0]["severity"]
        n = len(items)
        out.append(f"### {tid} · {sev} · {n} place{'s' if n != 1 else ''}")
        out.append(f"- What it means: {items[0]['meaning']}")
        out.append(f"- Fix: {items[0]['fix']}")
        out.append("- Where:")
        out += where_lines(items)
    return out


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("folder", nargs="?", default=".", help="project to scan")
    ap.add_argument("--out", help="also write the report to this .md file")
    ap.add_argument("--bandit-json", help="use saved bandit JSON instead of running it")
    ap.add_argument("--audit-json", help="use saved pip-audit JSON instead of running it")
    ap.add_argument("--secrets-json", help="use saved gitleaks JSON instead of running it")
    ap.add_argument("--osv-json", help="use saved osv-scanner JSON instead of running it")
    ap.add_argument("--audit-env", action="store_true",
                    help="no requirements.txt: audit the Python environment "
                         "pip-audit runs in (NOT necessarily your project's)")
    ap.add_argument("--all", action="store_true",
                    help="list everything: test-file findings and .plainsec skips")
    ap.add_argument("--no-save", action="store_true",
                    help="compare with the last scan but don't save this one")
    args = ap.parse_args(argv)

    folder = Path(args.folder).expanduser()
    errors = []

    if args.bandit_json:
        bandit_data, err = load_json(args.bandit_json), None
    else:
        bandit_data, err = scan_code(folder)
    if err:
        errors.append(f"code scan — {err}")

    dep_info = {}
    if args.osv_json:
        dep_info["tool"] = "osv-scanner"
        osv_data, err = load_json(args.osv_json), None
    elif args.audit_json:
        dep_info["tool"] = "pip-audit"
        audit_data, err = load_json(args.audit_json), None
    elif shutil.which("osv-scanner"):
        dep_info["tool"] = "osv-scanner"
        osv_data, err = scan_deps_osv(folder)
    else:
        dep_info["tool"] = "pip-audit"
        audit_data, err = scan_deps(folder, audit_env=args.audit_env)
        if args.audit_env and not (folder / "requirements.txt").exists() and not err:
            print("Note: --audit-env checked the environment pip-audit runs in, "
                  "not necessarily your project's.", file=sys.stderr)
    if err:
        errors.append(f"dependency scan — {err}")

    if args.secrets_json:
        leaks = load_json(args.secrets_json) or []
        secrets_data = {"history": any(r.get("Commit") for r in leaks), "leaks": leaks}
        err = None
    else:
        secrets_data, err = scan_secrets(folder)
    if err:
        errors.append(f"secrets scan — {err}")

    code = parse_bandit(bandit_data, root=folder)
    if dep_info["tool"] == "osv-scanner":
        deps, dep_info["notices"] = parse_osv(osv_data, root=folder)
        cargo_cache, ship_cache = {}, {}
        for d in deps + dep_info["notices"]:
            if d["ecosystem"] == "crates.io":
                src = d["source"]
                if src not in cargo_cache:
                    cargo_cache[src] = cargo_direct_deps(folder, src)
                    ship_cache[src] = cargo_shipping(folder, src)
                key = d["name"].replace("_", "-").lower()
                d["direct"] = key in cargo_cache[src]
                d["solana"] = any(n.startswith(("solana-", "anchor-")) for n in cargo_cache[src])
                if ship_cache[src] is not None:
                    d["ships"] = (key, d["version"]) in ship_cache[src]
                if not d["direct"] and d.get("fix_to") is not None:
                    d["via"] = cargo_via(folder, src, d["name"], d["version"],
                                         cargo_cache[src], d.get("ships"))
        dep_info["cargo_checked"] = any(v is not None for v in ship_cache.values())
        dep_info["cargo_missing"] = bool(ship_cache) and not dep_info["cargo_checked"]
        dep_info["no_sources"] = bool((osv_data or {}).get("no_sources"))
        dep_info["file_by_file"] = (osv_data or {}).get("file_by_file")
        dep_info["no_deps_declared"] = (osv_data or {}).get("no_deps_declared")
        dep_info["not_checked_files"] = (osv_data or {}).get("not_checked_files")
    else:
        deps = parse_audit(audit_data)
    secrets = parse_gitleaks(secrets_data, root=folder)
    code_ok = not any(e.startswith("code scan") for e in errors)
    deps_ok = not any(e.startswith("dependency scan") for e in errors)
    secrets_ok = not any(e.startswith("secrets scan") for e in errors)

    # Compare ALL findings (before .plainsec / test hiding), so adding an
    # ignore line never looks like a fix.
    spath = state_path(folder)
    old = load_state(spath)
    # History tracks notices too, so moving a package between "risky" and
    # "maintenance notice" is never reported as new or gone.
    deps_history = deps + dep_info.get("notices", [])
    changes = compare(old, code, deps_history, code_ok, deps_ok, secrets, secrets_ok)
    changes["saved"] = not args.no_save
    if not args.no_save:
        save_state(spath, snapshot(code, deps_history, code_ok, deps_ok, secrets, secrets_ok), old)

    skipped, unused = {}, []
    if not args.all:
        patterns = load_ignore(folder)
        code, skipped, unused = apply_ignore(code, patterns)
        # dependency files in skipped paths: counted, not detailed
        deps_kept, dep_skipped = [], {}
        for d in deps:
            hit = next((p for p in patterns if path_matches(d.get("source", ""), p)), None)
            (dep_skipped.setdefault(hit, []) if hit else deps_kept).append(d)
        deps, dep_info["skipped"] = deps_kept, dep_skipped
        unused = [p for p in unused if p not in dep_skipped]
    skipped_ids = {id(f) for items in skipped.values() for f in items}
    hidden_ids = set() if args.all else {
        id(f) for f in code if f["in_test"] and f["id"] in NORMAL_IN_TESTS}
    report = build_report(folder.resolve().name, code, deps, errors,
                          show_all=args.all, skipped=skipped, unused=unused,
                          changes=changes, hidden_ids=hidden_ids,
                          skipped_ids=skipped_ids,
                          secrets=secrets if secrets_ok else "not-checked",
                          secrets_info=secrets_data or {}, dep_info=dep_info,
                          root=folder)
    print(report)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Saved to {args.out}", file=sys.stderr)

    # Exit 1 if anything needs attention, so it can gate a git hook later.
    return 1 if (code or deps or secrets or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
