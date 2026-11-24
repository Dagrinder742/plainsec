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
    python plainsec.py https://github.com/owner/repo   # download, scan, delete

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
import ast
import hashlib
import json
import os
import re
import shutil
import stat
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
    "B110": ("An `except` that only does `pass` hides the errors it catches, so "
             "real failures go unnoticed.",
             "Catch the specific exception and at least log it."),
    "B112": ("An `except` that only does `continue` hides the errors it catches "
             "inside a loop.",
             "Catch only the error you expect (e.g. `except ValueError:`), so "
             "anything else still shows up. Logging is optional when skipping bad "
             "input is the point."),
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
    # B310 / B403: real cases (extremely-vulnerable-flask-app utils/profile_image.py:7,
    # routes/account.py:1) showed bandit's own text ("…associated with dumps module").
    "B310": ("A URL is opened with `urllib`. It also opens `file://` (and other) "
             "addresses, so if the address comes from a user or a file, it can be made "
             "to read local files instead.",
             "Check the address starts with `https://` (or `http://`) before opening it, "
             "or only open fixed addresses."),
    "B403": ("The `pickle` module is imported. Not a bug by itself, but loading pickle "
             "data can run code hidden in it (see B301 if it's flagged too).",
             "Fine if you only load pickle data your own program wrote; for anything "
             "else, use JSON."),
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
    "B605": ("A command built from variables is started through the shell "
             "(os.system etc.). If any part comes from a user, a file or an AI "
             "model, it can be bent into running other commands.",
             "Use `subprocess.run([...])` with a list instead."),
    "B607": ("A program is started by name only (e.g. 'git'), so whichever "
             "'git' is first on PATH gets run.",
             "Usually fine on your own device; use a full path if worried."),
    "B608": ("SQL is built by gluing strings together. That's how SQL "
             "injection happens.",
             "Use placeholders: `cur.execute('... WHERE id = ?', (id,))`. If the "
             "glued-in value is a number you set in code (like a LIMIT), the risk "
             "is low, but `LIMIT ?` is still the clean fix."),
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Checks that are normal inside test files: pytest is built on assert, and
# tests use fake passwords, temp paths and subprocess on purpose.
# bandit gives some checks LOW when the command is fixed text and HIGH when
# it's built from variables; the wording has to match. Real case: OXX-Terminal
# had six LOW B605s like os.system("clear") that read as alarming as a HIGH.
BANDIT_PLAIN_BY_SEVERITY = {
    ("B605", "LOW"): ("A fixed command (plain text, like `os.system(\"clear\")`) is "
                      "started through the shell. Safe as written; it only becomes "
                      "risky if someone later builds the command from input.",
                      "Fine to leave. If you edit it, `subprocess.run([...])` with a "
                      "list is the safer habit."),
    ("B602", "LOW"): ("A fixed command (plain text) runs with shell=True. Safe as "
                      "written; it only becomes risky if someone later builds the "
                      "command from input.",
                      "Fine to leave. If you edit it, pass a list and drop shell=True."),
}

NORMAL_IN_TESTS = {"B101", "B103", "B105", "B106", "B107", "B108", "B404", "B603"}

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
                 # not apt: Ubuntu's is 8.16.0, which missed a secret 8.30.1 finds
                 # (real case Nov 24, trinity_master: 2 vs 3 possible secrets)
                 "download it from github.com/gitleaks/gitleaks/releases",
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


NPM_LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                  "bun.lock", "bun.lockb"}


def workspace_patterns(folder):
    """Workspace globs a folder declares: package.json "workspaces" (a list, or
    {"packages": [...]}) and pnpm-workspace.yaml "packages:" items."""
    pats = []
    try:
        ws = json.loads((Path(folder) / "package.json").read_text(encoding="utf-8")).get("workspaces")
    except (OSError, ValueError, AttributeError):
        ws = None
    if isinstance(ws, dict):
        ws = ws.get("packages")
    if isinstance(ws, list):
        pats += [w for w in ws if isinstance(w, str)]
    try:
        in_list = False
        for line in (Path(folder) / "pnpm-workspace.yaml").read_text(encoding="utf-8").splitlines():
            if re.match(r"^packages\s*:", line):
                in_list = True
            elif in_list and re.match(r"^\s*-\s*", line):
                pats.append(re.sub(r"^\s*-\s*", "", line).strip().strip("'\""))
            elif in_list and line.strip() and not line.startswith((" ", "\t")):
                in_list = False
    except OSError:
        pass
    return [p.strip().lstrip("./").rstrip("/") for p in pats if p.strip()]


def covered_by_workspace(lock_dir, here):
    """A parent's lock covers `here` only if that parent declares it a workspace.
    Real case (LipStickFighting): a root package-lock.json without workspaces held
    none of server/package.json's 31 dependencies."""
    rel = here.relative_to(lock_dir).as_posix()
    pats = workspace_patterns(lock_dir)
    if any(fnmatch.fnmatch(rel, p[1:].lstrip("./")) for p in pats if p.startswith("!")):
        return False
    return any(fnmatch.fnmatch(rel, p) for p in pats if not p.startswith("!"))


def unlocked_package_jsons(folder, limit=20):
    """package.json files that declare dependencies but have no lock file in their
    folder, and aren't a workspace of a parent folder that has one. osv-scanner
    checks lock files only, so these are silently skipped. Real case
    (bradtraversy/react_step_form): 6 dependencies, no lock, and the report said
    "0 risky dependencies … nothing to check" (exit 0). With a lock: 35 risky."""
    folder = Path(folder)
    lock_dirs, found = set(), []
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if NPM_LOCK_NAMES & set(filenames):
            lock_dirs.add(Path(dirpath))
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        if "package.json" not in filenames:
            continue
        here = Path(dirpath)
        if here in lock_dirs or any(d in here.parents and covered_by_workspace(d, here)
                                    for d in lock_dirs):
            continue
        try:
            pj = json.loads((here / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(pj, dict) and any(isinstance(pj.get(k), dict) and pj[k] for k in
                                        ("dependencies", "devDependencies", "optionalDependencies")):
            found.append((here / "package.json").relative_to(folder).as_posix())
            if len(found) >= limit:
                break
    return found


def scan_deps_osv(folder):
    data, err = _scan_deps_osv(folder)
    if data is not None:
        unlocked = unlocked_package_jsons(folder)
        if unlocked:
            data["unlocked_npm"] = unlocked
    return data, err


def _scan_deps_osv(folder):
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
    # Real case (extremely-vulnerable-flask-app, osv-scanner 2.4.0): requirements.txt
    # came back twice (type "lockfile", then "unknown") and werkzeug was listed and
    # counted twice. One entry per package per file.
    seen = set()
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
            if (src, eco, name, version) in seen:
                continue
            seen.add((src, eco, name, version))
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
                    "summary": issue_summary(vs),
                    "osv_id": (g.get("ids") or ["?"])[0],
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
                    issues=[(e["label"], e["summary"], e["osv_id"]) for e in real],
                    fix_to=max(fixes, key=vkey) if fixes else None,
                    no_fix=[e["label"] for e in real if not e["fix"]]))
            for e in info:
                notices.append(dict(base, ids=[e["label"]], summary=e["summary"],
                                    issues=[(e["label"], e["summary"], e["osv_id"])],
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


# Go "pseudo-versions" name an untagged commit. Real case (go-test-bench,
# x/crypto fix 0.58.1-0.20261009181718-2f1f834330b2): "0.58.1 or later" named a
# version that doesn't exist (go get: "unknown revision v0.58.1").
#   X.Y.Z-0.<date>-<commit>: a commit after release X.Y.(Z-1)
#   X.Y.Z-<date>-<commit>:   a commit from before X.Y.Z was tagged
_GO_PSEUDO = re.compile(r"^(\d+)\.(\d+)\.(\d+)-(0\.)?(\d{14})-([0-9a-f]{12})$")


def go_after_release(v):
    """'0.58.1-0.20261009181718-2f1f…' -> '0.58.0' (the release the fix comes
    after); None for any other version."""
    m = _GO_PSEUDO.match(str(v))
    if not m or not m.group(4) or int(m.group(3)) == 0:
        return None
    return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) - 1}"


def fix_text(v, eco=None):
    after = go_after_release(v) if eco == "Go" else None
    if after:
        return (f"the first release after {after} (the fix is an unreleased commit, "
                f"{str(v).rsplit('-', 1)[-1]})")
    if is_prerelease(v):
        return f"{stable_of(v)} or later (first fixed in pre-release {v})"
    return f"{v} or later"


def npm_direct_deps(root, source):
    """Names in the package.json next to an npm lock file (every dependency
    list), or None if there's no readable package.json there."""
    base = (Path(root) / source).parent if root else Path(source).parent
    try:
        data = json.loads((base / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    names = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if isinstance(data.get(key), dict):
            names.update(data[key])
    return names


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


def _cargo_where(folder):
    """(extra args, cwd) for a cargo call about the Cargo.lock in folder.
    cargo reads `.cargo/config.toml` (which can name a program to run as
    rustc) and rustup reads `rust-toolchain.toml` from the folder it's started
    in, so scanning a stranger's repo could run its code (VERIFIED Nov 23: a
    rustc-wrapper script ran). Started from your home folder with
    --manifest-path, neither file in the project is read. Every scan works
    this way, downloaded or not: a cloned repo is just as untrusted. Cost: a
    project's own cargo settings are ignored too; if cargo fails because of
    that, the report only loses its test-only labels."""
    return ["--manifest-path", str(Path(folder).resolve() / "Cargo.toml")], Path.home()


def cargo_shipping(root, source):
    """Set of (name, version) that are built WITHOUT dev-dependencies, from
    `cargo tree -e no-dev` run next to the Cargo.lock. None if cargo is missing
    or fails (then nothing is labelled)."""
    if shutil.which("cargo") is None:
        return None
    folder = (Path(root) / source).parent if root else Path(source).parent
    extra, cwd = _cargo_where(folder)
    cmd = ["cargo", "tree", "-e", "no-dev", "--target", "all", "--prefix", "none",
           "--format", "{p}", "--locked"] + extra
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
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
        # appended, never inserted: an insert at [3] once split `-i` from its
        # crate (`-i -e no-dev borsh@…`), cargo failed, and the two crates
        # that ship got the old advice
        cmd += ["-e", "no-dev"]
    extra, cwd = _cargo_where(folder)
    cmd += extra
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
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


def dep_how(d, root=None, grouped=False):
    """Ecosystem-specific upgrade advice. grouped=True: the test-only
    explanation is already given once for the group, so don't repeat it."""
    if d.get("ships") is False and not grouped:
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
        # Real case (extremely-vulnerable-flask-app): pasted from ~ on Ubuntu, the bare
        # command was refused ("externally-managed-environment"); in a venv it worked.
        # How to make that venv, from what actually happens (Nov 23): Ubuntu's Python
        # is EXTERNALLY-MANAGED (plain pip refused) and its venv needs python3-venv
        # (it says `apt install python3.14-venv`); Termux has no marker, plain pip works.
        make = (f"`{cd}python3 -m venv .venv && . .venv/bin/activate`" if cd is not None
                else "`python3 -m venv .venv && . .venv/bin/activate` in the project folder")
        return (f"inside the project's virtual environment, run `pip install '{name}>={to}'`, "
                f"then update its pin in `{shown_source}`. No virtual environment yet? "
                f"{make} makes one and turns it on (Ubuntu/Debian: if that fails, run "
                "`sudo apt install python3-venv` first; on Termux a plain `pip install` "
                "works too)")
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
            # the "if the newest version still uses it, wait" note is said ONCE at
            # the top of the section (real case: it was repeated 9 times)
            return (f"`{name}` isn't in your Cargo.toml: it comes in through {names} "
                    f"({'which is' if one else 'which are'} in your Cargo.toml). Update "
                    f"{'that crate' if one else 'those crates'}.")
        return (f"`{name}` isn't in your Cargo.toml: another crate pulls it in. To see "
                f"which, run `{pre}cargo tree -i {name}@{d['version']} --depth 1`{loc}, then "
                "update that crate instead" + (" (here that's usually one of your solana / anchor crates)"
                                   if d.get("solana") else ""))
    if eco == "npm":
        if d.get("direct") is False:
            # Real case (NodeGoat): minimist had 12 copies, 11 nested under other
            # packages; `npm install minimist@…` only adds a new top-level one.
            # `npm ls --package-lock-only` reads the lock, no install needed.
            loc = "" if folder in ("", ".") or cd is not None else f" in `{folder}`"
            # `npm audit fix` is said once per lock file: npm_audit_note()
            return (f"`{name}` isn't in your package.json: other packages pull it in. To see "
                    f"which, run `{cd or ''}npm ls {name} --package-lock-only`{loc}, then "
                    "update those packages (the names right under your project).")
        return f"{where}`{cd or ''}npm install {name}@{to}`"
    if eco == "Go":
        after = go_after_release(to)
        if after:
            return (f"{where}`{cd or ''}go get {name}@latest`, then check the version it "
                    f"prints is newer than v{after}")
        if _GO_PSEUDO.match(str(to)):
            # real case (yaml.v3): the snapshot DOWNGRADED v3.0.1; the tag doesn't
            return f"{where}`{cd or ''}go get {name}@v{stable_of(to)}`"
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
            or name == "conftest.py"
            # checkers like bench/tasks/*/verify.py: their asserts ARE the check
            or (name.startswith("verify") and name.endswith(".py")))


def flagged_line(code, line_number):
    """bandit's "code" field is a few numbered lines ("51  command, shell=True");
    return the text of the flagged one, or "" if it isn't there."""
    for raw in (code or "").splitlines():
        m = re.match(r"\s*(\d+)[ \t]?(.*)$", raw)
        if m and int(m.group(1)) == line_number:
            return " ".join(m.group(2).split())
    return ""


_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)")


def enclosing_function(path, line, cache):
    """Name of the def that contains `line`, or "". Reads the file once."""
    if path not in cache:
        try:
            cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path]
    if not 0 < line <= len(lines):
        return ""
    target = lines[line - 1]
    indent = len(target) - len(target.lstrip())
    for i in range(line - 2, -1, -1):
        m = _DEF.match(lines[i])
        if m and len(m.group(1)) < indent:
            return m.group(2)
        stripped = lines[i].strip()
        if stripped and not stripped.startswith(("#", "@")) and \
                len(lines[i]) - len(lines[i].lstrip()) == 0 and not m:
            return ""                       # back at module level
    return ""


def is_selftest_name(name):
    """Real case: macro_engine.py's asserts sit in cmd_selftest()."""
    return bool(re.search(r"(^|_)(self_?test|tests?)(_|$)|^test", name or "", re.I))


def _fixed(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.IfExp):
        return _fixed(node.body) and _fixed(node.orelse)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _fixed(node.left) and _fixed(node.right)
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_fixed(e) for e in node.elts)
    return False


def fixed_command(text):
    """'empty', 'fixed' or ''. Reads ONLY the flagged line. Real cases:
    os.system("cls" if os.name == "nt" else "clear") was a HIGH B605 (fixed
    either way); os.system("") turns on ANSI colors in Windows consoles."""
    try:
        tree = ast.parse((text or "").strip())
    except (SyntaxError, ValueError):
        return ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and arg.value == "":
                return "empty"
            if _fixed(arg):
                return "fixed"
            return ""
    return ""


COMMAND_CHECKS = {"B602", "B605", "B607"}


# A value with 7+ words is a sentence (a message, help text), not a key.
# Passphrases can have spaces, so short multi-word values are NOT tagged.
# Real case: plainsec's own SECRET_FIX_HISTORY = ("Rotate it first: make a new
# key and revoke …") was flagged B105 "password hard-coded".
_SENTENCE_VALUE = re.compile(r"""[:=]\s*\(?\s*[rbfu]*(["'])((?:(?!\1).){0,400})""")


def sentence_value(finding):
    if finding["id"] not in PASSWORD_CHECKS:
        return False
    m = _SENTENCE_VALUE.search(finding.get("text") or "")
    return bool(m) and len(m.group(2).split()) >= 7


def line_note(f):
    """Short note after a line number, from the flagged line only."""
    if empty_password_value(f):
        return "empty value, likely not a secret"
    if sentence_value(f):
        return "the value is a sentence, not a key: likely a false alarm"
    if f["id"] in COMMAND_CHECKS:
        kind = fixed_command(f.get("text"))
        if kind == "empty":
            return "empty command: the usual trick to turn on colors in Windows consoles; harmless"
        if kind == "fixed" and f["severity"] != "LOW":
            return "fixed text either way, so likely safe"
    return ""


def parse_bandit(data, root=None):
    findings = []
    seen = set()
    sources = {}                    # file text cache for enclosing_function
    for r in (data or {}).get("results", []):
        tid = r.get("test_id", "?")
        meaning, fix = BANDIT_PLAIN.get(
            tid, (r.get("issue_text", "No description."),
                  f"See {r.get('more_info', 'bandit docs')}"))
        sev_text = BANDIT_PLAIN_BY_SEVERITY.get((tid, r.get("issue_severity", "LOW").upper()))
        if sev_text:
            meaning, fix = sev_text
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
        in_test = is_test_file(path)
        if not in_test and root and tid in NORMAL_IN_TESTS:
            in_test = is_selftest_name(enclosing_function(Path(root) / path, line, sources))
        findings.append({
            "id": tid,
            "severity": r.get("issue_severity", "LOW").upper(),
            "file": path,
            "line": line,
            "text": flagged_line(r.get("code", ""), line),
            "in_test": in_test,
            "meaning": meaning,
            "fix": fix,
        })
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                 f["file"], f["line"]))
    return findings


def python_error(path):
    """'line N: message' if Python itself can't read the file, else ''.
    Only parses (ast), never runs it. Real case (Nov 23, trinity_master): all
    11 files bandit skipped were really broken drafts (unmatched ')', missing
    blocks), and the old advice "upgrading bandit can help" was wrong."""
    try:
        ast.parse(Path(path).read_bytes(), str(path))
    except SyntaxError as e:
        return f"line {e.lineno}: {e.msg}" if e.lineno else e.msg
    except ValueError as e:          # e.g. a null byte in the file
        return str(e)
    except (OSError, RecursionError, MemoryError):
        return ""
    return ""


def bandit_unread(data, root=None):
    """Files bandit skipped because it couldn't read them -> {"invalid":
    {file: Python's own error}, "other": [files], "crashed": bool, "all":
    every file failed and some weren't simply invalid Python}.
    Real case (Nov 23): Ubuntu's apt bandit 1.7.10 on Python 3.14 crashed on
    every file ("exception while scanning file") and the report said
    "0 low-priority", an all-clear about nothing."""
    out = {"invalid": {}, "other": [], "crashed": False, "all": False}
    errs = [e for e in (data or {}).get("errors") or [] if e.get("filename")]
    if not errs:
        return out
    def rel(p):
        if root:
            try:      # same form as parse_bandit, so history can match files
                return str(Path(p).resolve().relative_to(Path(root).resolve()))
            except ValueError:
                pass
        return p
    for e in errs:
        why = python_error(e["filename"])
        if why:
            out["invalid"][rel(e["filename"])] = why
        elif rel(e["filename"]) not in out["other"]:
            out["other"].append(rel(e["filename"]))
            out["crashed"] |= "exception" in (e.get("reason") or "")
    out["other"].sort()
    scanned = {k for k in ((data or {}).get("metrics") or {}) if k != "_totals"}
    out["all"] = bool(out["other"]) and not (data or {}).get("results") and \
        (not scanned or scanned <= {e["filename"] for e in errs})
    return out


def _listed(items):
    return ", ".join(items[:MAX_LINES_SHOWN]) + \
        (f" +{len(items) - MAX_LINES_SHOWN} more" if len(items) > MAX_LINES_SHOWN else "")


def unread_warnings(info, patterns=()):
    """Warning lines for bandit_unread() info. Files skipped by .plainsec
    aren't listed (you said you don't use them). -> (lines, n invalid shown,
    other files shown?)."""
    keep = lambda f: not any(path_matches(f, p) for p in patterns)
    invalid = {f: w for f, w in info["invalid"].items() if keep(f)}
    other = [f for f in info["other"] if keep(f)]
    lines = []
    if invalid:
        n = len(invalid)
        one = n == 1
        ver = f"{sys.version_info.major}.{sys.version_info.minor}"
        lines.append(
            f"{n} Python file{'' if one else 's'} {'isn' if one else 'aren'}'t valid Python: "
            f"Python {ver} can't read {'it' if one else 'them'} either, so "
            f"{'it' if one else 'they'} can't run as written (usually a broken or "
            f"unfinished draft). bandit skipped {'it' if one else 'them'}: "
            + _listed([f"`{f}` ({w})" for f, w in sorted(invalid.items())])
            + f". Fix {'it' if one else 'them'}, delete {'it' if one else 'them'}, or "
            "skip the folder in a `.plainsec` file.")
    if other:
        them = "them" if len(other) != 1 else "it"
        where = shutil.which("bandit")
        why = (f"bandit crashed on {them}, which usually means your bandit is too old for "
               "your Python version" + (f" (the one used: `{where}`)" if where else "")
               + ". Install a newer one with `pipx install bandit` (the apt version can lag "
               "far behind), or upgrade the one you have" if info["crashed"] else
               f"bandit couldn't parse {them}, though Python can (its syntax may be newer "
               "than your bandit knows): upgrade bandit")
        listed = _listed([f"`{f}`" for f in other])
        if info["all"]:
            lines.append(f"bandit couldn't read any of your Python files ({listed}): {why}.")
        else:
            lines.append(f"{len(other)} Python file{'s' if len(other) != 1 else ''} "
                         f"({listed}) — {why}. Findings in {them} are missing below, and "
                         "\"since last scan\" skips your code this time.")
    return lines, len(invalid), bool(other)


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


_PROBLEM_WORDS = re.compile(
    r"vulnerab|attack|exploit|crash|denial|dos\b|inject|bypass|overflow|leak|spoof|"
    r"forg|unsound|panic|hang|exhaust|untrusted|malicious|unsafe|disclos|expos|"
    r"allow|could|can be|may |fail|improper|incorrect|insufficient|missing|race|"
    r"redirect|traversal|smuggl|tamper|compromis|distrust|timing|weak|discovered to contain",
    re.I)


def issue_summary(vs):
    """Short 'what it means' for one problem. Real case: idna had no summary,
    and the first sentence of its details just described the package
    ("…provides support for Internationalized Domain Names…"). A details
    sentence is used only if it sounds like a problem; else "" (the report
    then links the advisory)."""
    for v in vs:
        if v.get("summary"):
            return first_sentence(v["summary"])
    for v in vs:
        text = " ".join((v.get("details") or "").split())
        # Real case (vulpy, pyjwt PYSEC-2025-183): the problem sentence ("…discovered
        # to contain weak encryption.") didn't match, so the NOTE after it ("NOTE: this
        # is disputed by the Supplier…") became the meaning. A NOTE is never the meaning.
        disputed = " (disputed by the maintainers; see the advisory)" if re.search(
            r"\bdisputed\b", text, re.I) else ""
        for sentence in re.split(r"(?<=[.!?])\s+", text)[:3]:
            if re.match(r"\W*(NOTE\b|\*\*\s*DISPUTED)", sentence, re.I):
                continue
            if _PROBLEM_WORDS.search(sentence):
                return first_sentence(sentence) + disputed
    return ""


def advisory_link(osv_id):
    return f"https://osv.dev/vulnerability/{osv_id}"


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


# Real case: OXX-Terminal's `API_KEY_ID = "…"` (a real Kalshi key) got
# "IDs usually aren't secret" and was counted as probably harmless.
KEY_ID_HINT = ("the name says it's an API key ID: half of a login (it's paired with a "
               "secret or private key). Treat it as private; if the other half was "
               "ever committed too, rotate the key")


# Names that say "this is a credential". Unlike the ID/hash notes this one
# doesn't play anything down: real case (Nov 23), trinity_master's
# `CLOUDFLARE_TUNNEL_TOKEN", "REDACTED"` got no note at all, and nothing said
# it deserved a look before the ID/hash ones.
_SECRET_NAMES = (
    (r"passphrase$", "passphrase"),
    (r"(passw(or)?d|pwd)$", "password"),
    (r"private[-_ ]?key$", "private key"),
    (r"api[-_ ]?key$", "API key"),
    (r"secret[-_ ]?key$|secret$", "secret"),
    (r"credentials?$", "credential"),
    (r"token$", "token"),
    # Real cases (Nov 23): `aws_secret_access_key` (test_keys keys:5, the secret
    # half of an AWS key), `secret_key_base` (Rails, leaky-repo secrets.yml) and
    # docker's `auth` (base64 user:password, leaky-repo .docker/.dockercfg) got
    # no note. Checked after the endings above; the hash / ID notes still win.
    (r"secret", "secret"),
    (r"^auth$", "login (user name and password)"),
)


def secret_name_hint(kind):
    # "an API key", not "a API key" (real case: leaky-repo cloud/.tugboat:4)
    article = "an" if kind[:1].lower() in "aeiou" else "a"
    return (f"the name says it's {article} {kind}: a working credential unless it's a "
            "placeholder or test value, so check this one first")


def setting_name(match):
    """The setting's NAME at the start of gitleaks' redacted match, never the
    value. Real shapes: `market_id: "REDACTED"`, `api_token_hash": "REDACTED"`,
    `CLOUDFLARE_TUNNEL_TOKEN", "REDACTED"` (a getenv default: no : or = at all)."""
    m = re.match(r"""\s*["'`]?([A-Za-z_][A-Za-z0-9_.\-]*)""", match or "")
    return m.group(1).lower() if m else ""


def name_hint(match):
    """Look only at the setting's NAME in gitleaks' redacted match, never the
    value. Returns a short note, or ""."""
    name = setting_name(match)
    if not name or len(name) > 60:
        return ""
    if re.search(r"key[-_ ]?id$", name):
        return KEY_ID_HINT
    if re.search(r"hash|sha\d*|digest|checksum|fingerprint", name):
        return ("the name says it's a hash: a one-way fingerprint, not the key itself. "
                "Usually fine")
    if re.search(r"(^|[^a-z])(id|uuid)$", name) or name.endswith("_id"):
        return "the name says it's an ID: IDs usually aren't secret on their own"
    for pattern, kind in _SECRET_NAMES:
        if re.search(pattern, name):
            return secret_name_hint(kind)
    return ""


def plays_down(hint):
    """True for notes that say "probably fine" (ID / hash). Only those are
    counted as "named like IDs/hashes" in the headline."""
    return bool(hint) and ("it's an ID:" in hint or "it's a hash:" in hint)


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
    lines = f["line"] if isinstance(f["line"], list) else [f["line"]]
    # several lines: one sed prints them all, with their numbers so you can
    # tell them apart ('7877p;7964p' → "7877: …")
    sed = (f"sed -n {lines[0]}p" if len(lines) == 1 else
           "sed -n '" + ";".join(f"{n}{{=;p}}" for n in lines) + "' | paste - -")
    if f["commit"]:
        repo = f"-C {shell_path(root)} " if root is not None else ""
        return f"git {repo}show {f['commit']}:'{f['file']}' | {sed}"
    prefix = shell_path(root) + "/" if root is not None else ""
    return f"{sed} {prefix}'{f['file']}'" if len(lines) == 1 else \
        f"cat {prefix}'{f['file']}' | {sed}"


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
    return {"history": history, "leaks": leaks or [], "version": gitleaks_version(),
            "path": shutil.which("gitleaks")}, None


GITLEAKS_MIN = (8, 30)


def gitleaks_version():
    """'8.30.1', or None when `gitleaks version` prints no number (Ubuntu's apt
    build 8.16.0-1build2 prints "Version is set by build process")."""
    try:
        proc = subprocess.run(["gitleaks", "version"], capture_output=True, text=True)
    except OSError:
        return None
    m = re.search(r"(?<![\d.])(\d+\.\d+(?:\.\d+)?)", proc.stdout or "")   # "8.30.1" or "v8.30.1"
    return m.group(1) if m else None


def old_gitleaks_note(info):
    """One line for section 0 when the gitleaks that ran is older than 8.30 or
    doesn't say its version; None otherwise (or when plainsec didn't run it)."""
    if "version" not in info:          # --secrets-json: not run here, version unknown
        return None
    ver, path = info["version"], info.get("path")
    at = f" (`{path}`)" if path else ""
    if ver:
        if tuple(int(p) for p in ver.split(".")[:2]) >= GITLEAKS_MIN:
            return None
        which = f"This scan used gitleaks {ver}{at}."
    else:
        which = (f"This scan used a gitleaks{at} that doesn't say its version "
                 "(Ubuntu's apt build, 8.16.0, prints no number).")
    return (f"{which} Versions older than 8.30 have older rules and can miss secrets "
            f"that newer ones find, so this list may not be complete. "
            + install_hint("gitleaks"))


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


def state_path(folder, key=None):
    """key: a repo URL's state_key(). A URL scan uses a new temp folder every
    time, so the folder can't be the identity there."""
    base = os.environ.get("PLAINSEC_STATE_DIR") or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
        "plainsec")
    resolved = key or str(Path(folder).resolve())
    name = (re.sub(r"[^A-Za-z0-9._-]", "_", key.rsplit("/", 1)[-1].replace("#", "-"))
            if key else Path(resolved).name) or "root"
    # Only names a file, not security; saying so keeps bandit (B324) quiet honestly.
    tag = hashlib.sha1(resolved.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
    return Path(base) / f"{name}-{tag}.json"


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


def compare(old, code, deps, code_ok, deps_ok, secrets=None, secrets_ok=False,
            unread_files=frozenset()):
    """Return a dict describing changes, or {"first": True} with no history.
    unread_files: files bandit couldn't read this time (invalid Python); their
    old findings aren't "gone", just not looked at."""
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
        old = dict(old, code=[i for i in old["code"] if i.get("file") not in unread_files])
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
        # Same check + same flagged text + same file name (any case, any folder)
        # = the file was renamed or moved, not a new problem. Real case:
        # Matrix_Rain.py → matrix_rain.py showed "New: [HIGH] B605" + "Gone".
        out["moved"] = []
        for f in list(out["new"]):
            if not f.get("text"):
                continue
            for item in out["fixed"]:
                parts = item["fp"].split("|", 2)
                if (len(parts) == 3 and parts[0] == f["id"] and parts[2] == f["text"]
                        and parts[1] != f["file"]
                        and Path(parts[1]).name.lower() == Path(f["file"]).name.lower()):
                    out["moved"].append((f, parts[1]))
                    out["new"].remove(f)
                    out["fixed"].remove(item)
                    break
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
            return out + ["No earlier scan of this project to compare with, and this "
                          "run used --no-save, so nothing was saved for next time.", ""]
        return out + ["First scan of this project. Saved as the starting point; "
                      "the next scan will show what changed.", ""]
    out.append(f"Compared with the scan from {ch['since'].replace('T', ' ')}.")
    names = {"code": "Code", "deps": "Dependencies", "secrets": "Secrets"}
    for part, label in names.items():
        # Only mention a part this scan DID check but the last one didn't;
        # parts not checked now are already flagged NOT CHECKED elsewhere.
        if ch["checked"][part] and not ch[f"{part}_compared"]:
            out.append(f"- {label}: no earlier result to compare with yet.")
    any_change = (ch["new"] or ch["fixed"] or ch["new_deps"] or ch["fixed_deps"]
                  or ch["new_secrets"] or ch["gone_secrets"] or ch.get("moved"))
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
        lines += [f"  - dependency `{d.split('|')[1]}`: {d.split('|')[2]} (`{d.split('|')[0]}`)"
                  for d in ch["new_deps"]]
        out += capped(lines)
    if ch.get("moved"):
        one = len(ch["moved"]) == 1
        out.append(f"**Moved or renamed ({len(ch['moved'])}):** "
                   f"{'the same finding' if one else 'same findings'} in a renamed "
                   "or moved file, so not counted as new or gone.")
        out += capped([f"  - {f['id']} `{f['file']}` line {f['line']} (was `{was}`)"
                       for f, was in ch["moved"]])
    if ch["fixed"] or ch["fixed_deps"] or ch["gone_secrets"]:
        total = len(ch["fixed"]) + len(ch["fixed_deps"]) + len(ch["gone_secrets"])
        out.append(f"**Gone since last time ({total}):**")
        lines = [f"  - {i['id']} `{i['file']}` (was line {i['line']})" for i in ch["fixed"]]
        lines += [f"  - possible secret {fp.split('|')[0]} `{fp.split('|')[1]}` "
                  "(no longer found — if it was real, it still needed rotating)"
                  for fp in ch["gone_secrets"]]
        lines += [f"  - dependency `{d.split('|')[1]}`: {d.split('|')[2]} (`{d.split('|')[0]}`)"
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
    m = len(ch.get("moved") or [])
    return f"{n} new, {g} gone" + (f", {m} moved" if m else "") + " since last scan"


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


def merge_copies(code, root):
    """Files with identical content are listed once. Real case: OXX-Terminal
    had glitch_hunter.py and claude/misc/glitch_hunter.py (and more copies),
    so every finding counted twice. The kept path is the shortest one; the
    others go in f["copies"]. Returns (kept findings, number of copy files)."""
    digests = {}
    for path in {f["file"] for f in code}:
        try:
            data = (Path(root) / path).read_bytes()
        except OSError:
            continue
        digests.setdefault(hashlib.sha256(data).hexdigest(), []).append(path)
    keep_of = {}
    for paths in digests.values():
        if len(paths) > 1:
            # keep a copy in real code over one in a test file, then the shortest
            paths.sort(key=lambda p: (is_test_file(p), len(Path(p).parts), len(p), p))
            for p in paths[1:]:
                keep_of[p] = paths[0]
    if not keep_of:
        return code, 0
    others = {}
    for p, k in keep_of.items():
        others.setdefault(k, []).append(p)
    kept = []
    for f in code:
        if f["file"] in keep_of:
            continue
        if f["file"] in others:
            f = dict(f, copies=sorted(others[f["file"]]))
        kept.append(f)
    return kept, len(keep_of)


def where_lines(findings):
    """One line per file: 'path — lines 3, 9, 12 (+4 more)'."""
    per_file, notes = {}, {}
    for f in findings:
        per_file.setdefault(f["file"], []).append(f["line"])
        note = line_note(f)
        if note:
            notes[(f["file"], f["line"])] = note
    out = []
    for path, lines in sorted(per_file.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines = sorted(set(lines))
        shown = ", ".join(str(n) + (f" ({notes[(path, n)]})" if (path, n) in notes else "")
                          for n in lines[:MAX_LINES_SHOWN])
        extra = len(lines) - MAX_LINES_SHOWN
        label = "line" if len(lines) == 1 else "lines"
        tag = " — test file, often harmless there" if is_test_file(path) else ""
        copies = next((f.get("copies") for f in findings if f["file"] == path and f.get("copies")), None)
        if copies:
            tag += (" — same file also at " + ", ".join(f"`{c}`" for c in copies[:2])
                    + (f" and {len(copies) - 2} more" if len(copies) > 2 else ""))
        out.append(f"  - `{path}` — {label} {shown}" + (f" (+{extra} more)" if extra > 0 else "") + tag)
    return out


def headline(shown, hidden, deps, skipped=None, deps_checked=True, secrets=None,
             unsound=0, code_checked=True, n_invalid=0, deps_partly=False):
    """code_checked: True, False, or "partly" (bandit skipped some files).
    deps_partly: some dependency files (an unlocked package.json) weren't checked.
    n_invalid: files that aren't valid Python (so not checked, and can't run)."""
    urgent = sum(1 for f in shown if f["severity"] in ("HIGH", "MEDIUM"))
    high = sum(1 for f in shown if f["severity"] == "HIGH")
    low = len(shown) - urgent
    serious = sum(1 for d in deps if d.get("severity") in ("CRITICAL", "HIGH"))
    test_only = sum(1 for d in deps if d.get("ships") is False)
    dep_part = (f"{len(deps)} risky dependenc{'y' if len(deps) == 1 else 'ies'}"
                + (f" ({', '.join(x for x in [f'{serious} high/critical' if serious else '', f'{test_only} test-only' if test_only else ''] if x)})"
                   if serious or test_only else "")
                + (f" + {unsound} unsound" if unsound else "")
                + (" · some dependency files NOT CHECKED" if deps_partly else "")
                if deps_checked else "dependencies NOT CHECKED")
    parts = []
    if secrets is not None:          # None = secrets feature not in this report
        if secrets == "not-checked":
            parts.append("secrets NOT CHECKED")
        else:
            likely = sum(1 for f in secrets if plays_down(f.get("hint")))
            parts.append(f"{len(secrets)} possible secret{'s' if len(secrets) != 1 else ''}"
                         + (f" ({likely} named like IDs/hashes)" if likely else ""))
    parts.append(dep_part)
    if code_checked is False:
        parts.append("code NOT CHECKED")
    else:
        parts += [f"{urgent} to fix first" + (f" ({high} high)" if high else ""),
                  f"{low} low-priority"]
        if n_invalid:
            parts.append(f"{n_invalid} invalid Python file{'s' if n_invalid != 1 else ''} "
                         "not checked")
        if code_checked == "partly":
            parts.append("some code files NOT CHECKED")
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
                 secrets=None, secrets_info=None, dep_info=None, root=None, n_copies=0,
                 remote=None, code_partly=False, n_invalid=0):
    """secrets: None = not part of this report; "not-checked"; or a list.
    root: the scanned folder; when given, the report says paths start there.
    remote: a parse_repo_url() dict (+ commit, branch, settings) for a scan
    by address; root is then where the reader's own copy is expected."""
    deps_failed = any(e.startswith("dependency scan") for e in errors)
    code_failed = any(e.startswith("code scan") for e in errors)
    shown, hidden = split_findings(code, show_all)
    urgent = [f for f in shown if f["severity"] in ("HIGH", "MEDIUM")]
    low = [f for f in shown if f["severity"] not in ("HIGH", "MEDIUM")]

    n_unsound = sum(1 for n in (dep_info or {}).get("notices") or []
                    if n.get("kind") != "unmaintained")
    head = headline(shown, hidden, deps, skipped, not deps_failed, secrets, n_unsound,
                    False if code_failed else "partly" if code_partly else True,
                    0 if code_failed else n_invalid,
                    deps_partly=bool((dep_info or {}).get("unlocked_npm")))
    if changes:
        head += " · " + changes_headline(changes)
    out = [f"# Security report: {name}", "", f"**{head}**", ""]
    if remote:
        out += remote_intro(remote, root)
    elif root is not None:
        out += [f"File paths below start from `{display_path(root)}`. To open one, "
                f"first run `cd {shell_path(root)}`.", ""]
    if n_copies:
        out += [f"{n_copies} file{'s are exact copies' if n_copies != 1 else ' is an exact copy'} "
                "of another file here, so their findings are listed once "
                "(look for \"same file also at\"). Fixing one copy doesn't fix the others.", ""]
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
        out.append("These checks are expected inside tests and test checkers like "
                   "`verify.py` (they use `assert` on purpose, fake passwords, temp files "
                   "with loose permissions). Run with `--all` to list them.")
        counts = {}
        for f in hidden:
            counts[f["id"]] = counts.get(f["id"], 0) + 1
        for tid, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            out.append(f"- {tid}: {n}")
        out.append("")

    dep_skipped = (dep_info or {}).get("skipped") or {}
    unlocked_skipped = (dep_info or {}).get("unlocked_skipped") or {}
    if skipped or unused or dep_skipped or unlocked_skipped:
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
        for pat, files in unlocked_skipped.items():
            out.append(f"- `{pat}` — " + ", ".join(f"`{f}`" for f in files)
                       + " (lists dependencies, no lock file: not checked)")
        for pat in unused or []:
            out.append(f"- `{pat}` — matched nothing. Typo, or the path moved?")
        out.append("")
    return "\n".join(out)


def remote_intro(remote, root):
    """The scanned copy is gone when the report is read, so every printed
    command points at the reader's own copy, and says how to get one."""
    what = ", ".join(x for x in (f"branch `{remote['branch']}`" if remote.get("branch") else "",
                                 f"commit `{remote['commit'][:12]}`" if remote.get("commit") else "")
                     if x)
    branch = f"--branch {remote['ref']} " if remote.get("ref") else ""
    out = [f"Scanned `{remote['shown']}`" + (f" ({what})" if what else "")
           + " from a temporary copy that was deleted after the scan. File paths below "
           "start from the top of the repository.",
           "",
           f"Commands below expect your own copy at `{display_path(root)}`. If you don't "
           f"have one: `git clone {branch}{remote['shown']} {shell_path(root)}`. "
           "If yours is somewhere else, change that part of the command.", ""]
    if remote.get("web") and remote.get("commit"):
        out += [f"To look at a file in your browser instead: "
                f"{remote['web']}/blob/{remote['commit'][:12]}/ followed by its path.", ""]
    if remote.get("settings"):
        out += ["This repository has its own scanner settings ("
                + ", ".join(f"`{s}`" for s in remote["settings"])
                + "), and they were used. Settings can switch checks off: fine in your "
                "own repository, but in one you don't trust, read them first.", ""]
    return out


def render_secrets(secrets, info, root=None):
    out = ["## 0. Possible secrets (check these first)"]
    if secrets == "not-checked":
        return out + ["NOT CHECKED (see warning above). This is not an all-clear.", ""]
    where = ("git history (every committed version; files never committed aren't included)"
             if info.get("history") else "the files as they are now (not a git repo)")
    out.append(f"Scanned: {where}. Secrets are never printed here.")
    note = old_gitleaks_note(info)
    if note:
        out.append(note)
    if not secrets:
        return out + ["No secrets found.", ""]
    if info.get("history"):
        # Real case (test_keys): the AWS key was at `keys` line 4 in fbc14303;
        # today's `keys` has an empty line 4. The number belongs to that commit.
        out.append("Line numbers are from the commit named for each place; the file may "
                   "have changed since, so today's version can show something else there.")
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
        # Same file + commit + notes → one bullet and one check command.
        # Real case: OXX-Terminal listed kalshi/openapi.yaml 12 times.
        groups = {}
        for f in items:
            key = (f["file"], f["commit"], f["still_there"], f["in_test"], f.get("hint"),
                   bool(f.get("generic")))
            groups.setdefault(key, []).append(f)
        for group in groups.values():
            f = group[0]
            lines = sorted(g["line"] for g in group)
            if len(lines) == 1:
                bits = [f"`{f['file']}` line {lines[0]}"]
            else:
                bits = [f"`{f['file']}` — {len(lines)} places (lines "
                        + ", ".join(str(n) for n in lines[:MAX_LINES_SHOWN])
                        + (f" +{len(lines) - MAX_LINES_SHOWN} more" if len(lines) > MAX_LINES_SHOWN else "")
                        + ")"]
            if f["commit"]:
                bits.append(f"first committed in {f['commit']}" + (f" ({f['date']})" if f["date"] else ""))
                if not f["still_there"]:
                    bits.append("file no longer exists, but it's still in history")
            if f["in_test"]:
                bits.append("test file: probably a fake value, but check")
            if f.get("hint"):
                bits.append(f["hint"] + (" (all of them)" if len(lines) > 1 else ""))
            out.append("  - " + " — ".join(bits))
            if f.get("generic"):
                out.append(f"    - check: `{view_command(dict(f, line=lines), root)}`")
    return out + [""]


def what_it_means(d):
    """One line, or one line per issue when they're about different things.
    Real cases: anyio had 2 issues and only the first was explained; idna's
    only text was the package's own description."""
    issues = d.get("issues") or [(d["ids"][0] if d.get("ids") else "?", d.get("summary", ""), None)]
    distinct = []
    for label, summary, osv_id in issues:
        if summary not in [x[1] for x in distinct]:
            distinct.append((label, summary, osv_id))
    def text(summary, osv_id):
        return summary or ("No short description was published"
                           + (f"; details: {advisory_link(osv_id)}" if osv_id else ""))
    if len(distinct) == 1:
        label, summary, osv_id = distinct[0]
        return [f"  - What it means: {text(summary, osv_id)}"]
    out = [f"  - What it means ({len(distinct)} different issues):"]
    for label, summary, osv_id in distinct[:4]:
        out.append(f"    - {label}: {text(summary, osv_id)}")
    if len(distinct) > 4:
        out.append(f"    - …and {len(distinct) - 4} more")
    return out


_ARCHIVE_DIR = re.compile(r"^_?(archive[sd]?|old|backups?|deprecated|legacy|attic)$", re.I)


def archive_hint(src):
    """Real case: trinity_master's _archive/subdirs/android/requirements.txt
    got upgrade advice for code that's no longer used."""
    parts = Path(src).parts[:-1]
    for i, part in enumerate(parts):
        if _ARCHIVE_DIR.match(part):
            folder = "/".join(parts[:i + 1]) + "/"
            return (f"This file is in an archive-looking folder (`{folder}`). If you don't "
                    f"use that code any more, add the line `{folder}` to a `.plainsec` file "
                    "in the project to skip it.")
    return ""


def test_only_heading(n):
    return [f"#### Used only by tests / dev tools ({n}): lower priority",
            "These come in only through dev-dependencies, so they aren't built into "
            "your program."]


def npm_audit_note(src, items, root=None):
    """Once per npm lock file with pulled-in packages (real case: NodeGoat said it
    117 times, once per entry). Verified on NodeGoat: only package-lock.json changed,
    no node_modules; 131 → 82 risky on rescan. npm 12 (Termux 12.2.3) refused that
    old lock first with EALLOWREMOTE (URL-style entries; allow-remote=none is npm
    12's default); --allow-remote=all got past it. Only npm's own lock files: for
    yarn / pnpm / bun locks the command would edit a file the project doesn't use."""
    if Path(src).name not in ("package-lock.json", "npm-shrinkwrap.json"):
        return None
    if not any(d.get("ecosystem") == "npm" and d.get("direct") is False for d in items):
        return None
    folder = str(Path(src).parent)
    cd = _run_in(root, folder) or ""
    loc = "" if folder in ("", ".") or cd else f" in `{folder}`"
    return (f"For the packages below that your package.json doesn't list, "
            f"`{cd}npm audit fix --package-lock-only`{loc} updates the ones it safely can "
            f"in `{Path(src).name}` without installing anything (it sends your package "
            "list to npm's servers). npm 12 or newer may refuse an old lock file that "
            "lists packages by web address (error EALLOWREMOTE); adding "
            "`--allow-remote=all` lets it go on, but then npm downloads from those "
            "addresses, so look at them in the lock file first.")


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
        # Real case (LipStickFighting): "every dependency file" sat right above
        # "NOT CHECKED: server/package.json".
        out.append("Checked with osv-scanner: every dependency file in the project"
                   + (", except the ones marked NOT CHECKED below." if info.get("unlocked_npm")
                      else "."))
        if info.get("no_deps_declared"):
            return out + [", ".join(f"`{f}`" for f in info["no_deps_declared"])
                          + " declares no dependencies, so there was nothing to check.", ""]
        if info.get("no_sources"):
            if info.get("unlocked_skipped"):
                return out + ["Nothing to check outside the paths your .plainsec skips "
                              "(see section 5).", ""]
            return out + ["No dependency files found, so there was nothing to check.", ""]
    else:
        out.append("Checked with pip-audit: the top-level requirements.txt only. "
                   "Install osv-scanner to check every dependency file (Rust, Node, "
                   "subfolders too).")
    if info.get("cargo_checked"):
        out.append("Rust crates were checked with `cargo tree`, so crates used only by "
                   "tests are listed separately.")
    elif info.get("cargo_missing"):
        # Belongs to cargo_checked. v0.1.18 inserted the NO SCORE note between the two,
        # which hung this elif on it: a report with any unscored advisory never said
        # to install cargo.
        out.append("Install Rust's `cargo` (or fix `cargo tree` in that folder) to tell "
                   "test-only crates apart from ones that ship in your program.")
    every = deps + [n for n in info.get("notices") or [] if n.get("kind") != "unmaintained"]
    if any(d.get("via") for d in every):
        out.append("When a crate comes in through another one, updating that one is the "
                   "fix. If even its newest version still uses the old crate, there's "
                   "nothing to do on your side but wait for its authors.")
    if any(d.get("severity") == "NO SCORE" for d in deps):
        out.append("\"No severity score\" means the advisory wasn't given a rating. It "
                   "doesn't mean harmless: read what it means and decide.")
    for f in info.get("unlocked_npm") or []:
        out.append("NOT CHECKED: " + unlocked_message([f], root))
    if not deps:
        out.append("No known vulnerabilities in your dependencies."
                   + (" (in the files that were checked)" if info.get("unlocked_npm") else ""))
    by_src = {}
    for d in deps:
        by_src.setdefault(d.get("source", "requirements.txt"), []).append(d)
    def one_package(d, grouped):
        sev = (" · no severity score" if d.get("severity") == "NO SCORE"
               else f" · {d['severity']}" if d.get("severity") else "")
        if not grouped:
            sev += " · ships in your program" if d.get("ships") else ""
        n = len(d["ids"])
        lines = [f"- **{d['name']} {d['version']}**{sev} · {n} issue{'s' if n != 1 else ''} "
                 f"({', '.join(d['ids'][:4])}{', …' if n > 4 else ''})"]
        lines += what_it_means(d)
        if d.get("fix_to"):
            lines.append(f"  - Fixed in: {fix_text(d['fix_to'], d.get('ecosystem'))}"
                         + (f" (no fix yet for {', '.join(d['no_fix'])})" if d.get("no_fix") else ""))
        lines.append(f"  - How: {dep_how(d, root, grouped)}")
        return lines

    for src, items in by_src.items():
        eco = ECOSYSTEM_NAME.get(items[0].get("ecosystem"), items[0].get("ecosystem", ""))
        out.append(f"### `{src}` ({eco}) · {len(items)} package{'s' if len(items) != 1 else ''}")
        hint = archive_hint(src)
        if hint:
            out.append(hint)
        note = npm_audit_note(src, items, root)
        if note:
            out.append(note)
        ships = [d for d in items if d.get("ships") is not False]
        tests = [d for d in items if d.get("ships") is False]
        for d in ships:
            out += one_package(d, False)
        if tests:
            out += test_only_heading(len(tests))
            for d in tests:
                out += one_package(d, True)
    notices = info.get("notices") or []
    unsound = [n for n in notices if n.get("kind") != "unmaintained"]
    unmaint = [n for n in notices if n.get("kind") == "unmaintained"]
    if unsound:
        out.append(f"### Unsound code ({len(unsound)}): no known attack, but not safe")
        out.append("\"Unsound\" means the code can break Rust's memory-safety guarantees "
                   "if it's used in certain ways. No real attack is known, so it isn't "
                   "scored as a vulnerability, but it's worth fixing when a fix exists.")
        def one_notice(d, grouped):
            kind = "" if d.get("kind") in ("unsound", "") else f" [{d['kind']}]"
            if not grouped:
                kind += " · ships in your program" if d.get("ships") else ""
            lines = [f"- **{d['name']} {d['version']}**{kind} (`{d['source']}`): "
                     f"{d['summary'] or d['ids'][0]}"]
            if d.get("fix_to"):
                lines.append(f"  - Fixed in: {fix_text(d['fix_to'], d.get('ecosystem'))}")
            lines.append(f"  - How: {dep_how(d, root, grouped)}")
            return lines
        tests = [d for d in unsound if d.get("ships") is False]
        for d in unsound:
            if d.get("ships") is not False:
                out += one_notice(d, False)
        if tests:
            out += test_only_heading(len(tests))
            for d in tests:
                out += one_notice(d, True)
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


def unlocked_message(files, root):
    """Why an unlocked package.json wasn't checked, and the command that fixes it
    without installing anything (`--package-lock-only` writes only the lock;
    verified on react_step_form: lock written, no node_modules)."""
    parts = []
    for f in files:
        folder = str(Path(f).parent)
        here = Path(root) / folder if root is not None else None
        cd = f"cd {shell_path(here)} && " if here is not None else ""
        where = "" if here is not None or folder in ("", ".") else f" in `{folder}`"
        parts.append(f"`{f}` lists dependencies but has no lock file, so the exact versions "
                     "aren't known and nothing in it was checked (osv-scanner checks lock "
                     f"files). Make one without installing anything: `{cd}npm install "
                     f"--package-lock-only`{where}, then run plainsec again.")
    return " ".join(parts)


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Scanning a repository by its address (downloaded to a temp folder, deleted after)
# ---------------------------------------------------------------------------
_NO_SCHEME_HOSTS = ("github.com/", "gitlab.com/", "codeberg.org/", "bitbucket.org/")
_HOST = r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
_REPO_PATH = r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*"


def looks_like_url(text):
    return "://" in text or "::" in text or bool(re.match(rf"^[\w.-]+@{_HOST}:", text)) or \
        text.lower().startswith(_NO_SCHEME_HOSTS)


def parse_repo_url(text):
    """A repo address → {"url": what git clones, "shown": the address without
    any login in it, "key": identity for "since last scan", "name": folder
    name, "ref": branch/tag from a /tree/ link or None, "web": GitHub page or
    None}. None if it isn't an https:// or ssh address plainsec accepts.
    Only https and ssh: git also takes ext:: and file:// addresses, which
    can run commands or read local files."""
    t = text.strip()
    if t.lower().startswith(_NO_SCHEME_HOSTS):
        t = "https://" + t
    m = re.match(rf"^https://([^@/\s]+@)?({_HOST})(:\d+)?/({_REPO_PATH})/*$", t)
    login = ""
    if m:
        login, host, port, path = m.group(1) or "", m.group(2).lower(), m.group(3) or "", m.group(4)
        login_free = f"https://{host}{port}/"
    else:
        m = (re.match(rf"^ssh://([\w.-]+@)?({_HOST})(:\d+)?/({_REPO_PATH})/*$", t) or
             re.match(rf"^()([\w.-]+@{_HOST}):({_REPO_PATH})/*$", t))
        if not m:
            return None
        if t.startswith("ssh://"):
            user, host, port, path = m.group(1) or "", m.group(2).lower(), m.group(3) or "", m.group(4)
            login_free = f"ssh://{user}{host}{port}/"
        else:                                   # git@github.com:owner/repo
            user_host, path = m.group(2), m.group(3)
            host, port = user_host.split("@", 1)[1].lower(), ""
            login_free = f"{user_host}:"
    parts = path.split("/")
    ref, web = None, None
    if "-" in parts:                            # GitLab: group/repo/-/tree/main
        i = parts.index("-")
        if parts[i + 1:i + 2] == ["tree"] and len(parts) > i + 2:
            ref = "/".join(parts[i + 2:])
        parts = parts[:i]
    if host == "github.com":
        if len(parts) < 2:
            return None
        if len(parts) > 3 and parts[2] == "tree":
            ref = "/".join(parts[3:])
        parts = parts[:2]
    if any(p in (".", "..") for p in parts):
        return None
    clone_path = "/".join(parts)                # as given (some servers need the .git)
    if parts and parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]
    if not parts or not parts[-1]:
        return None
    repo = "/".join(parts)
    if host == "github.com":
        web = f"https://github.com/{repo}"
    shown = login_free + repo
    url = (login_free.replace("https://", "https://" + login, 1) if login else login_free) + clone_path
    # https and ssh addresses of the same repo share their scan history
    base_key = f"{host}/{repo.lower() if host == 'github.com' else repo}"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", parts[-1]).lstrip(".") or "repo"
    info = {"url": url, "shown": shown, "base_key": base_key, "name": name, "web": web}
    set_ref(info, ref)
    return info


def set_ref(info, ref):
    info["ref"] = ref
    info["key"] = info["base_key"] + (f"#{ref}" if ref else "")


def _git_env():
    # no password prompt (a typo'd GitHub address asks for one and waits),
    # no Git LFS downloads (big files, not needed for the scan)
    return dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")


GIT_ERRORS = (   # (git's words, plain English); real messages, checked Nov 23
    ("host key verification failed",
     "this device's SSH doesn't know that server yet. Use the https:// address, or run "
     "`ssh -T git@github.com` once and answer yes"),
    ("permission denied (publickey)",
     "the server didn't accept your SSH key (none set up here, or not added to your account)"),
    ("repository not found",
     "the repository doesn't exist, or it's private (GitHub answers the same for both)"),
    ("could not read username",
     "the server wants a login, so the repository is probably private"),
    ("authentication failed", "your login was refused"),
    ("remote branch", "there's no branch or tag with that name"),
    ("could not resolve host", "no internet connection, or the server name is misspelled"),
)


def _git_error(proc, info):
    """git's message up to its first fatal: line (the last line was useless in a
    real case: "and the repository exists."), led by a plain-English reason."""
    lines = [l.strip() for l in (proc.stderr or proc.stdout or "").splitlines() if l.strip()]
    kept = []
    for l in lines:
        kept.append(l)
        if l.lower().startswith("fatal:"):
            break
    msg = " ".join(kept) or "git failed"
    plain = next((p for k, p in GIT_ERRORS if k in msg.lower()), None)
    msg = f"{plain} (git said: {msg})" if plain else msg
    return msg.replace(info["url"], info["shown"])          # never print a login


def resolve_ref(info):
    """A /tree/ link can go on into folders (tree/main/src/app), and branch
    names can have slashes too (tree/feature/x). The longest start of it that
    is a real branch or tag wins. -> (ref, folder part or "", error)."""
    ref = info["ref"]
    if not ref or "/" not in ref:
        return ref, "", None
    proc = subprocess.run(["git", "ls-remote", "--heads", "--tags", "--", info["url"]],
                          capture_output=True, text=True, env=_git_env(),
                          timeout=120)  # list form, no shell
    if proc.returncode != 0:
        return None, "", _git_error(proc, info)
    names = {l.split("\t", 1)[1].split("/", 2)[2].removesuffix("^{}")
             for l in proc.stdout.splitlines() if "\t" in l and l.count("/") >= 2}
    parts = ref.split("/")
    for n in range(len(parts), 0, -1):
        if "/".join(parts[:n]) in names:
            return "/".join(parts[:n]), "/".join(parts[n:]), None
    return ref, "", None                        # let clone say it's not found


def clone_repo(info, dest):
    """Full clone (gitleaks needs every commit) of info["url"] into dest.
    Symlinks are checked out as plain files, so a link in the repo can't make
    the scanners read files outside it. -> (commit, branch, error)."""
    if shutil.which("git") is None:
        return None, None, "git is not installed (Ubuntu/Debian: `sudo apt install git`)"
    try:
        ref, folder, err = resolve_ref(info)
        if err:
            return None, None, err
        if folder:
            print(f"Note: scanning the whole repository, not just `{folder}`.", file=sys.stderr)
            set_ref(info, ref)       # history and the printed clone command use the branch
        cmd = ["git", "clone", "--quiet", "--config", "core.symlinks=false"]
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", info["url"], str(dest)]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=_git_env())  # list form, no shell
        if proc.returncode != 0:
            return None, None, _git_error(proc, info)
        commit = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                                capture_output=True, text=True).stdout.strip()
        branch = ref or subprocess.run(["git", "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"],
                                       capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, None, f"git couldn't run ({getattr(e, 'strerror', None) or e})"
    return commit, (branch if branch and branch != "HEAD" else None), None


CLONE_HINT = ("Check the address. If the repository is private, git needs your login: "
              "the git@… address works once you've set up an SSH key, or download it "
              "yourself (`git clone …`) and scan the folder.")


TEMP_PREFIX = "plainsec-"
OWNER_FILE = ".plainsec-owner"           # holds the pid of the scan using the copy
_TEMP_NAME = re.compile(r"^plainsec-[A-Za-z0-9_]{8}$")    # mkdtemp's 8 random characters
STALE_SECONDS = 24 * 3600


def exit_on_termination():
    """Turn SIGTERM (`kill`) and SIGHUP (terminal / Termux session closed)
    into a normal exit, so the temp copy's `finally` cleanup runs. Python's
    default ends without it: a scan stopped this way (Nov 23) left 122 MB in
    Termux's tmp. Ctrl-C already ran it. -> a function that puts the old
    handlers back."""
    import signal
    def stop(signum, frame):
        raise SystemExit(128 + signum)
    old = {}
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:                   # no SIGHUP on Windows
            continue
        try:
            old[sig] = signal.signal(sig, stop)
        except (ValueError, OSError):     # not the main thread
            pass
    def restore():
        for sig, handler in old.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
    return restore


def _pid_alive(pid):
    """None when it can't be told safely. On Windows os.kill(pid, 0) would
    END that process, so it's never called there."""
    if os.name == "nt":
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:                       # exists, owned by someone else
        return True
    return True


def sweep_leftover_copies(base=None, now=None):
    """Delete temp copies whose scan was killed too hard for any cleanup to
    run (kill -9, power loss). A copy is removed only when the scan that made
    it is gone: its owner pid isn't running, or it's over a day old (no owner
    file, made before v0.2.2, or no safe way to check the pid, as on Windows).
    So two scans running at once never delete each other's copy. Only
    plainsec-XXXXXXXX folders that are real folders (not links) and yours.
    -> how many were removed."""
    import time
    base = Path(base or tempfile.gettempdir())
    now = time.time() if now is None else now
    removed = 0
    try:
        entries = list(base.iterdir())
    except OSError:
        return 0
    for d in entries:
        if not _TEMP_NAME.match(d.name):
            continue
        try:
            st = os.lstat(d)
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode):              # a link is never followed
            continue
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            continue
        try:
            pid = int((d / OWNER_FILE).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pid = None
        # Over a day old counts as gone even if its pid runs: the pid may have
        # been reused by another program, and no scan takes a day.
        gone = (now - st.st_mtime > STALE_SECONDS or
                (pid is not None and _pid_alive(pid) is False))
        if gone and remove_tree(d):
            removed += 1
    return removed


def remove_tree(path):
    """Delete the temp copy. git makes some files read-only (on Windows that
    stops rmtree), so those are made writable and tried again."""
    def retry(func, p, *_):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=retry)
        else:
            shutil.rmtree(path, onerror=retry)
    except OSError:
        return False
    return not Path(path).exists()


# Files in a repo that change what the scanners report. Fine in your own repo;
# in a stranger's they can switch checks off, so a URL scan names them.
REPO_SETTINGS = (".plainsec", "bandit.yaml", ".gitleaks.toml", ".gitleaksignore", "osv-scanner.toml")


def repo_settings(folder):
    found = [n for n in REPO_SETTINGS if (Path(folder) / n).is_file()]
    for p in Path(folder).rglob("osv-scanner.toml"):
        rel = p.relative_to(folder).as_posix()
        if ".git" not in p.relative_to(folder).parts and rel not in found:
            found.append(rel)
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("folder", nargs="?", default=".",
                    help="project folder to scan, or a repository address "
                         "(https://github.com/owner/repo or git@…): it's downloaded "
                         "to a temporary folder, scanned, and deleted")
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

    # A folder that exists always wins (a folder can be named github.com).
    if Path(args.folder).expanduser().exists():
        return scan(Path(args.folder).expanduser(), args)
    if not looks_like_url(args.folder):
        # used to scan nothing and print a whole report of NOT CHECKED parts
        print(f"plainsec: there's no folder `{args.folder}` here. Give a project folder "
              "(like ~/my-project) or a repository address "
              "(like https://github.com/owner/repo).", file=sys.stderr)
        return 2
    remote = parse_repo_url(args.folder)
    if remote is None:
        print("plainsec: that address isn't one plainsec can download. Use an https:// "
              "address (like https://github.com/owner/repo) or an SSH one "
              "(git@github.com:owner/repo).", file=sys.stderr)
        return 2
    swept = sweep_leftover_copies()
    if swept:
        print(f"Removed {swept} temporary cop{'y' if swept == 1 else 'ies'} left by "
              "earlier scans that were stopped.", file=sys.stderr)
    print(f"Downloading {remote['shown']} with its full history (old commits are "
          "checked for secrets too)…", file=sys.stderr)
    tmp = tempfile.mkdtemp(prefix=TEMP_PREFIX)
    (Path(tmp) / OWNER_FILE).write_text(str(os.getpid()), encoding="utf-8")
    restore = exit_on_termination()
    try:
        dest = Path(tmp) / remote["name"]
        commit, branch, err = clone_repo(remote, dest)
        if err:
            # Real case: offline phone ("Could not resolve host") also got the
            # private-repository hint. That hint only helps a not-found / login error.
            offline = err.startswith("no internet connection")
            print(f"plainsec: couldn't download {remote['shown']}: {err}"
                  + ("" if offline else f"\n{CLONE_HINT}"),
                  file=sys.stderr)
            return 2
        remote.update(commit=commit, branch=branch, settings=repo_settings(dest))
        return scan(dest, args, remote)
    finally:
        if not remove_tree(tmp):
            print(f"Note: couldn't fully delete the temporary copy at {tmp}; "
                  "you can delete that folder yourself.", file=sys.stderr)
        restore()


def scan(folder, args, remote=None):
    """remote: set when folder is a temp copy of a repo address (see main)."""
    errors = []
    # A URL scan's printed commands point at the reader's own copy (~/<repo>);
    # the temp copy is deleted before anyone reads the report.
    shown_root = Path.home() / remote["name"] if remote else folder

    if args.bandit_json:
        bandit_data, err = load_json(args.bandit_json), None
    else:
        bandit_data, err = scan_code(folder)
    unread = bandit_unread(None if err else bandit_data, folder)
    if unread["all"]:
        err = unread_warnings(unread)[0][-1]
    # Files bandit skipped although Python can read them: their findings are
    # missing, so code history isn't compared (missing must not read as "gone").
    # Invalid-Python files don't block history: they keep their old entries.
    code_partial = bool(unread["other"]) and not unread["all"]
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
        npm_cache = {}
        for d in deps + dep_info["notices"]:
            if d["ecosystem"] == "npm":
                src = d["source"]
                if src not in npm_cache:
                    npm_cache[src] = npm_direct_deps(folder, src)
                if npm_cache[src] is not None:
                    d["direct"] = d["name"] in npm_cache[src]
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
        unlocked = (osv_data or {}).get("unlocked_npm") or []
        # .plainsec applies here too, like it does to dependency files (counted in
        # section 5, not reported as NOT CHECKED); --all ignores it as usual.
        skip_pats = [] if args.all else load_ignore(folder)
        unlocked_skipped = {}
        for f in list(unlocked):
            hit = next((pt for pt in skip_pats if path_matches(f, pt)), None)
            if hit:
                unlocked_skipped.setdefault(hit, []).append(f)
                unlocked.remove(f)
        dep_info["unlocked_skipped"] = unlocked_skipped
        if unlocked:
            msg = unlocked_message(unlocked, shown_root)
            if dep_info["no_sources"]:
                # nothing else was checked: the whole section is NOT CHECKED,
                # never "0 risky dependencies … nothing to check". Not judged by
                # empty "results": osv-scanner 2.4.0 doesn't list a CLEAN lock file
                # there (real case: IBM/graphiql-cost-plugin's clean package-lock.json
                # gave "results": [], and everything was called NOT CHECKED).
                errors.append(f"dependency scan — {msg}")
            else:
                # said once, in section 1 (real case: LipStickFighting showed it twice);
                # the headline says "some dependency files NOT CHECKED"
                dep_info["unlocked_npm"] = unlocked
    else:
        deps = parse_audit(audit_data)
    secrets = parse_gitleaks(secrets_data, root=folder)
    code_ok = not code_partial and not any(e.startswith("code scan") for e in errors)
    deps_ok = not any(e.startswith("dependency scan") for e in errors)
    secrets_ok = not any(e.startswith("secrets scan") for e in errors)

    # Compare ALL findings (before .plainsec / test hiding), so adding an
    # ignore line never looks like a fix.
    spath = state_path(folder, remote["key"] if remote else None)
    old = load_state(spath)
    # History tracks notices too, so moving a package between "risky" and
    # "maintenance notice" is never reported as new or gone.
    deps_history = deps + dep_info.get("notices", [])
    invalid_files = set(unread["invalid"])
    changes = compare(old, code, deps_history, code_ok, deps_ok, secrets, secrets_ok,
                      unread_files=invalid_files)
    changes["saved"] = not args.no_save
    if not args.no_save:
        snap = snapshot(code, deps_history, code_ok, deps_ok, secrets, secrets_ok)
        if snap["code"] is not None and old and old.get("code"):
            # a file that's broken right now keeps what it had, so fixing it
            # later doesn't show its old findings as new
            snap["code"] += [i for i in old["code"] if i.get("file") in invalid_files]
        save_state(spath, snap, old)

    skipped, unused = {}, []
    patterns = [] if args.all else load_ignore(folder)
    lines, n_invalid, other_shown = unread_warnings(unread, patterns)
    if unread["all"]:        # that line is already the "code scan" error
        lines, other_shown = lines[:-1], False
    errors += lines
    if not args.all:
        code, skipped, unused = apply_ignore(code, patterns)
        # dependency files in skipped paths: counted, not detailed
        deps_kept, dep_skipped = [], {}
        for d in deps:
            hit = next((p for p in patterns if path_matches(d.get("source", ""), p)), None)
            (dep_skipped.setdefault(hit, []) if hit else deps_kept).append(d)
        deps, dep_info["skipped"] = deps_kept, dep_skipped
        unread_all = list(unread["invalid"]) + unread["other"]
        unused = [p for p in unused if p not in dep_skipped
                  and p not in (dep_info.get("unlocked_skipped") or {})
                  and not any(path_matches(f, p) for f in unread_all)]
    # After history (which keeps every copy) AND after .plainsec skips: merging
    # first once let the kept copy be a skipped one, so v0.1.12 showed 57
    # skipped instead of 60 (real case). Only shown findings are merged.
    code, n_copies = merge_copies(code, folder)
    skipped_ids = {id(f) for items in skipped.values() for f in items}
    hidden_ids = set() if args.all else {
        id(f) for f in code if f["in_test"] and f["id"] in NORMAL_IN_TESTS}
    title = remote["shown"].split("://", 1)[-1] if remote else folder.resolve().name
    report = build_report(title, code, deps, errors,
                          show_all=args.all, skipped=skipped, unused=unused,
                          changes=changes, hidden_ids=hidden_ids,
                          skipped_ids=skipped_ids,
                          secrets=secrets if secrets_ok else "not-checked",
                          secrets_info=secrets_data or {}, dep_info=dep_info,
                          root=shown_root, n_copies=n_copies, remote=remote,
                          code_partly=other_shown, n_invalid=n_invalid)
    print(report)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Saved to {args.out}", file=sys.stderr)

    # Exit 1 if anything needs attention, so it can gate a git hook later.
    # an unchecked package.json is never "clean", even with nothing else found
    return 1 if (code or deps or secrets or errors or dep_info.get("unlocked_npm")) else 0


if __name__ == "__main__":
    sys.exit(main())
