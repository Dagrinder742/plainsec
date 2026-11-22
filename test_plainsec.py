"""Tests for plainsec. Run: python -m unittest test_plainsec -v

Uses sample JSON shaped like real bandit / pip-audit output, so the tests
run without either tool installed.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import plainsec

_STATE_TMP = None


def setUpModule():
    """Keep every test's scan history in a throwaway folder, never ~/.local/state."""
    global _STATE_TMP
    _STATE_TMP = tempfile.TemporaryDirectory()
    os.environ["PLAINSEC_STATE_DIR"] = _STATE_TMP.name


def tearDownModule():
    os.environ.pop("PLAINSEC_STATE_DIR", None)
    _STATE_TMP.cleanup()

BANDIT_SAMPLE = {
    "errors": [],
    "results": [
        {"filename": "app/util.py", "line_number": 12, "issue_severity": "LOW",
         "issue_confidence": "HIGH", "test_id": "B311",
         "issue_text": "Standard pseudo-random generators are not suitable...",
         "more_info": "https://bandit.readthedocs.io/"},
        {"filename": "app/db.py", "line_number": 40, "issue_severity": "MEDIUM",
         "issue_confidence": "MEDIUM", "test_id": "B608",
         "issue_text": "Possible SQL injection vector.", "more_info": "x"},
        {"filename": "app/run.py", "line_number": 5, "issue_severity": "HIGH",
         "issue_confidence": "HIGH", "test_id": "B602",
         "issue_text": "subprocess call with shell=True", "more_info": "x"},
        {"filename": "app/new.py", "line_number": 1, "issue_severity": "LOW",
         "issue_confidence": "LOW", "test_id": "B999",
         "issue_text": "Some brand new check.", "more_info": "https://ex/b999"},
    ],
}

AUDIT_SAMPLE = {
    "dependencies": [
        {"name": "requests", "version": "2.25.0", "vulns": [
            {"id": "PYSEC-2023-74", "fix_versions": ["2.31.0"], "aliases": [],
             "description": "Requests leaks Proxy-Authorization headers. More text."}]},
        {"name": "jinja2", "version": "2.10", "vulns": [
            {"id": "A", "fix_versions": ["2.11.3"], "description": "x"},
            {"id": "B", "fix_versions": ["3.1.4"], "description": "y"}]},
        {"name": "oldlib", "version": "0.1", "vulns": [
            {"id": "C", "fix_versions": [], "description": ""}]},
        {"name": "clean", "version": "1.0", "vulns": []},
    ],
    "fixes": [],
}


class TestParsing(unittest.TestCase):
    def test_bandit_sorted_high_first(self):
        found = plainsec.parse_bandit(BANDIT_SAMPLE)
        self.assertEqual([f["severity"] for f in found],
                         ["HIGH", "MEDIUM", "LOW", "LOW"])

    def test_known_id_gets_plain_text(self):
        found = plainsec.parse_bandit(BANDIT_SAMPLE)
        sql = next(f for f in found if f["id"] == "B608")
        self.assertIn("placeholders", sql["fix"])

    def test_unknown_id_is_kept_not_dropped(self):
        found = plainsec.parse_bandit(BANDIT_SAMPLE)
        new = next(f for f in found if f["id"] == "B999")
        self.assertEqual(new["meaning"], "Some brand new check.")
        self.assertIn("https://ex/b999", new["fix"])

    def test_audit_skips_clean_and_picks_highest_fix(self):
        deps = plainsec.parse_audit(AUDIT_SAMPLE)
        self.assertEqual([d["name"] for d in deps], ["requests", "jinja2", "oldlib"])
        jinja = next(d for d in deps if d["name"] == "jinja2")
        self.assertEqual(jinja["fix_to"], "3.1.4")
        self.assertIsNone(deps[2]["fix_to"])

    def test_audit_old_list_format(self):
        deps = plainsec.parse_audit(AUDIT_SAMPLE["dependencies"])
        self.assertEqual(len(deps), 3)

    def test_empty_inputs(self):
        self.assertEqual(plainsec.parse_bandit(None), [])
        self.assertEqual(plainsec.parse_audit(None), [])


def finding(tid, path, line, sev="LOW"):
    return {"filename": path, "line_number": line, "issue_severity": sev,
            "test_id": tid, "issue_text": "x", "more_info": "x"}


# Shaped like the first real run on demo-project (Nov 2026).
REAL_PIP = {"dependencies": [{"name": "pip", "version": "26.1.2", "vulns": [
    {"id": "PYSEC-2026-3721", "fix_versions": ["26.2.0"],
     "description": "pip would incorrectly handle doubly-encoded package URLs from "
                    "indexes allowing for files to be installed to arbitrary locations "
                    "on disk even when installing wheels from an index that is trusted "
                    "by the user and more words to push it past the length limit here"},
    {"id": "PYSEC-2026-3721", "fix_versions": ["26.2.0"], "description": "dup"}]}]}


class TestReport(unittest.TestCase):
    def test_headline_counts(self):
        code = plainsec.parse_bandit(BANDIT_SAMPLE)
        deps = plainsec.parse_audit(AUDIT_SAMPLE)
        shown, hidden = plainsec.split_findings(code)
        self.assertEqual(plainsec.headline(shown, hidden, deps),
                         "3 risky dependencies · 2 to fix first (1 high) · 2 low-priority")

    def test_headline_singular_and_hidden(self):
        self.assertEqual(plainsec.headline([], [{}], [{}]),
                         "1 risky dependency · 0 to fix first · 0 low-priority"
                         " · 1 normal-in-tests hidden")

    def test_report_shows_fix_command_and_errors(self):
        report = plainsec.build_report(
            "demo", [], plainsec.parse_audit(AUDIT_SAMPLE), ["code scan — bandit is not installed"])
        self.assertIn("pip install 'requests>=2.31.0'", report)
        self.assertIn("Not checked: code scan", report)
        self.assertIn("no fixed version yet", report)

    def test_failed_scan_is_not_an_all_clear(self):
        report = plainsec.build_report(
            "demo", [], [], ["code scan — bandit is not installed",
                             "dependency scan — pip-audit is not installed"])
        self.assertNotIn("Nothing high", report)
        self.assertNotIn("No known vulnerabilities", report)
        self.assertEqual(report.count("NOT CHECKED"), 3)   # headline + both sections


class TestRealRunFixes(unittest.TestCase):
    """Bugs found in the first real run on demo-project."""

    def test_duplicate_findings_removed(self):
        data = {"results": [finding("B105", "a.py", 58), finding("B105", "a.py", 58)]}
        self.assertEqual(len(plainsec.parse_bandit(data)), 1)

    def test_duplicate_vuln_ids_removed(self):
        self.assertEqual(plainsec.parse_audit(REAL_PIP)[0]["ids"], ["PYSEC-2026-3721"])

    def test_pip_not_told_to_upgrade_itself(self):
        with mock.patch.dict(os.environ, {"PREFIX": "/data/data/com.termux/files/usr"}):
            report = plainsec.build_report("x", [], plainsec.parse_audit(REAL_PIP), [])
        self.assertNotIn("pip install 'pip", report)
        self.assertIn("pkg upgrade python-pip", report)
        self.assertIn("hasn't packaged the fix yet", report)
        self.assertIn("26.2.0", report)

    def test_pip_advice_off_termux(self):
        with mock.patch.dict(os.environ, {"PREFIX": ""}):
            report = plainsec.build_report("x", [], plainsec.parse_audit(REAL_PIP), [])
        self.assertNotIn("Termux", report)
        self.assertIn("python -m pip install --upgrade pip", report)

    def test_docstring_has_no_personal_paths(self):
        import re
        paths = re.findall(r"~/[\w.-]+", plainsec.__doc__)
        self.assertTrue(paths)
        self.assertEqual(set(paths), {"~/my-project"})
        self.assertNotIn("/home/", plainsec.__doc__)

    def test_summary_cut_on_word_boundary(self):
        summary = plainsec.parse_audit(REAL_PIP)[0]["summary"]
        self.assertTrue(summary.endswith("…"))
        self.assertTrue(summary[:-1].split(" ")[-1] in REAL_PIP["dependencies"][0]
                        ["vulns"][0]["description"].split(" "))

    def test_agent_tool_advice(self):
        # Real run: proto.py runs AI-generated commands; "pass a list" alone was wrong advice.
        f = plainsec.parse_bandit({"results": [finding("B602", "a.py", 1, "HIGH"),
                                               finding("B102", "a.py", 2, "MEDIUM")]})
        by_id = {x["id"]: x for x in f}
        self.assertIn("AI model", by_id["B602"]["fix"])
        self.assertIn("allow a fixed set", by_id["B602"]["fix"])
        self.assertIn("NOT a sandbox", by_id["B102"]["meaning"])

    def test_b103_has_plain_text(self):
        f = plainsec.parse_bandit({"results": [finding("B103", "a.py", 1, "MEDIUM")]})[0]
        self.assertIn("permissions", f["meaning"])

    def test_test_files_detected(self):
        yes = ["tests/test_x.py", "sandbox-tool/tests/helpers.py", "claude/test_main_flow.py",
               "a/b_test.py", "conftest.py",
               # checkers: their asserts are the check (OXX-Terminal: ~140 of 163 B101)
               "testkit/verify_skill.py", "sandbox-tool/bench/tasks/stack/verify.py"]
        no = ["src/engine.py", "contest.py", "src/verify_notes.txt", "src/reverify.py"]
        for p in yes:
            self.assertTrue(plainsec.is_test_file(p), p)
        for p in no:
            self.assertFalse(plainsec.is_test_file(p), p)

    def test_normal_test_findings_hidden_but_counted(self):
        code = plainsec.parse_bandit({"results": [
            finding("B101", "test_a.py", 1),          # hidden
            finding("B105", "tests/b.py", 2),         # hidden
            finding("B602", "test_a.py", 3, "HIGH"),  # shell=True: never hidden
            finding("B101", "engine.py", 4),          # not a test file: shown
        ]})
        report = plainsec.build_report("x", code, [], [])
        self.assertIn("B602 · HIGH · 1 place", report)
        self.assertIn("B101 · LOW · 1 place", report)
        self.assertIn("## 4. Hidden", report)
        self.assertIn("- B101: 1", report)
        self.assertIn("- B105: 1", report)

    def test_all_flag_shows_everything(self):
        code = plainsec.parse_bandit({"results": [finding("B101", "test_a.py", 1)]})
        report = plainsec.build_report("x", code, [], [], show_all=True)
        self.assertNotIn("Hidden", report)
        self.assertIn("test_a.py", report)

    def test_grouping_one_block_per_check(self):
        code = plainsec.parse_bandit({"results":
            [finding("B101", "macro_engine.py", n) for n in range(1, 41)]})
        report = plainsec.build_report("x", code, [], [])
        self.assertEqual(report.count("### B101"), 1)
        self.assertEqual(report.count("What it means"), 1)
        self.assertIn("B101 · LOW · 40 places", report)
        self.assertIn("(+32 more)", report)

    def test_high_listed_before_low(self):
        code = plainsec.parse_bandit({"results": [
            finding("B101", "a.py", 1), finding("B602", "b.py", 2, "HIGH")]})
        report = plainsec.build_report("x", code, [], [])
        self.assertLess(report.index("B602"), report.index("B101"))


class TestIgnoreFile(unittest.TestCase):
    """.plainsec: skip old drafts/copies but never lose count of them."""

    def test_path_matching(self):
        m = plainsec.path_matches
        self.assertTrue(m("tools/termux/proto.py", "tools/"))
        self.assertTrue(m("tools/x.py", "tools"))
        self.assertTrue(m("tools/x.py", "./tools/"))
        self.assertFalse(m("toolsx/a.py", "tools/"))       # no partial-name match
        self.assertTrue(m("cv.py", "cv.py"))
        self.assertFalse(m("a/cv.py", "cv.py"))            # plain names are from the root
        self.assertTrue(m("a/b_old.py", "*_old.py"))       # * crosses folders
        self.assertTrue(m("testkit/misc/v.py", "testkit/*/"))
        self.assertTrue(m("tools\\windows\\x.py", "tools/windows/"))  # Windows paths
        self.assertTrue(m(".github/x.py", ".github/"))     # leading dot kept

    def test_load_ignore_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".plainsec").write_text(
                "# drafts\ntools/   # old copies\n\n  testkit/misc/\n")
            self.assertEqual(plainsec.load_ignore(tmp), ["tools/", "testkit/misc/"])
            self.assertEqual(plainsec.load_ignore(Path(tmp, "nope")), [])

    def test_skipped_are_counted_high_called_out_typos_flagged(self):
        code = plainsec.parse_bandit({"results": [
            finding("B602", "tools/termux/proto.py", 51, "HIGH"),
            finding("B102", "tools/termux/proto.py", 39, "MEDIUM"),
            finding("B110", "sandbox-tool/src/s.py", 765),
        ]})
        kept, skipped, unused = plainsec.apply_ignore(code, ["tools/", "toolz/"])
        self.assertEqual([f["file"] for f in kept], ["sandbox-tool/src/s.py"])
        self.assertEqual(len(skipped["tools/"]), 2)
        self.assertEqual(unused, ["toolz/"])
        report = plainsec.build_report("x", kept, [], [], skipped=skipped, unused=unused)
        self.assertIn("2 skipped by .plainsec (incl. 1 HIGH)", report)
        self.assertIn("`tools/` — 2 findings (1 high, 1 medium)", report)
        self.assertIn("includes HIGH", report)
        self.assertIn("`toolz/` — matched nothing", report)
        self.assertNotIn("proto.py", report)          # details really skipped
        self.assertIn("0 to fix first", report)

    def test_cli_reads_file_and_all_overrides(self):
        data = {"results": [finding("B602", "tools/p.py", 1, "HIGH")]}
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".plainsec").write_text("tools/\n")
            b = Path(tmp, "b.json"); b.write_text(json.dumps(data))
            a = Path(tmp, "a.json"); a.write_text('{"dependencies": []}')
            for extra, expect_in, expect_out in [([], "skipped by .plainsec", "B602 · HIGH"),
                                                 (["--all"], "B602 · HIGH", "skipped by")]:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    plainsec.main([tmp, "--bandit-json", str(b), "--audit-json", str(a)] + extra)
                self.assertIn(expect_in, out.getvalue(), extra)
                self.assertNotIn(expect_out, out.getvalue(), extra)


class TestNoRequirements(unittest.TestCase):
    """WSL run: no requirements.txt + pipx pip-audit = it audited its own venv
    and reported '0 risky dependencies'. That's a false all-clear."""

    def test_no_requirements_is_not_checked(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(plainsec, "run_tool", side_effect=AssertionError("ran")):
            data, err = plainsec.scan_deps(tmp)
        self.assertIsNone(data)
        self.assertIn("no requirements.txt", err)

    def test_report_says_not_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp, "b.json"); b.write_text('{"results": []}')
            out = io.StringIO()
            only_pip_audit = lambda n: "/x/pip-audit" if n == "pip-audit" else None
            with contextlib.redirect_stdout(out), \
                 mock.patch.object(plainsec.shutil, "which", side_effect=only_pip_audit):
                plainsec.main([tmp, "--bandit-json", str(b)])
        text = out.getvalue()
        self.assertIn("NOT CHECKED", text)
        self.assertNotIn("No known vulnerabilities", text)
        self.assertIn("dependencies NOT CHECKED ·", text.splitlines()[2])
        self.assertNotIn("risky dependenc", text)

    def test_requirements_used_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "requirements.txt").write_text("requests==2.25.0\n")
            with mock.patch.object(plainsec, "run_tool", return_value=({}, None)) as rt:
                plainsec.scan_deps(tmp)
            self.assertIn("-r", rt.call_args[0][0])

    def test_audit_env_flag_runs_without_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(plainsec, "run_tool", return_value=({}, None)) as rt:
                data, err = plainsec.scan_deps(tmp, audit_env=True)
            self.assertIsNone(err)
            self.assertNotIn("-r", rt.call_args[0][0])


def bfind(tid, path, line, text, sev="LOW"):
    """bandit result with a code snippet, like real output."""
    return {"filename": path, "line_number": line, "issue_severity": sev,
            "test_id": tid, "issue_text": "x", "more_info": "x",
            "code": f"{line - 1} # before\n{line} {text}\n{line + 1} # after\n"}


class TestSinceLastScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.state = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"PLAINSEC_STATE_DIR": self.state.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()
        self.state.cleanup()

    def scan(self, results, deps=None, extra=()):
        b = self.dir / "b.json"
        b.write_text(json.dumps({"results": results}))
        a = self.dir / "a.json"
        a.write_text(json.dumps({"dependencies": deps or []}))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            plainsec.main([str(self.dir), "--bandit-json", str(b), "--audit-json", str(a), *extra])
        return out.getvalue()

    def test_flagged_line_text(self):
        code = "50     result = subprocess.run(\n51         command, shell=True,\n52     )\n"
        self.assertEqual(plainsec.flagged_line(code, 51), "command, shell=True,")
        self.assertEqual(plainsec.flagged_line(code, 99), "")
        self.assertEqual(plainsec.flagged_line(None, 1), "")

    def test_first_scan_then_no_change(self):
        r = [bfind("B602", "a.py", 5, "run(cmd, shell=True)", "HIGH")]
        self.assertIn("first scan (baseline saved)", self.scan(r))
        second = self.scan(r)
        self.assertIn("0 new, 0 gone since last scan", second)
        self.assertIn("Nothing changed in what was checked.", second)

    def test_b605_wording_follows_severity(self):
        # Real case: OXX-Terminal's six LOW B605s (fixed commands) read as
        # alarming as trinity_master's HIGH one.
        low = plainsec.parse_bandit({"results": [dict(bfind("B605", "a.py", 3, 'os.system("clear")'))]})
        high = plainsec.parse_bandit({"results": [dict(bfind("B605", "b.py", 3, "os.system(cmd)", "HIGH"))]})
        self.assertIn("Safe as written", low[0]["meaning"])
        self.assertIn("built from variables", high[0]["meaning"])

    def test_report_says_where_paths_start(self):
        # Real case: report said `anvil/Matrixenc.py` line 24; the user ran
        # `nano anvil/Matrixenc.py` from ~ and got an empty new file.
        out = self.scan([bfind("B105", "anvil/x.py", 24, "pw = 'x'")])
        self.assertIn(f"File paths below start from `{plainsec.display_path(self.dir)}`", out)
        self.assertIn(f"first run `cd ", out)

    def test_empty_password_value_is_tagged(self):
        # Real case: trinity_master anvil/Matrixenc.py line 24, B105 on
        # ACTIVE_LISTENER = {"status": False, "port": None, "password": None}
        f = lambda tid, text: {"id": tid, "text": text}
        yes = ['ACTIVE_LISTENER = {"status": False, "port": None, "password": None}',
               'token = ""', "api_key=None,", "PASSWORD = ''  # set later"]
        no = ['password = "hunter2"', 'DB_PASS = os.environ["X"]',
              'password = None_or_default()']
        for t in yes:
            self.assertTrue(plainsec.empty_password_value(f("B105", t)), t)
        for t in no:
            self.assertFalse(plainsec.empty_password_value(f("B105", t)), t)
        self.assertFalse(plainsec.empty_password_value(f("B101", yes[0])))
        out = self.scan([bfind("B105", "anvil/m.py", 24, yes[0]),
                         bfind("B105", "anvil/m.py", 30, 'pw = "hunter2"')])
        self.assertIn("lines 24 (empty value, likely not a secret), 30", out)

    def test_display_path(self):
        home = Path.home()
        self.assertEqual(plainsec.display_path(home / "proj"), "~/proj")
        self.assertEqual(plainsec.display_path(home), "~")
        self.assertEqual(plainsec.display_path("/opt/x"), "/opt/x")

    def test_no_save_does_not_claim_baseline_saved(self):
        # Real case: the Action runs with --no-save, yet its report said
        # "first scan (baseline saved)".
        r = [bfind("B602", "a.py", 5, "run(cmd, shell=True)", "HIGH")]
        out = self.scan(r, extra=("--no-save",))
        self.assertNotIn("baseline saved", out)
        self.assertNotIn("Saved as the starting point", out)
        self.assertIn("first scan (not saved: --no-save)", out)
        self.assertIn("first scan (baseline saved)", self.scan(r))   # really nothing was saved

    def test_moved_line_is_not_new_or_gone(self):
        self.scan([bfind("B602", "a.py", 5, "run(cmd, shell=True)", "HIGH")])
        out = self.scan([bfind("B602", "a.py", 40, "run(cmd, shell=True)", "HIGH")])
        self.assertIn("0 new, 0 gone", out)

    def test_new_and_gone(self):
        self.scan([bfind("B602", "a.py", 5, "run(cmd, shell=True)", "HIGH"),
                   bfind("B110", "b.py", 9, "except: pass")])
        out = self.scan([bfind("B602", "a.py", 5, "run(cmd, shell=True)", "HIGH"),
                         bfind("B307", "c.py", 3, "eval(x)", "MEDIUM")])
        self.assertIn("1 new, 1 gone since last scan", out)
        self.assertIn("[MEDIUM] B307 `c.py` line 3", out)
        self.assertIn("B110 `b.py` (was line 9)", out)

    def test_two_identical_lines_counted_separately(self):
        one = bfind("B101", "t.py", 3, "assert x")
        self.scan([one])
        out = self.scan([one, bfind("B101", "t.py", 8, "assert x")])
        self.assertIn("1 new, 0 gone", out)

    def test_failed_code_scan_is_not_all_fixed_and_keeps_baseline(self):
        r = [bfind("B602", "a.py", 5, "run(cmd, shell=True)", "HIGH")]
        self.scan(r)
        out = io.StringIO()
        a = self.dir / "a.json"
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
             mock.patch.object(plainsec.shutil, "which", return_value=None):
            plainsec.main([str(self.dir), "--audit-json", str(a)])   # bandit "missing"
        self.assertIn("## 2. Your code\nNOT CHECKED", out.getvalue())
        self.assertNotIn("Gone since last time", out.getvalue())
        self.assertIn("0 new, 0 gone", self.scan(r))   # baseline survived

    def test_ignore_line_is_not_a_fix(self):
        r = [bfind("B602", "tools/p.py", 5, "run(cmd, shell=True)", "HIGH")]
        self.scan(r)
        (self.dir / ".plainsec").write_text("tools/\n")
        self.assertIn("0 new, 0 gone", self.scan(r))

    def test_new_finding_in_skipped_path_is_tagged(self):
        self.scan([])
        (self.dir / ".plainsec").write_text("tools/\n")
        out = self.scan([bfind("B602", "tools/p.py", 5, "run(c, shell=True)", "HIGH")])
        self.assertIn("1 new", out)
        self.assertIn("skipped by .plainsec", out.split("## 1.")[0])

    def test_dependency_changes(self):
        dep = lambda vid: [{"name": "requests", "version": "2.25.0",
                            "vulns": [{"id": vid, "fix_versions": [], "description": ""}]}]
        self.scan([], deps=dep("OLD-1"))
        out = self.scan([], deps=dep("NEW-2"))
        self.assertIn("dependency requests NEW-2", out)
        self.assertIn("dependency requests OLD-1", out)

    def test_no_save(self):
        self.scan([], extra=["--no-save"])
        self.assertEqual(list(Path(self.state.name).iterdir()), [])
        self.scan([])
        out = self.scan([bfind("B110", "b.py", 9, "except: pass")], extra=["--no-save"])
        self.assertIn("1 new", out)
        self.assertIn("1 new", self.scan([bfind("B110", "b.py", 9, "except: pass")]))

    def test_state_stays_out_of_project(self):
        self.scan([])
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["a.json", "b.json"])
        self.assertEqual(len(list(Path(self.state.name).iterdir())), 1)


# Shaped like gitleaks 8.16 JSON with --redact (Secret/Match already redacted).
def leak(rule, file, line, commit="", date="", desc="x"):
    return {"Description": desc, "StartLine": line, "EndLine": line, "File": file,
            "Commit": commit, "Date": date, "RuleID": rule, "Secret": "REDACTED",
            "Match": "token = REDACTED", "Fingerprint": f"{commit}:{file}:{rule}:{line}"}


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.state = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"PLAINSEC_STATE_DIR": self.state.name})
        self.env.start()
        (self.dir / "b.json").write_text('{"results": []}')
        (self.dir / "a.json").write_text('{"dependencies": []}')

    def tearDown(self):
        self.env.stop(); self.tmp.cleanup(); self.state.cleanup()

    def run_with(self, leaks, extra=()):
        g = self.dir / "g.json"
        g.write_text(json.dumps(leaks))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = plainsec.main([str(self.dir), "--bandit-json", str(self.dir / "b.json"),
                                "--audit-json", str(self.dir / "a.json"),
                                "--secrets-json", str(g), *extra])
        return rc, out.getvalue()

    def test_same_file_secrets_grouped_with_one_check(self):
        # Real case: OXX-Terminal listed kalshi/openapi.yaml 12 times, each
        # with its own check command.
        leaks = []
        for n in (7877, 7964, 7998):
            l = leak("generic-api-key", "kalshi/openapi.yaml", n, "1523accfffff", "2026-09-12T00:00:00Z")
            l["Match"] = 'market_id: "REDACTED"'
            leaks.append(l)
        leaks.append(leak("generic-api-key", "kalshi/howto.md", 61, "1523accfffff"))
        _, out = self.run_with(leaks)
        self.assertIn("**4 possible secrets (3 named like IDs/hashes)", out)
        self.assertIn("`kalshi/openapi.yaml` — 3 places (lines 7877, 7964, 7998)", out)
        self.assertIn("IDs usually aren't secret on their own (all of them)", out)
        self.assertEqual(out.count("kalshi/openapi.yaml' |"), 1)          # one check command
        self.assertIn("sed -n '7877{=;p};7964{=;p};7998{=;p}' | paste - -", out)
        self.assertIn("`kalshi/howto.md` line 61", out)

    def test_multi_line_check_command_runs(self):
        f = self.dir / "t.txt"
        f.write_text("a\nb\nc\nd\n")
        cmd = plainsec.view_command({"commit": None, "file": "t.txt", "line": [2, 4]}, self.dir)
        cmd = cmd.replace(plainsec.shell_path(self.dir), str(self.dir))   # no ~ for /bin/sh
        out = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True).stdout
        self.assertEqual(out, "2\tb\n4\td\n")

    def test_secret_value_never_printed(self):
        raw = [leak("github-pat", "cfg.py", 3, "abc12345def", "2026-08-16T10:00:00Z")]
        raw[0]["Secret"] = "ghp_REALLOOKINGVALUE1234567890abcdef"   # even if unredacted
        raw[0]["Match"] = "token = ghp_REALLOOKINGVALUE1234567890abcdef"
        _, out = self.run_with(raw)
        self.assertNotIn("ghp_REAL", out)
        self.assertNotIn("REDACTED", out)

    def test_history_finding_explained(self):
        rc, out = self.run_with([leak("github-pat", "old/cfg.py", 3, "abc12345def",
                                      "2026-08-16T10:00:00Z")])
        self.assertEqual(rc, 1)
        self.assertIn("1 possible secret ·", out)
        self.assertIn("GitHub token", out)
        self.assertIn("first committed in abc12345 (2026-08-16)", out)
        self.assertIn("file no longer exists, but it's still in history", out)
        self.assertIn("Rotate it first", out)
        self.assertLess(out.index("## 0. Possible secrets"), out.index("## 1. Dependencies"))

    def test_files_mode_and_test_file_flag(self):
        (self.dir / "tests").mkdir()
        (self.dir / "tests" / "test_x.py").write_text("x")
        _, out = self.run_with([leak("generic-api-key", "tests/test_x.py", 7)])
        self.assertIn("files as they are now", out)
        self.assertIn("test file: probably a fake value, but check", out)
        self.assertIn("move it out of the code", out.lower())
        self.assertNotIn("commit", out.split("## 0.")[1].split("## 1.")[0])

    def test_plainsec_file_never_skips_secrets(self):
        (self.dir / ".plainsec").write_text("tools/\n")
        _, out = self.run_with([leak("private-key", "tools/id_rsa", 1)])
        self.assertIn("1 possible secret", out)
        self.assertIn("`tools/id_rsa`", out)

    def test_none_found(self):
        rc, out = self.run_with([])
        self.assertEqual(rc, 0)
        self.assertIn("0 possible secrets", out)
        self.assertIn("No secrets found.", out)

    def test_not_installed_is_not_an_all_clear(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), \
             mock.patch.object(plainsec.shutil, "which", return_value=None):
            rc = plainsec.main([str(self.dir), "--bandit-json", str(self.dir / "b.json"),
                                "--audit-json", str(self.dir / "a.json")])
        self.assertEqual(rc, 1)
        self.assertIn("secrets NOT CHECKED", out.getvalue())
        self.assertNotIn("No secrets found", out.getvalue())

    def test_new_and_gone_secrets_in_history(self):
        a = leak("github-pat", "a.py", 3, "c1")
        b = leak("aws-access-token", "b.py", 9, "c2")
        self.run_with([a])
        _, out = self.run_with([b])
        self.assertIn("1 new, 1 gone since last scan", out)
        self.assertIn("possible secret: aws-access-token `b.py`", out)
        self.assertIn("possible secret github-pat `a.py` (no longer found", out)

    def test_generic_says_check_first_with_command(self):
        _, out = self.run_with([leak("generic-api-key", "deploy_tokens.py", 32,
                                     "76dbbad2ffff", "2026-07-25T00:00:00Z")])
        sec = out.split("## 0.")[1].split("## 1.")[0]
        self.assertIn("Check whether it's real first", sec)
        self.assertNotIn("- Fix: Rotate it first", sec)
        self.assertIn("rotate it first", sec)          # still the advice IF real
        # git -C: works from any folder (real case: run from another repo gave
        # "fatal: invalid object name").
        self.assertIn(f"check: `git -C {plainsec.shell_path(self.dir)} show 76dbbad2:"
                      "'deploy_tokens.py' | sed -n 32p`", sec)

    def test_specific_rule_still_says_rotate(self):
        _, out = self.run_with([leak("github-pat", "a.py", 3, "c1")])
        self.assertIn("- Fix: Rotate it first", out)
        self.assertNotIn("check: `", out)

    def test_name_hints_hash_and_id_without_value(self):
        h = leak("generic-api-key", "registry.json", 6, "103f2fb2aa")
        h["Match"] = '"api_token_hash": "REDACTED"'
        i = leak("generic-api-key", "cfg.json", 2)
        i["Match"] = 'account_id = "REDACTED"'
        n = leak("generic-api-key", "x.py", 9)
        n["Match"] = 'token = "REDACTED"'
        _, out = self.run_with([h, i, n])
        self.assertIn("registry.json` line 6 — first committed in 103f2fb2 — file no longer exists, "
                      "but it's still in history — the name says it's a hash", out)
        self.assertIn("the name says it's an ID", out)
        self.assertEqual(out.count("the name says"), 2)   # plain 'token' gets no hint
        self.assertNotIn("REDACTED", out)

    def test_api_key_id_is_not_played_down(self):
        # Real case: OXX-Terminal `API_KEY_ID = "837934ae-…"` was a real Kalshi
        # key ID, labelled "IDs usually aren't secret" and counted as harmless.
        for m in ('API_KEY_ID = "REDACTED"', 'access_key_id: "REDACTED"', '"key-id": "REDACTED"'):
            self.assertIs(plainsec.name_hint(m), plainsec.KEY_ID_HINT, m)
        self.assertIn("IDs usually", plainsec.name_hint('client_order_id: "REDACTED"'))
        k = leak("generic-api-key", "kalshi/client.py", 14, "044b5640ffff")
        k["Match"] = 'API_KEY_ID = "REDACTED"'
        o = leak("generic-api-key", "kalshi/openapi.yaml", 7877, "1523accfffff")
        o["Match"] = 'client_order_id: "REDACTED"'
        _, out = self.run_with([k, o])
        self.assertIn("**2 possible secrets (1 named like IDs/hashes)", out)
        self.assertIn("half of a login", out)

    def test_name_hint_never_uses_the_value(self):
        self.assertEqual(plainsec.name_hint('token = "sha256_looking_value"'), "")
        self.assertIn("hash", plainsec.name_hint('"api_token_hash": "x"'))
        self.assertEqual(plainsec.name_hint(""), "")

    def test_files_mode_check_command(self):
        (self.dir / "cfg.py").write_text("x")
        _, out = self.run_with([leak("generic-api-key", "cfg.py", 4)])
        self.assertIn(f"check: `sed -n 4p {plainsec.shell_path(self.dir)}/'cfg.py'`", out)

    def test_view_command_paths(self):
        f = {"commit": "abc12345", "file": "a b.json", "line": 3}
        home = Path.home()
        self.assertEqual(plainsec.view_command(f, home / "repo"),
                         "git -C ~/repo show abc12345:'a b.json' | sed -n 3p")
        self.assertEqual(plainsec.view_command(f, home / "my repo"),
                         "git -C \"$HOME/my repo\" show abc12345:'a b.json' | sed -n 3p")
        self.assertEqual(plainsec.view_command(dict(f, commit=None), home / "repo"),
                         "sed -n 3p ~/repo/'a b.json'")
        self.assertEqual(plainsec.view_command(f), "git show abc12345:'a b.json' | sed -n 3p")

    def test_history_rewrite_is_not_new_secrets(self):
        # Real case (demo-repo, Nov 20): filter-repo gave every commit a new
        # ID and plainsec said "2 new, 4 gone" instead of "0 new, 2 gone".
        keep = lambda c: [leak("generic-api-key", "registry.json", 6, c),
                          leak("generic-api-key", "registry.json", 14, c)]
        self.run_with(keep("103f2fb2aa") + [leak("generic-api-key", "deploy_tokens.py", 32, "76dbbad2aa"),
                                            leak("generic-api-key", ".wrangler/cache/cf.json", 1, "cbef32bbaa")])
        _, out = self.run_with(keep("5912f466bb"))
        self.assertIn("0 new, 2 gone since last scan", out)

    def test_old_saved_format_is_upgraded(self):
        self.run_with([])                                     # creates a state file
        sf = next(Path(self.state.name).iterdir())
        data = json.loads(sf.read_text())
        data["secrets"] = ["generic-api-key|registry.json|103f2fb2|6"]  # old format
        sf.write_text(json.dumps(data))
        _, out = self.run_with([leak("generic-api-key", "registry.json", 6, "5912f466")])
        self.assertIn("0 new, 0 gone since last scan", out)

    def test_same_leak_in_many_commits_shown_once_with_earliest(self):
        _, out = self.run_with([leak("github-pat", "a.py", 3, "late0000", "2026-09-01T00:00:00Z"),
                                leak("github-pat", "a.py", 3, "early000", "2026-07-01T00:00:00Z")])
        self.assertIn("1 possible secret ·", out)
        self.assertIn("first committed in early000 (2026-07-01)", out)

    def test_duplicate_leaks_counted_once(self):
        _, out = self.run_with([leak("github-pat", "a.py", 3, "c1")] * 2)
        self.assertIn("1 possible secret ·", out)

    def test_gitleaks_command_uses_redact_and_history(self):
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            Path(cmd[cmd.index("--report-path") + 1]).write_text("[]")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(plainsec.shutil, "which", return_value="/x/gitleaks"), \
             mock.patch.object(plainsec.subprocess, "run", side_effect=fake_run):
            data, err = plainsec.scan_secrets(self.dir)          # not a repo
            (self.dir / ".git").mkdir()
            data2, err2 = plainsec.scan_secrets(self.dir)        # a repo
        self.assertIsNone(err); self.assertIsNone(err2)
        self.assertIn("--redact", calls[0]); self.assertIn("--no-git", calls[0])
        self.assertNotIn("--no-git", calls[1])
        self.assertFalse(data["history"]); self.assertTrue(data2["history"])


def osv_vuln(vid, name, fixed=None, summary="", aliases=(), informational=False,
             informational_in_affected=False, kind="unmaintained"):
    v = {"id": vid, "summary": summary, "details": "", "aliases": list(aliases),
         "affected": [{"package": {"name": name},
                       "ranges": [{"type": "ECOSYSTEM",
                                   "events": [{"introduced": "0"}] +
                                             ([{"fixed": f} for f in ([fixed] if isinstance(fixed, str) else fixed or [])])}]}]}
    if informational:
        v["database_specific"] = {"informational": "unmaintained"}
    if informational_in_affected:          # where real RustSec data puts it
        v["affected"][0]["database_specific"] = {"informational": kind}
    return v


def osv_pkg(name, version, eco, vulns, groups):
    return {"package": {"name": name, "version": version, "ecosystem": eco},
            "vulnerabilities": vulns, "groups": groups}


REAL_CARGO_SHIPPING = plainsec.cargo_shipping
REAL_CARGO_VIA = plainsec.cargo_via


class TestOsvScanner(unittest.TestCase):
    """Shaped like real osv-scanner 2.7.1 output (demo-repo, Nov 20)."""

    def setUp(self):
        # Never run the real `cargo tree` in tests (WSL has cargo): same result
        # on every machine. Tests about it use REAL_CARGO_SHIPPING with mocks.
        self.no_cargo = mock.patch.object(plainsec, "cargo_shipping", return_value=None)
        self.no_cargo.start()
        self.addCleanup(self.no_cargo.stop)
        self.no_via = mock.patch.object(plainsec, "cargo_via", return_value=None)
        self.no_via.start()
        self.addCleanup(self.no_via.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.state = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"PLAINSEC_STATE_DIR": self.state.name})
        self.env.start()
        root = str(self.dir.resolve())
        self.data = {"results": [
            {"source": {"path": f"{root}/_archive/android/requirements.txt", "type": "lockfile"},
             "packages": [osv_pkg("anyio", "4.9.0", "PyPI",
                [osv_vuln("PYSEC-2026-4024", "anyio", "4.10.0", "Race condition in anyio."),
                 osv_vuln("GHSA-5p39-cfhj-2xmp", "anyio", "4.10.0", "Race condition in anyio.")],
                [{"ids": ["PYSEC-2026-4024", "GHSA-5p39-cfhj-2xmp"],
                  "aliases": ["CVE-2026-64847", "GHSA-5p39-cfhj-2xmp", "PYSEC-2026-4024"],
                  "max_severity": "6.8"}])]},
            {"source": {"path": f"{root}/app/program/Cargo.lock", "type": "lockfile"},
             "packages": [
                osv_pkg("curve25519-dalek", "3.2.0", "crates.io",
                    [osv_vuln("RUSTSEC-2024-0344", "curve25519-dalek", "4.1.3", "Timing variability."),
                     osv_vuln("GHSA-aaaa", "curve25519-dalek", ["3.2.1", "4.0.0"], "Other bug.")],
                    [{"ids": ["RUSTSEC-2024-0344"], "aliases": ["GHSA-x4gp"], "max_severity": "5.9"},
                     {"ids": ["GHSA-aaaa"], "aliases": [], "max_severity": "7.5"}]),
                osv_pkg("ansi_term", "0.12.1", "crates.io",
                    [osv_vuln("RUSTSEC-2021-0139", "ansi_term", None, "ansi_term is Unmaintained",
                              informational=True)],
                    [{"ids": ["RUSTSEC-2021-0139"], "aliases": [], "max_severity": ""}]),
                osv_pkg("nofix", "1.0.0", "crates.io",
                    [osv_vuln("RUSTSEC-2099-0001", "nofix", None, "No fix yet.")],
                    [{"ids": ["RUSTSEC-2099-0001"], "aliases": [], "max_severity": "9.8"}]),
             ]},
        ]}
        (self.dir / "b.json").write_text('{"results": []}')
        (self.dir / "g.json").write_text('[]')
        (self.dir / "o.json").write_text(json.dumps(self.data))

    def tearDown(self):
        self.env.stop(); self.tmp.cleanup(); self.state.cleanup()

    def run_cli(self, extra=()):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = plainsec.main([str(self.dir), "--bandit-json", str(self.dir / "b.json"),
                                "--secrets-json", str(self.dir / "g.json"),
                                "--osv-json", str(self.dir / "o.json"), *extra])
        return rc, out.getvalue()

    def test_vkey_order(self):
        self.assertGreater(plainsec.vkey("1.10.0"), plainsec.vkey("1.9.9"))
        self.assertLess(plainsec.vkey("2.0.0rc1"), plainsec.vkey("2.0.0"))
        self.assertGreater(plainsec.vkey("4.1.3"), plainsec.vkey("3.2.1"))

    def test_groups_counted_not_alias_ids(self):
        risky, notices = plainsec.parse_osv(self.data, root=self.dir)
        anyio = next(d for d in risky if d["name"] == "anyio")
        self.assertEqual(anyio["ids"], ["CVE-2026-64847"])      # 1 issue, CVE preferred
        self.assertEqual(anyio["severity"], "MEDIUM")
        self.assertEqual(anyio["source"], "_archive/android/requirements.txt")

    def test_fix_covers_all_issues(self):
        risky, _ = plainsec.parse_osv(self.data, root=self.dir)
        d = next(d for d in risky if d["name"] == "curve25519-dalek")
        self.assertEqual(len(d["ids"]), 2)
        self.assertEqual(d["severity"], "HIGH")                # worst of the two
        self.assertEqual(d["fix_to"], "4.1.3")                 # needs both fixes: max(3.2.1, 4.1.3)

    def test_unmaintained_is_a_notice_not_a_vulnerability(self):
        risky, notices = plainsec.parse_osv(self.data, root=self.dir)
        self.assertNotIn("ansi_term", [d["name"] for d in risky])
        self.assertEqual([n["name"] for n in notices], ["ansi_term"])

    def test_report(self):
        rc, out = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertIn("3 risky dependencies (2 high/critical)", out)
        self.assertIn("Checked with osv-scanner", out)
        self.assertIn("### `app/program/Cargo.lock` (Rust) · 2 packages", out)
        self.assertIn("`curve25519-dalek` isn't in your Cargo.toml", out)
        # every printed command works wherever it's pasted: it cd's first
        self.assertIn(f"run `cd {plainsec.shell_path(self.dir / 'app/program')} && "
                      "cargo tree -i curve25519-dalek@3.2.0 --depth 1`, then update", out)
        self.assertIn("`pip install 'anyio>=4.10.0'`, then update its pin in "
                      f"`{plainsec.display_path(self.dir / '_archive/android/requirements.txt')}`", out)
        self.assertIn("nofix 1.0.0** · CRITICAL", out)
        self.assertNotIn("UNKNOWN", out)
        self.assertIn("no fixed version yet", out)
        self.assertIn("### Unmaintained (1): not vulnerabilities", out)

    # ---- found on the real demo-repo report (Nov 20) ----
    def test_informational_inside_affected_and_summary_backstop(self):
        data = {"results": [{"source": {"path": "Cargo.lock"}, "packages": [
            osv_pkg("bincode", "1.3.3", "crates.io",
                    [osv_vuln("RUSTSEC-2025-0141", "bincode", None, "Bincode is unmaintained",
                              informational_in_affected=True)],
                    [{"ids": ["RUSTSEC-2025-0141"], "aliases": [], "max_severity": ""}]),
            osv_pkg("paste", "1.0.15", "crates.io",
                    [osv_vuln("RUSTSEC-2024-0436", "paste", None, "paste - no longer maintained")],
                    [{"ids": ["RUSTSEC-2024-0436"], "aliases": [], "max_severity": ""}]),
            osv_pkg("atty", "0.2.14", "crates.io",
                    [osv_vuln("GHSA-g98v", "atty", None, "Potential unaligned read"),
                     osv_vuln("RUSTSEC-2024-0375", "atty", None, "atty is unmaintained",
                              informational_in_affected=True)],
                    [{"ids": ["GHSA-g98v"], "aliases": [], "max_severity": ""},
                     {"ids": ["RUSTSEC-2024-0375"], "aliases": [], "max_severity": ""}]),
        ]}]}
        risky, notices = plainsec.parse_osv(data)
        self.assertEqual([d["name"] for d in risky], ["atty"])          # real unsound issue stays
        self.assertEqual(risky[0]["ids"], ["GHSA-g98v"])
        self.assertEqual(sorted(n["name"] for n in notices), ["atty", "bincode", "paste"])

    def test_unsound_kept_apart_with_fix_and_advice(self):
        # Real case: 6 of 18 "notices" were unsound (lru use-after-free, memmap2...)
        root = str(self.dir.resolve())
        data = {"results": [{"source": {"path": f"{root}/app/program/Cargo.lock"}, "packages": [
            osv_pkg("lru", "0.7.8", "crates.io",
                    [osv_vuln("RUSTSEC-2026-0253", "lru", "0.18.2", "Potential use-after-free",
                              informational_in_affected=True, kind="unsound")],
                    [{"ids": ["RUSTSEC-2026-0253"], "aliases": [], "max_severity": ""}]),
            osv_pkg("bincode", "1.3.3", "crates.io",
                    [osv_vuln("RUSTSEC-2025-0141", "bincode", None, "Bincode is unmaintained",
                              informational_in_affected=True)],
                    [{"ids": ["RUSTSEC-2025-0141"], "aliases": [], "max_severity": ""}]),
        ]}]}
        (self.dir / "o.json").write_text(json.dumps(data))
        _, out = self.run_cli()
        self.assertIn("0 risky dependencies + 1 unsound", out)
        self.assertIn("### Unsound code (1): no known attack, but not safe", out)
        self.assertIn("**lru 0.7.8** (`app/program/Cargo.lock`): Potential use-after-free", out)
        self.assertIn("Fixed in: 0.18.2 or later", out)
        self.assertIn("`lru` isn't in your Cargo.toml", out)
        self.assertIn("### Unmaintained (1): not vulnerabilities", out)
        self.assertNotIn("Nothing is broken today", out.split("### Unmaintained")[0])
        self.assertEqual(plainsec._informational_kind(
            osv_vuln("x", "y", None, "fine", informational_in_affected=True, kind="unsound")), "unsound")

    def test_unmaintained_wording_with_a_fix_is_not_a_notice(self):
        v = osv_vuln("X-1", "foo", "2.0.0", "foo is unmaintained but this bug is fixed")
        self.assertFalse(plainsec._is_informational(v))

    def test_prerelease_fix_text(self):
        self.assertEqual(plainsec.fix_text("1.0.0-alpha.1"),
                         "1.0.0 or later (first fixed in pre-release 1.0.0-alpha.1)")
        self.assertEqual(plainsec.fix_text("0.103.16"), "0.103.16 or later")
        self.assertEqual(plainsec.stable_of("2.0rc1"), "2.0")

    def test_semver_compatible(self):
        sc = plainsec.semver_compatible
        self.assertTrue(sc("0.101.7", "0.101.9"))
        self.assertFalse(sc("0.101.7", "0.103.16"))      # 0.x: minor bump is breaking
        self.assertTrue(sc("1.3.3", "1.9.0"))
        self.assertFalse(sc("1.0.1", "2.0.0"))
        self.assertFalse(sc("0.10.4", "1.0.0-alpha.1"))

    def test_rust_advice_direct_transitive_compatible(self):
        prog = self.dir / "app" / "program"
        (prog / "target" / "x").mkdir(parents=True)
        (prog / "Cargo.toml").write_text(
            '[package]\nname = "sf"\n[dependencies]\nborsh = "0.10"\nsolana-program = "1.18"\n'
            '[dev-dependencies]\nmemmap2 = "0.5"\n')
        (prog / "target" / "x" / "Cargo.toml").write_text('[dependencies]\nrustls = "1"\n')  # ignored
        direct = plainsec.cargo_direct_deps(self.dir, "app/program/Cargo.lock")
        self.assertEqual(direct, {"borsh", "solana-program", "memmap2"})
        base = {"ecosystem": "crates.io", "source": "app/program/Cargo.lock"}
        t = plainsec.dep_how(dict(base, name="rustls", version="0.21.12", fix_to="0.23.46", direct=False))
        self.assertIn("isn't in your Cargo.toml", t)
        self.assertIn("`cargo tree -i rustls@0.21.12 --depth 1`", t)
        self.assertNotIn("raise", t)
        self.assertNotIn("solana", t)                      # not a Solana project here
        t = plainsec.dep_how(dict(base, name="rustls", version="0.21.12", fix_to="0.23.46",
                                  direct=False, solana=True))
        self.assertIn("usually one of your solana / anchor crates", t)
        t = plainsec.dep_how(dict(base, name="borsh", version="0.10.4", fix_to="1.0.0-alpha.1", direct=True))
        self.assertIn("raise `borsh` to 1.0.0 in Cargo.toml", t)
        t = plainsec.dep_how(dict(base, name="lru", version="0.7.8", fix_to="0.7.9", direct=False))
        self.assertIn("run `cargo update -p lru` in `app/program`; 0.7.9 is a compatible", t)

    def test_report_marks_direct_from_real_cargo_toml(self):
        prog = self.dir / "app" / "program"
        prog.mkdir(parents=True)
        (prog / "Cargo.toml").write_text('[dependencies]\ncurve25519-dalek = "3"\n')
        _, out = self.run_cli()
        self.assertIn(f"raise `curve25519-dalek` to 4.1.3 in `{plainsec.display_path(prog / 'Cargo.toml')}`, "
                      f"then run `cd {plainsec.shell_path(prog)} && cargo update -p curve25519-dalek`", out)

    # ---- which of YOUR crates pulls a crate in (real trinity_master case) ----
    # Excerpt of `cargo tree -i borsh@0.10.4 -e no-dev --prefix none --format {p}`
    # shape; the full tree was 846 lines.
    REAL_INVERSE = ("borsh v0.10.4\nkaigan v0.2.6\nsolana-config-program-client v0.0.2\n"
                    "solana-borsh v2.2.1\nsolana-program v2.3.0\n"
                    "soldier_fund v0.1.0 (/home/u/tm/soldier_fund/program)\n"
                    "solana-program v2.3.0 (*)\nsolana-pubkey v2.4.0\n")

    def test_cargo_via_finds_your_crate(self):
        direct = {"solana-program", "borsh-derive", "solana-program-test"}
        with mock.patch.object(plainsec.shutil, "which", return_value="/usr/bin/cargo"), \
             mock.patch.object(plainsec.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stdout=self.REAL_INVERSE)) as run:
            via = REAL_CARGO_VIA(self.dir, "p/Cargo.lock", "borsh", "0.10.4", direct, ships=True)
        self.assertEqual(via, ["solana-program"])
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[cmd.index("-i") + 1], "borsh@0.10.4")   # real bug: was "-e"
        self.assertEqual(cmd[cmd.index("-e") + 1], "no-dev")      # shipping: no dev paths
        for i, part in enumerate(cmd):                         # every flag keeps its value
            if part in ("-i", "-e", "--target", "--prefix", "--format"):
                self.assertFalse(cmd[i + 1].startswith("-"), cmd)
        with mock.patch.object(plainsec.shutil, "which", return_value=None):
            self.assertIsNone(REAL_CARGO_VIA(self.dir, "p/Cargo.lock", "borsh", "0.10.4", direct))

    def test_dep_how_names_the_crate_to_update(self):
        d = {"ecosystem": "crates.io", "source": "p/Cargo.lock", "name": "borsh",
             "version": "0.10.4", "fix_to": "1.0.0", "direct": False, "via": ["solana-program"]}
        t = plainsec.dep_how(d)
        self.assertIn("comes in through `solana-program` (which is in your Cargo.toml)", t)
        self.assertIn("still uses borsh 0.10.4, there's nothing to do on your side", t)
        self.assertNotIn("cargo tree", t)

    # ---- tests-only vs ships (cargo tree -e no-dev), real output format ----
    REAL_TREE = ("borsh v0.10.4\nborsh v0.10.4 (*)\nborsh v1.8.1\ncurve25519-dalek v4.1.3\n"
                 "rand v0.7.3\napp v0.1.0 (/home/u/app/program)\n")

    def fake_cargo(self, stdout=None, code=0):
        def run(cmd, **kw):
            assert cmd[:2] == ["cargo", "tree"] and "--locked" in cmd and "no-dev" in cmd
            return mock.Mock(returncode=code, stdout=stdout or self.REAL_TREE, stderr="")
        return run

    def test_cargo_shipping_parses_real_format(self):
        with mock.patch.object(plainsec.shutil, "which", return_value="/x/cargo"), \
             mock.patch.object(plainsec.subprocess, "run", side_effect=self.fake_cargo()):
            ship = REAL_CARGO_SHIPPING(self.dir, "Cargo.lock")
        self.assertIn(("borsh", "0.10.4"), ship)
        self.assertIn(("curve25519-dalek", "4.1.3"), ship)
        self.assertNotIn(("curve25519-dalek", "3.2.0"), ship)     # version matters
        self.assertIn(("app", "0.1.0"), ship)

    def test_cargo_missing_or_failing_labels_nothing(self):
        with mock.patch.object(plainsec.shutil, "which", return_value=None):
            self.assertIsNone(REAL_CARGO_SHIPPING(self.dir, "Cargo.lock"))
        with mock.patch.object(plainsec.shutil, "which", return_value="/x/cargo"), \
             mock.patch.object(plainsec.subprocess, "run", side_effect=self.fake_cargo(code=101)):
            self.assertIsNone(REAL_CARGO_SHIPPING(self.dir, "Cargo.lock"))

    def test_report_tests_only_vs_ships(self):
        (self.dir / "app" / "program").mkdir(parents=True)
        tree = "nofix v1.0.0\ncurve25519-dalek v4.1.3\n"           # nofix ships, dalek 3.2.0 doesn't
        with mock.patch.object(plainsec, "cargo_shipping", REAL_CARGO_SHIPPING), \
             mock.patch.object(plainsec.shutil, "which",
                               side_effect=lambda n: "/x/cargo" if n == "cargo" else None), \
             mock.patch.object(plainsec.subprocess, "run", side_effect=self.fake_cargo(tree)):
            _, out = self.run_cli()
        self.assertIn("3 risky dependencies (2 high/critical, 1 test-only)", out)
        self.assertIn("curve25519-dalek 3.2.0** · HIGH · tests only", out)
        self.assertIn("nofix 1.0.0** · CRITICAL · ships in your program", out)
        self.assertIn("only your tests / dev tools use this", out)
        self.assertIn("Rust crates were checked with `cargo tree`", out)
        sec = out.split("Cargo.lock` (Rust)")[1]
        self.assertLess(sec.index("nofix"), sec.index("curve25519-dalek"))   # ships first

    def test_report_without_cargo_says_how(self):
        with mock.patch.object(plainsec.shutil, "which", return_value=None):
            _, out = self.run_cli()
        self.assertIn("Install Rust's `cargo`", out)
        self.assertNotIn("tests only", out)

    def test_plainsec_skips_dependency_files_but_counts_them(self):
        (self.dir / ".plainsec").write_text("_archive/\n")
        _, out = self.run_cli()
        self.assertIn("2 risky dependencies", out)
        self.assertIn("Skipped by .plainsec `_archive/`: 1 vulnerable package", out)
        self.assertIn("`_archive/` — 1 vulnerable dependency in _archive/android/requirements.txt", out)
        self.assertNotIn("matched nothing", out)

    def test_no_dependency_files(self):
        (self.dir / "o.json").write_text('{"results": [], "no_sources": true}')
        rc, out = self.run_cli()
        self.assertIn("No dependency files found, so there was nothing to check.", out)
        self.assertIn("0 risky dependencies", out)

    def test_scan_deps_osv_exit_codes(self):
        for code, stdout, expect_err in [(0, '{"results": []}', False), (1, '{"results": []}', False),
                                         (128, "", False), (2, "", True)]:
            with mock.patch.object(plainsec.subprocess, "run",
                                   return_value=mock.Mock(returncode=code, stdout=stdout, stderr="boom")):
                data, err = plainsec.scan_deps_osv(self.dir)
            self.assertEqual(err is not None, expect_err, code)
            if code == 128:
                self.assertTrue(data["no_sources"])

    def test_bandit_skips_build_copies(self):
        # Real case: the Action ran `pip install .` first, which copied
        # plainsec.py into build/lib/, and every finding showed up twice.
        with mock.patch.object(plainsec, "run_tool", return_value=({}, None)) as rt:
            plainsec.scan_code(self.dir)
        excluded = rt.call_args[0][0][rt.call_args[0][0].index("-x") + 1].split(",")
        for part in ("/build/", "/dist/", ".egg-info", ".venv", "node_modules"):
            self.assertIn(part, excluded)
        self.assertNotIn("build", excluded)   # would also match rebuild.py

    def test_osv_none_found_falls_back_to_file_by_file(self):
        # Real case (Termux, osv-scanner 2.4.0): folder scan exit 128, but
        # `-L <Cargo.lock>` worked (exit 1, 682 packages).
        (self.dir / "prog").mkdir()
        (self.dir / "prog" / "Cargo.lock").write_text("x")
        (self.dir / "pyproject.toml").write_text("x")                     # not passed with -L
        (self.dir / "node_modules" / "a").mkdir(parents=True)
        (self.dir / "node_modules" / "a" / "package-lock.json").write_text("x")   # skipped
        calls = []
        def run(cmd, **kw):
            calls.append(cmd)
            if "-r" in cmd:
                return mock.Mock(returncode=128, stdout="", stderr="No package sources found")
            return mock.Mock(returncode=1, stdout='{"results": []}', stderr="")
        with mock.patch.object(plainsec.subprocess, "run", side_effect=run):
            data, err = plainsec.scan_deps_osv(self.dir)
        self.assertIsNone(err)
        self.assertEqual(data["file_by_file"], ["prog/Cargo.lock"])
        self.assertEqual(data["not_checked_files"], ["pyproject.toml"])
        self.assertEqual(calls[1][-2:], ["-L", str(self.dir / "prog" / "Cargo.lock")])
        self.assertNotIn("node_modules", " ".join(calls[1]))

    def test_pyproject_without_dependencies_is_nothing_to_check(self):
        # Real case: plainsec's own repo (pyproject.toml, no dependencies) showed
        # "dependencies NOT CHECKED" after the Termux safeguard.
        (self.dir / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = []\n'
            '[project.optional-dependencies]\nscanners = ["bandit"]\n')
        with mock.patch.object(plainsec.subprocess, "run",
                               return_value=mock.Mock(returncode=128, stdout="", stderr="")):
            data, err = plainsec.scan_deps_osv(self.dir)
        self.assertIsNone(err)
        self.assertEqual(data["no_deps_declared"], ["pyproject.toml"])
        (self.dir / "o.json").write_text(json.dumps(data))
        _, out = self.run_cli()
        self.assertIn("`pyproject.toml` declares no dependencies, so there was nothing to check.", out)
        self.assertNotIn("NOT CHECKED", out.split("## 1.")[1].split("## 2.")[0])

    def test_pyproject_with_dependencies_but_no_lock_is_not_checked(self):
        (self.dir / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["requests>=2"]\n')
        with mock.patch.object(plainsec.subprocess, "run",
                               return_value=mock.Mock(returncode=128, stdout="", stderr="")):
            data, err = plainsec.scan_deps_osv(self.dir)
        self.assertIsNone(data)
        self.assertIn("pyproject.toml lists dependencies but there's no lock file", err)

    def test_poetry_dependencies_counted(self):
        f = self.dir / "pyproject.toml"
        f.write_text('[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2"\n')
        self.assertEqual(plainsec.pyproject_dependencies(f), ["requests"])

    def test_osv_none_found_and_fallback_fails_is_not_checked(self):
        (self.dir / "requirements.txt").write_text("x")
        with mock.patch.object(plainsec.subprocess, "run",
                               return_value=mock.Mock(returncode=128, stdout="", stderr="none")):
            data, err = plainsec.scan_deps_osv(self.dir)
        self.assertIsNone(data)
        self.assertIn("requirements.txt", err)
        self.assertIn("Treat dependencies as unchecked", err)

    def test_file_by_file_note_in_report(self):
        d = json.loads((self.dir / "o.json").read_text())
        d["file_by_file"] = ["app/program/Cargo.lock"]
        d["not_checked_files"] = ["pyproject.toml"]
        (self.dir / "o.json").write_text(json.dumps(d))
        _, out = self.run_cli()
        self.assertIn("Checked with osv-scanner, file by file (1: `app/program/Cargo.lock`)", out)
        self.assertIn("NOT checked (osv-scanner can't take these one by one): `pyproject.toml`", out)

    def test_osv_none_found_really_empty(self):
        with mock.patch.object(plainsec.subprocess, "run",
                               return_value=mock.Mock(returncode=128, stdout="", stderr="")):
            data, err = plainsec.scan_deps_osv(self.dir)          # only b.json/g.json/o.json
        self.assertIsNone(err)
        self.assertTrue(data["no_sources"])

    def test_osv_options_come_before_the_folder(self):
        with mock.patch.object(plainsec.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stdout='{"results": []}', stderr="")) as run:
            plainsec.scan_deps_osv(self.dir)
        cmd = run.call_args[0][0]
        self.assertLess(cmd.index("--format"), cmd.index(str(self.dir)))
        self.assertEqual(cmd[-1], str(self.dir))

    def test_osv_preferred_when_installed_pip_audit_fallback(self):
        calls = []
        def fake_which(n):
            return "/x/osv-scanner" if n == "osv-scanner" else None
        with mock.patch.object(plainsec.shutil, "which", side_effect=fake_which), \
             mock.patch.object(plainsec, "scan_deps_osv", side_effect=lambda f: (calls.append(f), ({"results": []}, None))[1]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                plainsec.main([str(self.dir), "--bandit-json", str(self.dir / "b.json"),
                               "--secrets-json", str(self.dir / "g.json")])
        self.assertEqual(len(calls), 1)
        self.assertIn("Checked with osv-scanner", out.getvalue())

    def test_reclassified_as_notice_is_not_gone(self):
        # first scan: ansi_term counted as risky (no informational marker)
        pkgs = self.data["results"][1]["packages"]
        marker = pkgs[1]["vulnerabilities"][0].pop("database_specific")
        pkgs[1]["vulnerabilities"][0]["summary"] = "a real bug"
        (self.dir / "o.json").write_text(json.dumps(self.data))
        self.run_cli()
        pkgs[1]["vulnerabilities"][0]["database_specific"] = marker      # now a notice
        (self.dir / "o.json").write_text(json.dumps(self.data))
        self.assertIn("0 new, 0 gone", self.run_cli()[1])

    def test_history_with_sources_and_old_format(self):
        self.run_cli()
        sf = next(Path(self.state.name).iterdir())
        self.assertTrue(all(fp.count("|") == 2 for fp in json.loads(sf.read_text())["deps"]))
        self.assertIn("0 new, 0 gone", self.run_cli()[1])
        self.assertEqual(plainsec._upgrade_dep_fp("requests|PYSEC-1"),
                         "requirements.txt|requests|PYSEC-1")


class TestTermuxWording(unittest.TestCase):
    """From the first Termux report on demo-project (Nov 20)."""

    def test_missing_dependency_tool_points_to_osv_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, err = plainsec.scan_deps(tmp)
        self.assertIn("install osv-scanner", err)
        self.assertIn("Adding `--audit-env` to the plainsec command", err)

    def test_install_hint_per_platform(self):
        with mock.patch.dict(os.environ, {"PREFIX": "/data/data/com.termux/files/usr"}):
            hint = plainsec.install_hint("gitleaks")
            self.assertIn("`pkg install golang && go install github.com/zricethezav/gitleaks/v8@latest`", hint)
            self.assertIn("~/go/bin", hint)
            self.assertIn("pip install bandit", plainsec.install_hint("bandit"))
            self.assertIn("GOTOOLCHAIN=local go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0",
                          plainsec.install_hint("osv-scanner"))
        with mock.patch.dict(os.environ, {"PREFIX": ""}):
            self.assertIn("sudo apt install gitleaks", plainsec.install_hint("gitleaks"))
            self.assertNotIn("go install", plainsec.install_hint("gitleaks"))

    def test_missing_gitleaks_says_what_it_is_for(self):
        with mock.patch.object(plainsec.shutil, "which", return_value=None):
            _, err = plainsec.scan_secrets(".")
        self.assertIn("gitleaks is not installed (gitleaks finds leaked keys", err)
        self.assertIn("To install:", err)

    def test_test_files_tagged_in_where_lines(self):
        code = plainsec.parse_bandit({"results": [
            finding("B110", "sandbox-tool/tests/test_sandbox_tool.py", 1372),
            finding("B110", "app/run.py", 3)]})
        report = plainsec.build_report("x", code, [], [])
        self.assertIn("test_sandbox_tool.py` — line 1372 — test file, often harmless there", report)
        self.assertIn("`app/run.py` — line 3\n", report + "\n")

    def test_b103_in_tests_is_hidden(self):
        # Real case: OXX-Terminal's only "fix first" item was B103 in a test.
        code = plainsec.parse_bandit({"results": [
            finding("B103", "sandbox-tool/tests/test_sandbox_tool.py", 1372, "MEDIUM"),
            finding("B103", "app/run.py", 3, "MEDIUM")]})
        report = plainsec.build_report("x", code, [], [])
        self.assertIn("1 to fix first", report)
        self.assertIn("- B103: 1", report)
        self.assertNotIn("test_sandbox_tool.py", report)

    def test_identical_files_listed_once(self):
        # Real case: glitch_hunter.py and claude/misc/glitch_hunter.py are copies.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "claude" / "misc").mkdir(parents=True)
            (root / "glitch_hunter.py").write_text("x = 1\n")
            (root / "claude" / "misc" / "glitch_hunter.py").write_text("x = 1\n")
            (root / "other.py").write_text("y = 2\n")
            code = plainsec.parse_bandit({"results": [
                finding("B110", "glitch_hunter.py", 338),
                finding("B110", "claude/misc/glitch_hunter.py", 338),
                finding("B110", "other.py", 5)]})
            kept, n = plainsec.merge_copies(code, root)
            self.assertEqual(n, 1)
            self.assertEqual(sorted(f["file"] for f in kept), ["glitch_hunter.py", "other.py"])
            report = plainsec.build_report("x", kept, [], [], n_copies=n)
            self.assertIn("2 low-priority", report)
            self.assertIn("`glitch_hunter.py` — line 338 — same file also at "
                          "`claude/misc/glitch_hunter.py`", report)
            self.assertIn("1 file is an exact copy of another file here", report)
            self.assertIn("Fixing one copy doesn't fix the others", report)


class TestCli(unittest.TestCase):
    def test_main_with_saved_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp, "b.json"); b.write_text(json.dumps(BANDIT_SAMPLE))
            a = Path(tmp, "a.json"); a.write_text(json.dumps(AUDIT_SAMPLE))
            out = Path(tmp, "r.md")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = plainsec.main([tmp, "--bandit-json", str(b),
                                      "--audit-json", str(a), "--out", str(out)])
            self.assertEqual(code, 1)
            self.assertIn("# Security report", out.read_text())

    def test_clean_project_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp, "b.json"); b.write_text('{"results": []}')
            a = Path(tmp, "a.json"); a.write_text('{"dependencies": []}')
            g = Path(tmp, "g.json"); g.write_text('[]')
            with contextlib.redirect_stdout(io.StringIO()):
                rc = plainsec.main([tmp, "--bandit-json", str(b), "--audit-json", str(a),
                                    "--secrets-json", str(g)])
            self.assertEqual(rc, 0)
            with contextlib.redirect_stdout(io.StringIO()), \
                 mock.patch.object(plainsec.shutil, "which", return_value=None):
                rc = plainsec.main([tmp, "--bandit-json", str(b), "--audit-json", str(a)])
            self.assertEqual(rc, 1, "secrets not checked must not count as clean")


if __name__ == "__main__":
    unittest.main()
