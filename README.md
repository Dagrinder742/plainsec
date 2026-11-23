# plainsec

**Plain-English security reports for code projects.**

Security scanners are great at finding problems and terrible at explaining them.
plainsec runs the scanners you already have, and turns hundreds of lines of raw output
into a short report that says **what each problem means, whether it matters for you,
and the exact command to fix it**.

It's built for beginners and solo developers who find Snyk, Dependabot and raw scanner
output overwhelming.

> **Status: early (0.1.0), and I'm looking for feedback.** If you run it on a repo,
> please [open an issue](https://github.com/Dagrinder742/plainsec/issues) and tell me
> what confused you, what was wrong, or what was missing.

## Before and after

A Solana program's `Cargo.lock`. osv-scanner, on its own, reports **22 vulnerable Rust
crates**. plainsec's headline for the same project:

```
26 risky dependencies (4 high/critical, 6 test-only) + 6 unsound
```

…and then explains, crate by crate:

```
### `app/program/Cargo.lock` (Rust) · 7 packages
- **borsh 0.10.4** · no severity score · ships in your program · 1 issue (GHSA-fjx5-qpf4-xjf2)
  - How: `borsh` isn't in your Cargo.toml: another crate pulls it in. To see which,
    run `cargo tree -i borsh@0.10.4` in `app/program`, then update that crate instead
- **rustls 0.21.12** · MEDIUM · tests only · 3 issues (…)
  - How: only your tests / dev tools use this (dev-dependencies), so it isn't built
    into your program. Lower priority: …
### Unsound code (6): no known attack, but not safe
### Unmaintained (12): not vulnerabilities
```

Of the original 22, **only 2 are actually built into the program**, and neither is a
scored vulnerability. The rest come in through a test-only dependency. Getting to that
answer by hand takes an afternoon with `cargo tree`.

## What it checks

plainsec uses whichever of these you have installed. **A missing scanner is reported as
NOT CHECKED, never as an all-clear.**

| Scanner | Finds | Install |
|---|---|---|
| [bandit](https://github.com/PyCQA/bandit) | risky patterns in Python code | `pipx install bandit` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | leaked keys and passwords, **including in old commits** | `sudo apt install gitleaks`, or a [release](https://github.com/gitleaks/gitleaks/releases) |
| [osv-scanner](https://github.com/google/osv-scanner) | known vulnerabilities in **every** dependency file (Python, Rust, Node, Go…) | a [release](https://github.com/google/osv-scanner/releases) |
| [pip-audit](https://github.com/pypa/pip-audit) | fallback for a top-level `requirements.txt` when osv-scanner isn't installed | `pipx install pip-audit` |
| `cargo` | tells Rust crates used only by tests apart from ones that ship | comes with Rust |

## Install and run

```
pip install git+https://github.com/Dagrinder742/plainsec
plainsec ~/my-project
plainsec ~/my-project --out report.md     # also save the report as Markdown
plainsec https://github.com/owner/repo    # scan a repository without keeping a copy
```

No other Python packages are needed; plainsec itself is a single standard-library file.

### Scanning a repository by its address

Give plainsec an `https://` or SSH (`git@github.com:owner/repo`) address and it downloads
the repository with its full history (so old commits are checked for secrets too) into a
temporary folder, scans it, and deletes the copy. A link copied from your browser works,
including `/tree/<branch>` links. Private repositories work when your git can already log
in (an SSH key, or a saved login); plainsec never asks for a password.

- "Since last scan" follows the address, so `https://` and `git@` addresses of the same
  repository share one history.
- Commands in the report point at your own copy (`~/<repo>`) and say how to get one; on
  GitHub the report also links to the scanned commit.
- A downloaded repository is treated as someone else's code: symlinks are checked out as
  plain files, and the repository's own scanner settings (`bandit.yaml`,
  `.gitleaks.toml`, `osv-scanner.toml`, `.plainsec`) are named in the report, because they
  can switch checks off.

Useful options:

- `--all`: also list findings it normally hides (normal-in-test-file findings) or skips (`.plainsec`)
- `--no-save`: don't update the "since last scan" history
- `--audit-env`: (pip-audit fallback only) check the Python environment pip-audit runs in

## What the report does

- **Groups findings by check:** one explanation, then every place it occurs.
- **"Fix first" vs "low priority".** Normal-in-test-file findings (asserts, fake passwords)
  are counted but hidden; test files that do show up are labelled as such.
- **Secrets are never printed.** gitleaks runs with `--redact`, and the report only shows
  rule, file, line, commit and date. For pattern-based guesses it says *check whether
  it's real first* and gives you the command to look at the line in your own terminal.
  Deleted files that still exist in git history are called out.
- **Dependencies:** one entry per package per file, the version that fixes **all** of its
  issues, and advice that fits the ecosystem (`pip`, `cargo update`, `npm`…). Rust advice
  reads your `Cargo.toml`, so it knows whether you can bump a crate yourself or have to
  update the crate that pulls it in.
- **"Since last scan":** what's new and what's gone. Moving code around, rewriting git
  history, or adding an ignore line doesn't count as a change.
- **Scanning never runs the project's code.** `cargo` is started from your home folder
  with `--manifest-path`, so a project's `.cargo/config.toml` (which can name a program to
  run) and `rust-toolchain.toml` are never read, for downloaded and local folders alike.
- **Never a false all-clear:** a scanner that's missing, fails, or quietly finds nothing
  where dependency files clearly exist is reported as NOT CHECKED.

## Skipping old drafts

Put a `.plainsec` file in the project folder, one path per line:

```
# old experiments, not used any more
old/
drafts/
*_backup.py
```

Skipped findings are still **counted**, HIGH ones are called out, and a line that matches
nothing is flagged as a likely typo. Secrets are never skipped.

## Running it on every push (GitHub Actions)

This repo scans itself on every push: see
[`.github/workflows/plainsec.yml`](.github/workflows/plainsec.yml). The report appears on
each run's summary page. Copy that file into your own repo's `.github/workflows/` to do the
same.

## Known limits

- Tested on Linux (Ubuntu under WSL) and Android (Termux), with Python 3.12 and 3.13.
  **Not yet tested on native Windows or macOS.**
- On Termux, gitleaks and osv-scanner have to be built with `go install` (plainsec prints
  the exact commands). osv-scanner 2.4.0 can't walk folders there, so plainsec passes it
  each dependency file directly.
- "Since last scan" identifies a code finding by the text of the flagged line, so editing
  that line shows up as one gone and one new.
- An old bandit can crash on newer Python (Ubuntu's apt bandit 1.7.10 does on Python 3.14).
  plainsec then says which files weren't checked; `pipx install bandit` gets a current one.

## License

MIT, see [LICENSE](LICENSE).
