# plainsec

**Plain-English security reports for code projects.**

Security scanners are great at finding problems and terrible at explaining them.
plainsec runs the scanners you already have, and turns hundreds of lines of raw output
into a short report that says **what each problem means, whether it matters for you,
and the exact command to fix it**.

It's built for beginners and solo developers who find Snyk, Dependabot and raw scanner
output overwhelming.

> **Status: early (0.2.8), and I'm looking for feedback.** If you run it on a repo,
> please [open an issue](https://github.com/Dagrinder742/plainsec/issues) and tell me
> what confused you, what was wrong, or what was missing.

## Before and after

A real Solana project (names changed): one Rust `Cargo.lock`. osv-scanner, on its own,
flags **23 crate versions** with **40 advisory IDs**. plainsec's headline for the same file:

```
8 risky dependencies (1 high/critical, 7 test-only) + 6 unsound
```

…plus 12 "unmaintained" notices, listed separately because they aren't vulnerabilities.
3 crates are both unsound and unmaintained, so that's 8 + 6 + 12 − 3 = all 23. Then it
explains each crate (excerpt from the real report):

```
### `app/program/Cargo.lock` (Rust) · 8 packages
- **borsh 0.10.4** · no severity score · ships in your program · 1 issue (GHSA-fjx5-qpf4-xjf2)
  - What it means: Parsing borsh messages with ZST which are not-copy/clone is unsound
  - Fixed in: 1.0.0 or later (first fixed in pre-release 1.0.0-alpha.1)
  - How: `borsh` isn't in your Cargo.toml: it comes in through `solana-program`, `solana-sdk-ids`, `solana-system-interface` (which are in your Cargo.toml). Update those crates.
#### Used only by tests / dev tools (7): lower priority
These come in only through dev-dependencies, so they aren't built into your program.
- **rustls-webpki 0.101.7** · HIGH · 4 issues (CVE-2026-93599, CVE-2026-93600, CVE-2026-93601, CVE-2026-111943)
  …
  - How: `rustls-webpki` isn't in your Cargo.toml: it comes in through `solana-program-test` (which is in your Cargo.toml). Update that crate.
- **url 2.5.8** · no severity score · 1 issue (GHSA-hrj5-67jp-wqp9)
  - How: run `cd ~/demo-repo/app/program && cargo update -p url`; 2.5.9 is a compatible version, so no Cargo.toml change is needed
### Unsound code (6): no known attack, but not safe
- **rand 0.7.3** · ships in your program (`app/program/Cargo.lock`): Rand is unsound with a custom logger using `rand::rng()`
#### Used only by tests / dev tools (5): lower priority
### Unmaintained (12): not vulnerabilities
```

Of the 14 crate versions with a real problem (8 vulnerable + 6 unsound), **only 2 are built into
the program** (borsh and rand), and neither has a severity score. The other 12 come in
only through dev-dependencies (`solana-program-test`, `solana-sdk`). Getting to that answer by hand
takes an afternoon with `cargo tree`.

## What it checks

plainsec uses whichever of these you have installed. **A missing scanner is reported as
NOT CHECKED, never as an all-clear.**

| Scanner | Finds | Install |
|---|---|---|
| [bandit](https://github.com/PyCQA/bandit) | risky patterns in Python code | `pipx install bandit` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | leaked keys and passwords, **including in old commits** | a [release](https://github.com/gitleaks/gitleaks/releases), 8.30 or newer (Ubuntu's `apt install gitleaks` gives 8.16, which misses some secrets; the report says so when an older one ran) |
| [osv-scanner](https://github.com/google/osv-scanner) | known vulnerabilities in **every** dependency file (Python, Rust, Node, Go…) | a [release](https://github.com/google/osv-scanner/releases) |
| [pip-audit](https://github.com/pypa/pip-audit) | fallback for a top-level `requirements.txt` when osv-scanner isn't installed | `pipx install pip-audit` |
| `cargo` | tells Rust crates used only by tests apart from ones that ship | comes with Rust |

## Install and run

```
pipx install git+https://github.com/Dagrinder742/plainsec
plainsec ~/my-project
plainsec ~/my-project --out report.md     # also save the report as Markdown
plainsec https://github.com/owner/repo    # scan a repository without keeping a copy
```

On Termux, or inside a virtual environment, use `pip install git+https://github.com/Dagrinder742/plainsec`
instead. (On Ubuntu 23.04+ and Debian 12+, a plain `pip install` outside a venv is refused
on purpose; pipx gives plainsec its own environment.) To update later: `pipx upgrade
plainsec`, or the same `pip install` with `--upgrade`. To install a fixed version, add its
tag to the URL: `git+https://github.com/Dagrinder742/plainsec@v0.2.8`.

No other Python packages are needed; plainsec itself is a single standard-library file.
The scanners in the table above are installed separately.

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
- The temporary copy is deleted even when the scan is stopped (Ctrl-C, `kill`, or closing
  the terminal). If it was stopped too hard for that (`kill -9`, power loss), the next URL
  scan removes the leftover, but only once the scan that made it is no longer running.

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
  The setting's *name* (never its value) adds a note: `*_TOKEN`, `*_SECRET`, `*_PASSWORD`
  and similar are flagged to check first; names that say hash or ID are noted as usually
  fine, except API key IDs, which are half of a login.
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

Copy [`examples/plainsec-workflow.yml`](examples/plainsec-workflow.yml) to
`.github/workflows/plainsec.yml` in your repository. It installs plainsec and the scanners
(gitleaks and osv-scanner from their official releases, checksum-verified), runs
`plainsec . --out report.md --no-save`, and puts the report on each run's summary page and
as a downloadable file. It never fails your build: the report is information.

(This repo's own [`.github/workflows/plainsec.yml`](.github/workflows/plainsec.yml) is
different: it also runs plainsec's tests and installs plainsec from this checkout, so it
only works here.)

In CI there's no earlier scan, so the report can't show "since last scan".

## Privacy

Your code stays on your machine (or your CI runner): the scanners run locally, and plainsec
itself sends nothing anywhere. What does leave it:

- **osv-scanner** looks up each dependency's **name and version** in the
  [osv.dev](https://osv.dev) database (pip-audit, the fallback, asks PyPI's). Not your code.
- **`cargo tree`** may fetch crate metadata from crates.io to work out which crates ship.
- **Commands the report suggests** go further only when you run them: `npm audit fix
  --package-lock-only`, for example, sends your project's package list to npm's servers.
- **URL scans** download the repository from wherever it's hosted, like a `git clone`.

bandit and gitleaks work entirely offline, and secrets are never printed in the report.

## Known limits

- The test suite passes on Python 3.11, 3.12, 3.13 and 3.14: 3.12 on Ubuntu in GitHub
  Actions, 3.11 and 3.13 on Android (Termux), 3.14 on Ubuntu (in proot on Android). Real
  scans: Android (Termux), Ubuntu in GitHub Actions, and Ubuntu under WSL (an earlier
  version). Python 3.9 and 3.10 are allowed but not tested yet.
  **Not yet tested on native Windows or macOS.**
- On Termux, gitleaks and osv-scanner have to be built with `go install` (plainsec prints
  the exact commands). osv-scanner 2.4.0 can't walk folders there, so plainsec passes it
  each dependency file directly.
- "Since last scan" identifies a code finding by the text of the flagged line, so editing
  that line shows up as one gone and one new.
- An old bandit can crash on newer Python (Ubuntu's apt bandit 1.7.10 does on Python 3.14).
  plainsec then says which files weren't checked; `pipx install bandit` gets a current one.
  Files that aren't valid Python at all (broken drafts) are named with Python's own error
  and line, so you can tell them apart from a bandit problem.

## License

MIT, see [LICENSE](LICENSE).
