# PUBLICITY: cyber-range-lab (P24)

This log records channel outcomes for finished work on this repo.
The loop prepares drafts and never posts to social. Pieces are
graded on the 1,000-point publicity rubric (accuracy 300, research
200, gap fit 200, clarity 150, reach format 150) before release.
Ship line: 900.

## Actions polish pack (2026-11-05)

Applied through a pull request on 2026-11-05, following the Actions
polish pack standard. The pack adds: CI on a Python 3.11 and 3.12
matrix with a ruff lint step (the pre-existing CI step, the scaffold
smoke test, is preserved, and the per-level unit tests and runners
for Learn, Build, and Deep now run in CI as well), CodeQL scanning,
Dependabot for pip and GitHub Actions, a release workflow that
attaches a source tarball named cyber-range-lab-<tag>.tar.gz to
v* tag releases, Labeler, Greetings (snake_case inputs for
actions/first-interaction@v3: repo_token, issue_message,
pr_message), Stale in comment-only mode (days-before-close: -1,
never closes), and a docs summary page at docs/index.md for GitHub
Pages. Ruff scope is recorded in ruff.toml (E, F, I, line-length
120). requirements.txt records that this project is stdlib-only
and intentionally lists no packages, so Dependabot pip has a
manifest to watch. Ruff fixes in this pull request were style
only: import formatting in the test files, and three long string
lines split by implicit concatenation with identical string
values, with no change to behaviour.

This application is config and docs only. No offensive scenario
content was added. P24 stays defensive work only, and the scenario
list stays held for Jesun's batched sign-off.

| Channel | Outcome on 2026-11-05 |
| --- | --- |
| GitHub Pages | Docs page added at docs/index.md in this pull request. Pages enablement and live build status are verified after merge and recorded in the batch ledger; no live claim is made in this file before that check. |
| PyPI publishing | Held: needs a PyPI token, a new credential. Jesun's tap only. Not set up. |
| Social channels (LinkedIn, X, Facebook, Instagram, Threads) | Held: no posts made. The loop never posts to social; Threads waits for Jesun's tap per post under the standing gates. |

Publicity grade for this polish pack log piece, on the 1,000
point rubric (accuracy 300, research 200, gap fit 200, clarity
150, reach format 150), ship line 900:

| Piece | Accuracy /300 | Research /200 | Gap fit /200 | Clarity /150 | Reach /150 | Total /1000 |
| --- | --- | --- | --- | --- | --- | --- |
| PUBLICITY.md polish pack section (2026-11-05) | 295 | 180 | 195 | 145 | 100 | 915 |

At or above the 900 ship line. Named deductions: research minus
20, because the pack is a standard applied across repos and this
section records its application rather than new research; reach
minus 50, because the docs page is copy in this pull request with
no live Pages claim yet, PyPI publishing is held, and no social
channel carries this piece by the standing gates; accuracy minus
5, gap fit minus 5, and clarity minus 5 for summary compression
of the full pack standard, which lives in the batch files.
