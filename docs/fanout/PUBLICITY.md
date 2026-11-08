# PUBLICITY: cyber-range-lab (P24)

This log records channel outcomes for finished work on this repo.
The loop prepares drafts and never posts to social. Pieces were
reviewed before release; review scores are kept internally.

Path note (2026-11-08): the drafts in docs/fanout/ are dated
2026-11-05 and keep the paths of that time. Since the portfolio
standard v2 restructure: level-*/ code is in src/, snapshots, logs
and config are in experiments/, results_*.json are in results/,
level-3-deep/RUNBOOK.md is docs/RUNBOOK.md, fanout/ is docs/fanout/,
and the level READMEs, SPEC.md, DEEP-SPEC.md, NOVELTY.md, DOSSIER.md
and ROADMAP.md are folded into PROPOSAL.md, REPORT.md and
CHANGELOG.md. tests/test_smoke.py became tests/test_layout.py.

## Fan-out set for v1.0 (2026-11-05)

Written fan-out for P24 cyber-range-lab v1.0 (Learn, Build, and
compressed Deep), defensive scope only. Drafts are in docs/fanout/.
No scenario content is in any piece. The loop prepares drafts
and never posts to social.

| Channel | Outcome on 2026-11-05 |
| --- | --- |
| GitHub releases | Live: v0.1 https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.1 , v0.5 https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.5 , v1.0 https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v1.0 (verified with gh release list, 2026-11-05). Draft release notes for all three are in fanout/release-notes.md. No new release was created for the fan-out. |
| Portfolio index | Held: fan-out links are ready, the index update is a coordinator step outside this cycle. Named reason: held for index refresh. |
| Website page | Draft in fanout/website-page.md. Held: not published to jesunahmadushno.com. |
| Blog | Draft in fanout/blog-post.md. Held: not posted. |
| Tutorial | In repo: fanout/tutorial.md. Every command in it was run and verified on 2026-11-05 (three runners, three per-level test modules, scaffold smoke test, full suite at 71 tests). Results files stayed byte-identical across the verification runs. |
| LinkedIn post | Draft in fanout/linkedin-post.md, marked DRAFT NOT POSTED, link carried as the first-comment line per the LinkedIn rule. Held: not posted, loop never posts. |
| X | Draft held: no X copy is shipped in this set beyond the LinkedIn draft source text. Held under the standing social rules; posting is outside the loop. |
| Facebook | Draft held: no Facebook copy posted. Standing rule applies (no link in body or comments, keyword call to action fulfilled by DM). Held: not posted, loop never posts. |
| Instagram | Draft held: no Instagram copy posted. Standing rule applies (no clickable link in caption, link in bio). Held: not posted, loop never posts. |
| Threads | Draft held: no Threads copy posted. Threads waits for Jesun's tap per post, hash-locked on exact text and media. Held: awaiting Jesun's tap. |
| Video | Held: engine queue, January production for lab projects per the December Compression Protocol. No video was produced in this cycle. |
| Book chapter | Draft angle in fanout/blog-post.md (hardening first, detection second). Held: chapter draft follows the finished project set; not a published chapter. |
| Paper candidate | Draft brief in fanout/paper-candidate.md (the detection loop and baseline drift note). Submission is Jesun's tap. Nothing submitted, no venue contacted. The publications tracker is updated by the coordinator, not by this cycle. |

## Jev gate (2026-11-05)

claim_check on the blog main results paragraph, extracted
byte-exact from fanout/blog-post.md by script. Spec:
hidden_files/jev-p24-fanout-claim-spec-2026-11-05.json in the
goal workspace. Results:
hidden_files/jev-p24-fanout-claim-results-2026-11-05.json. Model
jev-1.13.0, question id supported, noul 0.87, route CLEAR
(clear at 0.85 or above, block at 0.10 or below, review
between), input tokens 1329, output tokens 20. Arithmetic was
pre-computed in the spec evidence (10 minus 0 is 10; 22 plus 26
is 48 and 48 plus 23 is 71; 12 plus 5 plus 6 plus 3 is 26;
firings 2 plus 2 plus 1 plus 2 is 7 and 7 plus 2 is 9). No claim
was blocked. The first route tried, jev_gate.py, failed with
TYPESAFE_API_KEY not set, so the gate ran through the
custom.typesafe connector helper, as in prior cycles.

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
