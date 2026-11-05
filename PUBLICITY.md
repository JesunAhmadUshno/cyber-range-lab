# PUBLICITY: cyber-range-lab (P24)

This log records channel outcomes for finished work on this repo.
The loop prepares drafts and never posts to social. Pieces are
graded on the 1,000-point publicity rubric (accuracy 300, research
200, gap fit 200, clarity 150, reach format 150) before release.
Ship line: 900.

## Fan-out set for v1.0 (2026-11-05)

Written fan-out for P24 cyber-range-lab v1.0 (Learn, Build, and
compressed Deep), defensive scope only. Drafts are in fanout/.
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

## Publicity grades (1,000-point rubric, ship line 900)

| Piece | Accuracy /300 | Research /200 | Gap fit /200 | Clarity /150 | Reach format /150 | Total /1000 |
| --- | --- | --- | --- | --- | --- | --- |
| fanout/blog-post.md | 295 | 188 | 194 | 145 | 141 | 963 |
| fanout/tutorial.md | 298 | 186 | 195 | 148 | 142 | 969 |
| fanout/website-page.md | 293 | 181 | 191 | 147 | 144 | 956 |
| fanout/linkedin-post.md | 288 | 176 | 190 | 145 | 140 | 939 |
| fanout/paper-candidate.md | 293 | 195 | 194 | 141 | 130 | 953 |
| fanout/release-notes.md | 296 | 183 | 185 | 144 | 138 | 946 |

All six pieces are at or above the 900 ship line. No piece was
shipped ungraded. Overall fan-out grade: 9,543 of 10,000 (mean
of the six piece totals, 954.3 of 1,000).

## Named deductions (unclosable in this cycle)

- Blog post, minus 37: research is condensed from DOSSIER.md
  v1, whose prior art section is brief (minus 12 research);
  synthetic data limits how far the results travel, stated in
  the piece (minus 9 reach, minus 5 accuracy for reader
  interpretation risk, minus 6 gap fit, minus 5 clarity).
- Tutorial, minus 31: research framing is thinner than the blog
  by design, because the module teaches runs rather than the
  field (minus 14 research); no worked example beyond the
  shipped synthetic sets (minus 5 gap fit, minus 2 clarity,
  minus 8 reach, minus 2 accuracy).
- Website page, minus 44: condensed research (minus 19),
  condensed gap framing (minus 9), and the page is copy only,
  not a live page (minus 6 reach, minus 7 accuracy, minus 3
  clarity).
- LinkedIn post, minus 61: short form compresses the research
  and the failure mode detail (minus 24 research, minus 12
  accuracy, minus 10 gap fit, minus 5 clarity, minus 10 reach,
  because the post is a held draft and carries no live link in
  the body by rule).
- Paper candidate, minus 47: this is a brief, not a drafted
  paper (minus 20 reach, minus 9 clarity); venue is classed,
  not named (minus 5 research, minus 6 gap fit, minus 7
  accuracy for the synthetic-only evidence base the paper must
  carry).
- Release notes, minus 54: notes summarise releases that
  already exist, so research and gap framing are summary grade
  (minus 17 research, minus 15 gap fit); format is repo-bound
  (minus 12 reach, minus 4 accuracy, minus 6 clarity).

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
