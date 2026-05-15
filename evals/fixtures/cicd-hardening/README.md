# `evals/fixtures/cicd-hardening`

GitHub Actions workflow files with known anti-patterns. The P3 MCP
tool `scan_github_actions` is run against each file and the SARIF
output is compared to `expected.json`.

Anti-patterns covered, with citation:

| Anti-pattern | Source skill |
| --- | --- |
| `uses: actions/checkout@v4` (unpinned) | `skills/cicd-security/checklists/github_actions_hardening.yaml` rule `pinned-sha` |
| `pull_request_target` + checkout of PR head | same checklist, rule `pull-request-target-checkout` |
| `permissions: write-all` | same checklist, rule `overbroad-permissions` |
| `curl … \| sh` in a `run:` step | same checklist, rule `curl-pipe-sh` |
| Secrets interpolated into a `run:` step | same checklist, rule `secret-in-run` |

Layout: one `.yml` per anti-pattern + an `expected.json` per file.
