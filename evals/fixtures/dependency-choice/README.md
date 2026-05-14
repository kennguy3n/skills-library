# `evals/fixtures/dependency-choice`

Project fixtures that contain known-malicious packages or
typosquats. The eval harness runs `scan_dependencies` (P3 MCP tool)
against each fixture and checks that every planted bad package is
reported, and that no clean package is reported.

Layout:

```
dependency-choice/
├── npm-malicious/         # package.json + lockfile with one malicious row
├── npm-typosquat/         # package.json with a typosquat candidate
├── pypi-malicious/        # requirements.txt with one known-bad package
└── go-clean/              # control: a clean go.sum with no bad deps
```

Each subdirectory carries an `expected.json` describing the planted
findings:

```json
{
  "expected_findings": [
    {"ecosystem": "npm", "package": "event-stream", "kind": "malicious"}
  ],
  "expected_clean": ["lodash", "react"]
}
```

The harness compares this against the SARIF returned by
`scan_dependencies` and reports precision / recall per category.

To add a fixture: pick an entry already in
`vulnerabilities/supply-chain/malicious-packages/<eco>.json` or
`vulnerabilities/supply-chain/typosquats/known_typosquats.json` —
never invent a name.
