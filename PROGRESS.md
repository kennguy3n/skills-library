# secure-code — Progress

**Last updated:** 2026-05-14
**Current phase:** Phase 5 (In Progress)
**Overall progress:** 145 / 150 items complete

### Changelog

- **2026-05-14 (SaaS Sigma rule expansion)** — Added Sigma detection rules for
  Google Workspace (4 rules), Salesforce (3 rules), and Slack (3 rules) under
  `rules/saas/`. Updated `rules/README.md`, `PHASES.md`, and `PROGRESS.md` to
  reflect expanded SaaS log-source coverage.
- **2026-05-14 (documentation refresh + brand)** — Project re-branded to **secure-code**
  (Go module path `github.com/kennguy3n/skills-library` and CLI binary `skills-check`
  remain stable). LICENSE updated to MIT with attribution to **ShieldNet360**
  (https://www.shieldnet360.com). Every Markdown file in the repo audited for
  consistency with the current code state: 28 skills, 9 supply-chain ecosystems, 74
  DLP patterns, 58 CVE detection patterns, 71 typosquats. Added `CONTRIBUTING.md`
  and `SECURITY.md` to bring the project up to top-tier OSS norms.
- **2026-05-14 (compliance mappings)** — Added `saas-security` and
  `iam-best-practices` to `cwe_mapping.yaml` (CWE-798/284/1392 and CWE-269/250/284)
  and `owasp_mapping.yaml` (A02/A07 and A01/A07). All 28 skills are now mapped to
  CWE and OWASP frameworks.
- **2026-05-13 (SaaS security + locale audit)** — Added the 28th skill,
  `saas-security`, covering 14 platforms across 15 rule files (Google Workspace,
  Google Chat, Atlassian Jira/Confluence, Notion, HubSpot, Salesforce, BambooHR,
  Workday, Odoo, Slack, Microsoft Teams, LarkSuite, Zoom, Calendly, NetSuite).
  `dlp_patterns.json` extended 53 → 74 with 21 new SaaS-token regexes. Published
  `docs/LOCALE_AUDIT.md` enumerating language coverage for top-10 world languages,
  the GCC region (Arabic), Southeast Asia, and Germany, with tier-1–3 recommendations.
- **2026-05-13 (10-year coverage expansion)** — Backfilled supply-chain history 2015-2025 across every database. `cve_patterns.json` expanded from 10 → 58 entries (ImageTragick / Dirty COW / Shiro / EternalBlue / Struts2 / Drupalgeddon / BlueKeep / runc / Zerologon / ProxyLogon / PrintNightmare / Text4Shell / MOVEit / Citrix Bleed / HTTP/2 Rapid Reset / regreSSHion / Next.js middleware / IngressNightmare …). `npm.json` 10 → 32 (left-pad, crossenv, getcookies, flatmap-stream, electron-native-notify, twilio-npm, fallguys, @ledgerhq/connect-kit, @solana/web3.js, lottie-player, rand-user-agent, ethers-provider2 …). `pypi.json` 13 → 30 (ssh-decorator, diango/djago/urllib, python3-dateutil, jeIlyfish, W4SP Stealer, pycord-self, AI-hallucination squats …). Added 5 new ecosystem files: `rubygems.json` (rest-client / strong_password / bootstrap-sass …), `maven.json` (Text4Shell / Sonatype 742-package wave / Spring4Shell …), `nuget.json` (Guna typosquat / Moq SponsorLink / SeroXen RAT …), `github-actions.json` (tj-actions / reviewdog / Codecov bash uploader / Ultralytics / pwn-request class), `docker.json` (TeamTNT / Kinsing / Sysdig 2023 wave / build-cache poisoning). `known_typosquats.json` 15 → 71 entries. `dlp_patterns.json` 26 → 53 patterns (Grafana, Shopify, Vercel, Railway, PlanetScale, Doppler, Postman, Fly.io, Netlify, Clerk, MongoDB Atlas, Snyk, Terraform, Airtable, Notion, Figma, Okta, New Relic, Buildkite, OpenAI Project, Pulumi, npm Granular, Slack/Discord webhooks). 6 new skills shipped: `cicd-security`, `ssrf-prevention`, `deserialization-security`, `graphql-security`, `file-upload-security`, `websocket-security`. Total skill count 21 → 27. `secret-detection` bumped to v1.4.0.
- **2026-05-13 (Phase 4 + Phase 5)** — Hardened DLP patterns (GitHub fine-grained PAT, Anthropic, Azure AD, Databricks, Datadog, Twilio, SendGrid, npm, PyPI, Heroku, DigitalOcean, Vault, Supabase, Linear) and bumped `secret-detection` to v1.3.0 with a denylist-aware test runner. Expanded npm/pypi/go/crates vulnerability databases with documented incidents (`coa`, `rc`, `eslint-scope`, polyfill.io, `ultralytics`, pytorch-nightly, `aiocpa`, requests typosquats, colourama) and added xz-utils/Log4Shell/Spring4Shell/codecov entries to `cve_patterns.json`. Expanded the top-50 typosquat database per ecosystem. Added 13 new skills (`iac-security`, `container-security`, `frontend-security`, `database-security`, `crypto-misuse`, `auth-security`, `serverless-security`, `mobile-security`, `ml-security`, `protocol-security`, `error-handling-security`, `logging-security`, `cors-security`). Phase 5: `skills-check new <id>` scaffolder, `skills-check test <id>` corpus runner, three enterprise profiles (`financial-services`, `healthcare`, `government`) with `--profile` flag in `init` / `regenerate`, `skills-check evidence --framework SOC2|HIPAA|PCI-DSS` with mappings under `compliance/`, `skills-check configure` for private-repo / org deployments, multi-trusted-key `VerifyAny` + bearer-token HTTPSource, Go / Python / TypeScript SDKs under `sdk/`, and Spanish / French / German translations of the top 3 skills under `locales/`.
- **2026-05-13** — Phase 3 completion + Phase 4 partial: Linux `.deb` / `.rpm` packaging (`packaging/linux/nfpm.yaml` + Makefile); Homebrew / Winget / Scoop / APT / YUM manifests (`packaging/{homebrew,winget,scoop,apt-yum}/`); first-run scheduler prompt in `skills-check init` + `--no-prompt` flag; conditional macOS notarization and Windows Authenticode signing in `.github/workflows/release.yml` (no-op without secrets, documented in `packaging/codesign/README.md`); `skills-check self-update` with SHA-256 verification against published `checksums-<goos>-<goarch>.txt`; 5 install / admin docs in `docs/`; 16 Sigma detection rules across AWS / GCP / Azure / Linux / macOS / Windows / K8s / O365 (`rules/`); `skills-mcp` MCP server (`cmd/skills-mcp/`) over JSON-RPC stdio exposing `lookup_vulnerability`, `check_secret_pattern`, `get_skill`, and `search_skills`; relocation of `skill` parser to top-level `internal/skill` so both binaries can import it.
- **2026-05-12** — Phase 2 + Phase 3 implementation: vulnerability data (`crates.json`, `go.json`, `known_typosquats.json`, `dependency-confusion/patterns.json`, `cve/code-relevant/cve_patterns.json`); manifest system with SHA-256 checksums, Ed25519 sign/verify, build-time public key embedding, delta patches, atomic writes, verify-before-replace flow; real `skills-check update` with `--check-only`, `--rollback`, `--source` (HTTP / local directory / tarball); `skills-check manifest compute/verify/sign/delta` subcommands; cross-platform scheduler (`launchd`, `systemd --user`, Windows Task Scheduler) with `skills-check scheduler install/remove/status`; `packaging/macos` (pkgbuild + productbuild) and `packaging/windows` (WiX) installers; release workflow with multi-platform reproducible builds; CI checks for `last_updated`, manifest verify, vulnerability references; full Go test suite covering manifest, updater, scheduler.
- **2026-05-12** — Phase 1 implementation: `skills-check` Go CLI (init / update / validate / list / regenerate / version), `internal/skill` SKILL.md parser, `internal/token` tiktoken-go counter (1.3x Claude multiplier), `internal/compiler` with 8 IDE formatters, all 8 `dist/` files generated, `dictionaries/attack_techniques.yaml`, supply-chain-security test corpus, CI jobs for Go build/test/vet/format, rule-file schema, token budgets, and `dist/` regeneration drift.

This document mirrors the deliverables in [PHASES.md](./PHASES.md). Items are checked off
as they ship.

---

## Phase 1: Core Skills + CLI Foundation (MVP)

### Skill manifests (`skills/`)
- [x] `skills/secret-detection/SKILL.md` + `rules/dlp_patterns.json` + `rules/dlp_exclusions.json` + `tests/corpus.json`
- [x] `skills/dependency-audit/SKILL.md` + `rules/known_malicious.json`
- [x] `skills/secure-code-review/SKILL.md` + `checklists/owasp_top10.yaml` + `checklists/injection_patterns.yaml`
- [x] `skills/supply-chain-security/SKILL.md` + `rules/typosquat_patterns.json` + `rules/dependency_confusion.json` + `tests/corpus.json`
- [x] `skills/infrastructure-security/SKILL.md` + `checklists/k8s_hardening.yaml` + `checklists/docker_security.yaml` + `checklists/terraform_security.yaml`
- [x] `skills/api-security/SKILL.md` + `checklists/auth_patterns.yaml` + `checklists/input_validation.yaml`
- [x] `skills/compliance-awareness/SKILL.md` + `frameworks/owasp_mapping.yaml` + `frameworks/cwe_mapping.yaml`

### CLI (`cmd/skills-check/`)
- [x] `skills-check init --tool <tool> --skills <list> --budget <tier>`
- [x] `skills-check update [--regenerate]` (scaffold; remote update channel is Phase 2)
- [x] `skills-check validate [--path <dir>]`
- [x] `skills-check list [--category <cat>]`
- [x] `skills-check regenerate [--tool <tool>] [--budget <tier>]`
- [x] `skills-check version`
- [x] Cobra-based command framework
- [x] Single-binary build via `go build -trimpath -ldflags "-s -w"`

### `dist/` compiler outputs
- [x] `dist/CLAUDE.md`
- [x] `dist/.cursorrules`
- [x] `dist/copilot-instructions.md`
- [x] `dist/AGENTS.md`
- [x] `dist/.windsurfrules`
- [x] `dist/devin.md`
- [x] `dist/.clinerules`
- [x] `dist/SECURITY-SKILLS.md`

### Token budget system
- [x] `minimal` tier extraction (ALWAYS + NEVER bullets only)
- [x] `compact` tier extraction (full Rules + KFP + references)
- [x] `full` tier extraction (everything, including Context)
- [x] `tiktoken-go` integration for OpenAI-family counts (`cl100k_base`)
- [x] Claude conservative `1.3x` multiplier
- [x] Per-skill budget enforcement at compile time (`skills-check validate`)

### CI pipeline
- [x] `.github/workflows/validate.yml` scaffolded (Phase 1 baseline: JSON + YAML syntax checks)
- [x] Schema validation of every `SKILL.md` frontmatter
- [x] Rule file JSON schema validation (`schema_version` required on every rules/checklists/frameworks/tests file)
- [x] Markdown link check
- [x] Token budget enforcement (`skills-check validate` job)
- [x] `dist/` files regenerated and diffed against committed copy

### Dictionaries
- [x] `dictionaries/security_terms.yaml` scaffolded
- [x] `dictionaries/cwe_top25.yaml` scaffolded
- [x] `dictionaries/owasp_top10_2025.yaml` scaffolded
- [x] `dictionaries/attack_techniques.yaml`

### Documentation
- [x] `README.md`
- [x] `PROPOSAL.md`
- [x] `ARCHITECTURE.md`
- [x] `PHASES.md`
- [x] `PROGRESS.md`

---

## Phase 2: Vulnerability Database + Remote Updates

### Vulnerability data
- [x] `vulnerabilities/manifest.json` scaffolded
- [x] `vulnerabilities/supply-chain/malicious-packages/npm.json` (initial well-known examples)
- [x] `vulnerabilities/supply-chain/malicious-packages/pypi.json` (initial well-known examples)
- [x] `vulnerabilities/supply-chain/malicious-packages/crates.json`
- [x] `vulnerabilities/supply-chain/malicious-packages/go.json`
- [x] `vulnerabilities/supply-chain/typosquat-db/known_typosquats.json`
- [x] `vulnerabilities/supply-chain/dependency-confusion/patterns.json`
- [x] `vulnerabilities/cve/code-relevant/cve_patterns.json`

### Manifest system
- [x] Root `manifest.json` scaffolded
- [x] SHA-256 checksums for every distributable file
- [x] Ed25519 signing of manifests
- [x] Embedded public key in CLI build
- [x] Delta patch generation for large vulnerability files
- [x] Atomic write (temp file + `rename`) on updates
- [x] Verify-before-replace flow

### CLI update commands
- [x] `skills-check update`
- [x] `skills-check update --check-only`
- [x] `skills-check update --rollback`
- [x] Configurable update source (`--source`)
- [x] Offline / air-gapped update path (manual tarball)

### Release workflow
- [x] GitHub Actions workflow to build manifest on tag push
- [x] Out-of-band signing step (YubiKey-backed) documented in [SIGNING.md](./SIGNING.md)
- [x] Publish manifest + delta patches as release assets
- [x] Reproducible CLI binary builds

### CI validation
- [x] `last_updated` timestamp check on modified files
- [x] Checksum regeneration check on modified files
- [x] Vulnerability entry reference validation

---

## Phase 3: Scheduled Updates + Cross-Platform Installers

### Scheduled tasks
- [x] macOS LaunchAgent generator
- [x] Linux systemd user timer generator
- [x] Windows Task Scheduler integration
- [x] `skills-check scheduler install --interval <duration>`
- [x] `skills-check scheduler remove`

### Platform installers
- [x] macOS `.pkg` via `pkgbuild` + `productbuild`
- [x] Windows MSI via WiX Toolset
- [x] Linux `.deb` via `nfpm`
- [x] Linux `.rpm` via `nfpm`

### Package managers
- [x] Homebrew tap (`kennguy3n/tap/skills-check`)
- [x] Winget manifest
- [x] Scoop bucket
- [x] APT / YUM release repo

### Post-install + signing
- [x] First-run prompt to set up scheduled updates
- [x] macOS Developer ID signing + notarization (CI scaffold — runs when `secrets.APPLE_DEVELOPER_ID` configured)
- [x] Windows Authenticode signing (CI scaffold — runs when `secrets.WINDOWS_CERT_PFX` configured)
- [x] CLI self-update (separate from rule updates) with signature verification

### Documentation
- [x] "Install on macOS" page
- [x] "Install on Linux" page
- [x] "Install on Windows" page
- [x] "Roll out to a team" admin guide
- [x] "Air-gapped installation" guide

---

## Phase 4: Detection Rules + MCP Server

### Sigma rule extraction
- [x] `rules/cloud/aws/`
- [x] `rules/cloud/gcp/`
- [x] `rules/cloud/azure/`
- [x] `rules/endpoint/linux/`
- [x] `rules/endpoint/macos/`
- [x] `rules/endpoint/windows/`
- [x] `rules/container/k8s/`
- [x] `rules/saas/o365/`
- [x] `rules/saas/google_workspace/`
- [x] `rules/saas/salesforce/`
- [x] `rules/saas/slack/`

### MCP server (`cmd/skills-mcp/`)
- [x] Model Context Protocol stdio implementation
- [x] Tool: `lookup_vulnerability(package, ecosystem, version)`
- [x] Tool: `check_secret_pattern(text)`
- [x] Tool: `get_skill(skill_id, budget)`
- [x] Tool: `search_skills(query)`

### Additional skills (target 20+)
- [x] `iac-security`
- [x] `container-security`
- [x] `frontend-security`
- [x] `database-security`
- [x] `crypto-misuse`
- [x] `auth-security`
- [x] `serverless-security`
- [x] `mobile-security`
- [x] `ml-security`
- [x] `protocol-security`
- [x] `error-handling-security`
- [x] `logging-security`
- [x] `cors-security`

---

## Phase 5: Enterprise Features + Community Growth

### Custom skill authoring
- [x] `skills-check new <skill-id>`
- [x] `skills-check test <skill-id>`
- [ ] `kennguy3n/skill-template` repo

### Enterprise profiles
- [x] `--profile financial-services` (PCI-DSS, SOC 2)
- [x] `--profile healthcare` (HIPAA)
- [x] `--profile government` (FedRAMP, FISMA)

### Compliance evidence
- [x] `skills-check evidence --framework SOC2`
- [x] `skills-check evidence --framework HIPAA`
- [x] `skills-check evidence --framework PCI-DSS`

### Private repository support
- [x] `skills-check configure --source <url>`
- [x] Org-specific signing keys
- [x] Private skill bundles

### Language SDKs
- [x] Go SDK (`sdk/go/`)
- [x] Python SDK (`sdk/python/`)
- [x] TypeScript SDK (`sdk/typescript/`)

### Localization (Phase 5b)
- [x] Spanish
- [x] French
- [x] German
- [ ] Japanese
- [ ] Mandarin
- [ ] Translation review workflow

### Security
- [ ] SBOM generation for Skills Library
- [ ] Third-party audit of signature verification
- [ ] Third-party audit of update protocol
- [ ] Third-party audit of dependency tree

### Community
- [ ] Slack / Discord launch
- [ ] Monthly office hours
- [ ] Quarterly community call
- [ ] Researcher sponsorship program

---

## Notes

This file is updated as deliverables ship. Each phase's introduction tag in PHASES.md
links back to the matching section here for traceability.
