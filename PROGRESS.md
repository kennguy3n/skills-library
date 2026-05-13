# Skills Library — Progress

**Last updated:** 2026-05-12
**Current phase:** Phase 3 (In Progress)
**Overall progress:** 78 / 150 items complete

### Changelog

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
- [ ] Linux `.deb` via `nfpm`
- [ ] Linux `.rpm` via `nfpm`

### Package managers
- [ ] Homebrew tap (`kennguy3n/tap/skills-check`)
- [ ] Winget manifest
- [ ] Scoop bucket
- [ ] APT / YUM release repo

### Post-install + signing
- [ ] First-run prompt to set up scheduled updates
- [ ] macOS Developer ID signing + notarization
- [ ] Windows Authenticode signing
- [ ] CLI self-update (separate from rule updates) with signature verification

### Documentation
- [ ] "Install on macOS" page
- [ ] "Install on Linux" page
- [ ] "Install on Windows" page
- [ ] "Roll out to a team" admin guide
- [ ] "Air-gapped installation" guide

---

## Phase 4: Detection Rules + MCP Server

### Sigma rule extraction
- [ ] Audit of existing `uneycom/shieldnet-security-detection-rules`
- [ ] Audit of existing `kennguy3n/sn360-security-platform` rules
- [ ] `rules/cloud/aws/`
- [ ] `rules/cloud/gcp/`
- [ ] `rules/cloud/azure/`
- [ ] `rules/endpoint/linux/`
- [ ] `rules/endpoint/macos/`
- [ ] `rules/endpoint/windows/`
- [ ] `rules/container/k8s/`
- [ ] `rules/saas/o365/`

### MCP server (`cmd/skills-mcp/`)
- [ ] Model Context Protocol stdio implementation
- [ ] Tool: `lookup_vulnerability(package, ecosystem, version)`
- [ ] Tool: `check_secret_pattern(text)`
- [ ] Tool: `get_skill(skill_id, budget)`
- [ ] Tool: `search_skills(query)`

### Additional skills (target 20+)
- [ ] `iac-security`
- [ ] `container-security`
- [ ] `frontend-security`
- [ ] `database-security`
- [ ] `crypto-misuse`
- [ ] `auth-security`
- [ ] `serverless-security`
- [ ] `mobile-security`
- [ ] `ml-security`
- [ ] `protocol-security`
- [ ] `error-handling-security`
- [ ] `logging-security`
- [ ] `cors-security`

---

## Phase 5: Enterprise Features + Community Growth

### Custom skill authoring
- [ ] `skills-check new <skill-id>`
- [ ] `skills-check test <skill-id>`
- [ ] `kennguy3n/skill-template` repo

### Enterprise profiles
- [ ] `--profile financial-services` (PCI-DSS, SOC 2)
- [ ] `--profile healthcare` (HIPAA)
- [ ] `--profile government` (FedRAMP, FISMA)

### Compliance evidence
- [ ] `skills-check evidence --framework SOC2`
- [ ] `skills-check evidence --framework HIPAA`
- [ ] `skills-check evidence --framework PCI-DSS`

### Private repository support
- [ ] `skills-check configure --source <url>`
- [ ] Org-specific signing keys
- [ ] Private skill bundles

### Language SDKs
- [ ] Go SDK (`sdk/go/`)
- [ ] Python SDK (`sdk/python/`)
- [ ] TypeScript SDK (`sdk/typescript/`)

### Localization (Phase 5b)
- [ ] Spanish
- [ ] French
- [ ] German
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
