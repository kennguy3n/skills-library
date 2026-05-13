# Skills Library — Phased Delivery Plan

The library is delivered in five phases. Each phase is independently useful: any team can
stop after Phase 1 and still have a working library, then opt into Phase 2+ as needs grow.

The numbering matches the milestones tracked in [PROGRESS.md](./PROGRESS.md).

---

## Phase 1: Core Skills + CLI Foundation (MVP)

**Covers:** seven canonical skills, the `skills-check` CLI, the `dist/` compiler, and the
CI pipeline that validates every PR. The deliverable is a library that a developer can
clone, generate IDE files from, and commit into their project today.

### Deliverables

- [x] Seven skill manifests under `skills/`, each with `SKILL.md` + supporting rule files:
  - `secret-detection`
  - `dependency-audit`
  - `secure-code-review`
  - `supply-chain-security`
  - `infrastructure-security`
  - `api-security`
  - `compliance-awareness`
- [x] `skills-check` Go CLI with the following commands:
  - `init` — generate IDE-specific config in target project
  - `update` — scaffold for Phase 2 (remote update channel)
  - `validate` — check `SKILL.md` schema, rule file syntax, token budgets
  - `list` — list available skills with token counts per tier
  - `regenerate` — rebuild `dist/` files from current skills
  - `version` — display CLI version, library version, embedded public key ID
- [x] `dist/` compiler producing the eight IDE-specific files:
  `CLAUDE.md`, `.cursorrules`, `copilot-instructions.md`, `AGENTS.md`,
  `.windsurfrules`, `devin.md`, `.clinerules`, `SECURITY-SKILLS.md`.
- [x] Token budget system: `minimal` / `compact` / `full` tiers with tiktoken-based
  counting and per-skill budget enforcement.
- [x] CI pipeline (`.github/workflows/validate.yml`) running on every PR.
- [x] Dictionaries: `security_terms.yaml`, `cwe_top25.yaml`, `owasp_top10_2025.yaml`, `attack_techniques.yaml`.
- [x] `README.md`, `PROPOSAL.md`, `ARCHITECTURE.md`, `PHASES.md`, `PROGRESS.md`.

### Out of scope for Phase 1

- Remote updates (Phase 2).
- Vulnerability database (Phase 2).
- Scheduled tasks (Phase 3).
- Detection rules / Sigma (Phase 4).
- MCP server (Phase 4).

---

## Phase 2: Vulnerability Database + Remote Updates

**Covers:** the supply-chain vulnerability database and the signed manifest system that
keeps it (and every other file in the library) up to date.

### Deliverables

- [x] Curated vulnerability data:
  - `vulnerabilities/supply-chain/malicious-packages/{npm,pypi,crates,go}.json`
  - `vulnerabilities/supply-chain/typosquat-db/known_typosquats.json`
  - `vulnerabilities/supply-chain/dependency-confusion/patterns.json`
  - `vulnerabilities/cve/code-relevant/cve_patterns.json`
- [x] Manifest system:
  - Root `manifest.json` listing every distributable file with SHA-256 checksum
  - Ed25519 signing of every release manifest, embedded public key in CLI
  - Per-file delta patches for large vulnerability databases
- [x] CLI update commands:
  - `skills-check update` — fetch latest manifest, verify signature, download deltas
  - `skills-check update --check-only` — show available updates without applying
  - `skills-check update --rollback` — revert to previous version on the local disk
  - `skills-check update --source <url|path|tarball>` — swap update source
- [x] GitHub Actions release workflow:
  - Compile `manifest.json` on tag push
  - Sign manifest with maintainer's offline signing key (out-of-band; see [SIGNING.md](./SIGNING.md))
  - Publish manifest + delta patches as release assets
- [x] CI validation: every PR must update `last_updated` timestamps and regenerate
  checksums for any modified file.

### Update protocol guarantees

- Atomic writes (temp file + `rename`) so a crash cannot leave the library in a
  half-updated state.
- Signature verification *before* any rule file is written; bad signatures abort.
- Per-file SHA-256 verification after download.
- Both online (GitHub Releases / CDN) and offline (manual tarball) update paths walk
  the same code path; the only difference is the transport layer.

This phase reuses the **same `manifest.json` + checksums + delta updates** pattern as
[kennguy3n/secure-edge](https://github.com/kennguy3n/secure-edge) Phase 3, with Ed25519
signing added.

---

## Phase 3: Scheduled Updates + Cross-Platform Installers

**Covers:** background update mechanisms and platform-native installers so non-technical
team leads can roll out Skills Library to their entire team without manual `go install`
steps.

### Deliverables

- [x] Scheduled update mechanism:
  - macOS: LaunchAgent (`~/Library/LaunchAgents/com.skills-library.update.plist`)
  - Linux: systemd user timer (`~/.config/systemd/user/skills-check-update.timer`)
  - Windows: Task Scheduler task (`SkillsLibraryUpdate`)
- [x] Platform installers (modeled directly on the secure-edge Phase 3 installer
  matrix):
  - macOS: `.pkg` via `pkgbuild` + `productbuild` — `packaging/macos/`
  - Windows: MSI via WiX Toolset — `packaging/windows/`
  - Linux: `.deb` + `.rpm` via `nfpm` — `packaging/linux/`
- [x] Package managers:
  - `brew install kennguy3n/tap/skills-check` — `packaging/homebrew/skills-check.rb`
  - `winget install kennguy3n.skills-check` — `packaging/winget/kennguy3n.skills-check.yaml`
  - `scoop install skills-check` — `packaging/scoop/skills-check.json`
  - `apt`/`yum` via release repo — `packaging/apt-yum/`
- [x] Post-install hooks that offer to set up the scheduled update on first run
  (`skills-check init` interactive prompt; `--no-prompt` skips for CI).
- [x] Code signing CI scaffolds in `.github/workflows/release.yml`
  (no-op when secrets not configured; see `packaging/codesign/README.md`):
  - macOS: Developer ID signing + notarization (`secrets.APPLE_DEVELOPER_ID`)
  - Windows: Authenticode signing (`secrets.WINDOWS_CERT_PFX`)
- [x] Auto-update of the CLI binary itself (separate from skills updates), with
  SHA-256 verification against published `checksums-<goos>-<goarch>.txt`
  (`skills-check self-update`).
- [x] Documentation — see `docs/`:
  - `install-macos.md`, `install-linux.md`, `install-windows.md`
  - `admin-team-rollout.md`
  - `air-gapped-install.md`

### Privacy of scheduled updates

The scheduled task issues `GET` requests for public release artifacts and writes them
to disk. It does not send any device identifier, hostname, IP, or user information to
the update server. The update server has no way of distinguishing a fresh install from
its hundredth recurring check. This is the same zero-telemetry posture as secure-edge.

---

## Phase 4: Detection Rules + MCP Server

**Covers:** real-time integration with AI tools via Model Context Protocol, and the
detection rule corpus extracted from production ShieldNet detection rules.

### Deliverables

- [x] Sigma rule extraction & adaptation (initial corpus from public sources —
  SigmaHQ, MITRE ATT&CK, AWS/GCP/Azure/M365 docs):
  - [ ] Audit existing rules in
    [uneycom/shieldnet-security-detection-rules](https://github.com/uneycom/shieldnet-security-detection-rules)
    and [kennguy3n/sn360-security-platform](https://github.com/kennguy3n/sn360-security-platform)
  - Rules live in `rules/cloud/`, `rules/endpoint/`, `rules/container/`, `rules/saas/`
  - Coverage: AWS, GCP, Azure, Linux, macOS, Windows, K8s, O365
- [x] MCP server (`cmd/skills-mcp/`):
  - JSON-RPC 2.0 over stdio (`initialize`, `tools/list`, `tools/call`)
  - Tool: `lookup_vulnerability(package, ecosystem, version)`
  - Tool: `check_secret_pattern(text)`
  - Tool: `get_skill(skill_id, budget)`
  - Tool: `search_skills(query)`
- [ ] Additional skills toward the target of 20+ total:
  - `iac-security` (Terraform, CloudFormation, Pulumi)
  - `container-security` (Dockerfile, K8s manifests)
  - `frontend-security` (XSS, CSP, CORS)
  - `database-security` (SQL injection, ORM patterns)
  - `crypto-misuse` (weak ciphers, bad RNG)
  - `auth-security` (JWT, OAuth, session management)
  - `serverless-security` (Lambda IAM, function permissions)
  - `mobile-security` (Android, iOS specific)
  - `ml-security` (prompt injection, model poisoning)
  - `protocol-security` (TLS, mTLS, gRPC)
  - `error-handling-security` (information disclosure)
  - `logging-security` (sensitive data in logs)
  - `cors-security`

### MCP integration model

Phase 4 inverts the delivery model. Instead of injecting a `compact` blob of all
skills at session start, an MCP-enabled AI tool calls `get_skill` or
`lookup_vulnerability` on demand. This is dramatically more token-efficient and
enables real-time vulnerability lookups against the database without pre-loading it
into context.

---

## Phase 5: Enterprise Features + Community Growth

**Covers:** features that turn Skills Library into a sustainable platform with enterprise
governance and community contribution at scale.

### Deliverables

- [ ] Custom skill authoring tooling:
  - `skills-check new <skill-id>` scaffolds a new skill
  - `skills-check test <skill-id>` runs the test corpus
  - Skill template repo (`kennguy3n/skill-template`)
- [ ] Enterprise profiles:
  - `--profile financial-services` — adds PCI-DSS, SOC 2 controls
  - `--profile healthcare` — adds HIPAA controls
  - `--profile government` — adds FedRAMP, FISMA controls
- [ ] Compliance evidence generation:
  - `skills-check evidence --framework SOC2` emits an audit-ready report
    documenting which skills were active when
- [ ] Private repository support:
  - `skills-check configure --source https://internal.corp/skills`
  - Org-specific skill bundles with their own signing keys
- [ ] Language SDKs:
  - Go (already required for CLI)
  - Python (for security teams' tooling)
  - TypeScript (for browser-extension and VS Code integrations)
- [ ] Localized content (Phase 5b):
  - Spanish, French, German, Japanese, Mandarin
  - Translation review workflow with native security professionals
- [ ] SBOM generation for Skills Library itself (eat our own dog food)
- [ ] Third-party security audit of:
  - The CLI binary's signature verification path
  - The update protocol against MITM and replay attacks
  - The dependency tree of every shipped binary
- [ ] Community growth:
  - Slack / Discord for skill authors
  - Monthly office hours
  - Quarterly community calls
  - Sponsorship program for security researchers contributing rules

---

## Difficulty Assessment

| Component | Difficulty | Notes |
|-----------|-----------|-------|
| `SKILL.md` schema + parser | Easy | YAML frontmatter + standard markdown |
| `dist/` compiler | Easy | String concatenation with per-tool formatters; ~400 lines |
| CLI command framework | Easy | Cobra is mature and well-documented |
| Manifest JSON format | Easy | Same pattern as secure-edge Phase 3 |
| Ed25519 signing | Easy | `crypto/ed25519` in stdlib; ~50 lines |
| Delta downloads | Easy-Medium | Patch format choice (bsdiff vs custom JSON diff); ~200 lines |
| CI pipeline | Easy | GitHub Actions with caching |
| Vulnerability data curation | Medium | Ongoing effort; quality matters more than quantity |
| Token counting | Easy | `tiktoken-go` library handles the heavy lifting |
| macOS LaunchAgent installer | Easy | Plist generation; ~100 lines |
| Linux systemd timer installer | Easy | Two ini files; ~80 lines |
| Windows Task Scheduler installer | Medium | COM integration via `x/sys/windows`; ~300 lines |
| Cross-platform installers (.pkg / MSI / .deb / .rpm) | Medium | Tooling exists (`pkgbuild`, WiX, `nfpm`); CI integration is the work |
| Code signing infrastructure | Medium-Hard | Certificate management, notarization workflow |
| MCP server implementation | Medium | Protocol is standardized but bindings are new |
| Sigma rule adaptation | Medium-Hard | Manual review of every imported rule for false-positive risk |
| Compliance evidence generation | Medium | Mapping skills to framework controls is mostly data entry |
| SDKs in multiple languages | Medium | Three small libraries with the same API surface |
| Third-party security audit | Hard | Long lead time, expensive, but essential |
| Localized content | Medium | Continuous translation workflow; native reviewers per language |
| Community growth | Hard | People work, not engineering work |

The hardest items are concentrated in Phase 5; Phases 1-3 are largely well-trodden ground
with a clear playbook adapted from the secure-edge project.
