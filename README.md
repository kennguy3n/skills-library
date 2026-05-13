# Skills Library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Skills](https://img.shields.io/badge/skills-27-blue)](#skill-catalogue)
[![Platforms](https://img.shields.io/badge/platforms-win%20%7C%20mac%20%7C%20linux-green)](#platform-support)

**Open-source security skills, rules, and vulnerability intelligence for AI-assisted coding tools.**

Skills Library is a structured, machine-readable collection of security skills designed to be
embedded directly into AI coding assistants — Claude Code, Cursor, GitHub Copilot, Codex,
Windsurf, Cline/OpenCode, Antigravity, and Devin. It ships bundled rules offline and supports
incremental remote updates for new vulnerabilities, detection patterns, and best practices.

## Why This Exists

- AI coding tools ("vibe coding") have exploded in adoption, but security is an afterthought.
  Developers ship AI-generated code into production with little or no review of secrets,
  dependencies, or dangerous patterns.
- There is no standardized way to inject security knowledge into AI coding assistants. Every
  team rolls its own `CLAUDE.md`, `.cursorrules`, or `copilot-instructions.md` and most of them
  contain only style rules — not security rules.
- Supply chain attacks are increasing rapidly (malicious npm/PyPI packages, typosquatting,
  dependency confusion). AI tools happily import the typosquatted package because their
  training data is older than the attack.
- Tech leads and CTOs need a turnkey way to enforce security practices across their
  AI-assisted dev teams without writing the rules from scratch.
- Existing solutions are proprietary, expensive, or require complex server infrastructure.
  Skills Library is MIT-licensed, runs entirely offline, and ships as plain files in a Git
  repo plus a single static Go binary.

## What's Inside

| Area | Path | Description |
|------|------|-------------|
| **Skills** | `skills/` | Self-contained `SKILL.md` manifests with associated rules, patterns, and checklists. Each skill is a security capability an AI tool can learn. |
| **Vulnerability Database** | `vulnerabilities/` | 10-year (2015-2025) curated supply-chain vulnerability data covering 7 ecosystems (npm, PyPI, crates, Go, RubyGems, Maven, NuGet, GitHub Actions, Docker Hub), 70+ typosquats, ~60 CVE detection patterns, dependency-confusion rules, and CVE-to-package mappings. Incrementally updatable. |
| **Detection Rules** | `rules/` | Sigma-format detection rules for AWS, GCP, K8s, Linux, macOS, Windows, O365. Extracted and adapted from production ShieldNet detection rules (Phase 4). |
| **Compliance Maps** | `compliance/` | Framework-to-control mappings for OWASP Top 10, CWE, SANS Top 25, covering what AI-generated code should be checked against. |
| **Dictionaries** | `dictionaries/` | Security term definitions, CWE catalogue, MITRE ATT&CK technique references — context AI tools need to reason about security. |
| **Pre-compiled IDE files** | `dist/` | Ready-to-drop-in `CLAUDE.md`, `.cursorrules`, `copilot-instructions.md`, `AGENTS.md`, `.windsurfrules`, `devin.md`, `.clinerules`, and a universal `SECURITY-SKILLS.md`. |
| **CLI** | `cmd/skills-check/` | Single static Go binary for installing, updating, and validating skills across all supported IDEs. |

## Quick Start — Embedding in Your IDE

The fastest path is to copy the pre-compiled file for your tool from `dist/` into your project
root. Three patterns are available for every tool:

1. **Copy once** — fast, no live updates.
2. **Symlink** — auto-updates whenever you run `skills-check update` or `git pull` in the
   skills-library checkout.
3. **CLI-generated** — `skills-check init` writes a project-specific file with only the skills
   you care about, at the token budget you specify.

### Claude Code (`CLAUDE.md`)

```bash
# Option 1: Copy the universal skill loader
cp skills-library/dist/CLAUDE.md /your-project/CLAUDE.md

# Option 2: Symlink for auto-updates
ln -s /path/to/skills-library/dist/CLAUDE.md /your-project/CLAUDE.md

# Option 3: Use the CLI to generate a project-specific CLAUDE.md
skills-check init --tool claude --skills secret-detection,dependency-audit,secure-code-review
```

### Cursor (`.cursorrules`)

```bash
# Option 1: Copy the universal skill loader
cp skills-library/dist/.cursorrules /your-project/.cursorrules

# Option 2: Use the CLI
skills-check init --tool cursor --skills secret-detection,dependency-audit
```

### GitHub Copilot (`.github/copilot-instructions.md`)

```bash
cp skills-library/dist/copilot-instructions.md /your-project/.github/copilot-instructions.md
```

### Codex (`codex.md` or `AGENTS.md`)

```bash
cp skills-library/dist/AGENTS.md /your-project/AGENTS.md
```

### Windsurf (`.windsurfrules`)

```bash
cp skills-library/dist/.windsurfrules /your-project/.windsurfrules
```

### Devin (`devin.md`)

```bash
cp skills-library/dist/devin.md /your-project/devin.md
```

### Cline / OpenCode (`.clinerules` or `.opencode/rules.md`)

```bash
cp skills-library/dist/.clinerules /your-project/.clinerules
```

### Universal (any tool that reads project-root markdown)

```bash
cp skills-library/dist/SECURITY-SKILLS.md /your-project/SECURITY-SKILLS.md
```

## Routine Updates (Pulling Latest Rules)

The point of Skills Library is that vulnerability data and detection patterns change every
week. The CLI keeps your local copy current with incremental, signed updates.

### Using the CLI (all platforms)

```bash
# Install (requires Go 1.22+)
go install github.com/kennguy3n/skills-library/cmd/skills-check@latest

# Pull latest rules, vulnerabilities, skills
skills-check update

# Pull and regenerate IDE files in one step
skills-check update --regenerate

# Check for updates without applying
skills-check update --check-only

# Revert to the previous version
skills-check update --rollback

# Use a custom source (HTTP URL, local directory, or tarball)
skills-check update --source https://cdn.example.com/skills-library/
skills-check update --source /mnt/airgap/skills-library-v2.tar.gz
```

### Scheduled Updates

#### macOS (`launchd`)

```bash
skills-check scheduler install --interval 6h
# creates ~/Library/LaunchAgents/com.skills-library.update.plist
```

#### Linux (`systemd` timer)

```bash
skills-check scheduler install --interval 6h
# creates ~/.config/systemd/user/skills-check-update.timer
```

#### Windows (`Task Scheduler`)

```powershell
skills-check scheduler install --interval 6h
# creates a scheduled task named "SkillsLibraryUpdate"
```

### Manual / Git-based

```bash
cd /path/to/skills-library
git pull origin main
skills-check regenerate    # rebuild dist/ files from latest skills
```

## Token Efficiency

AI coding tools have finite context windows, and every byte of instructions you inject costs
either tokens (for API tools) or working memory (for IDE tools). Skills Library is designed
around three principles:

- **Skills are loaded on demand, not all at once.** The CLI lets you pick exactly which
  skills your project needs.
- **Every `SKILL.md` declares a `token_budget` block** with three pre-counted variants:
  `minimal`, `compact`, and `full`.
- **The `dist/` files are pre-compiled to a budget tier.** Generated output is checked at
  build time and the build fails if a variant exceeds its budget.

| Tier | Approx. tokens | Contents | Recommended for |
|------|----------------|----------|-----------------|
| `minimal` | < 500 | ALWAYS / NEVER bullet rules only | Expensive API-based tools, very small context budgets |
| `compact` | < 2000 | Full rules + known false positives + references; no examples or rationale | Default for most IDE integrations |
| `full` | < 5000 | Rules + examples + rationale + related CWEs | Local models with large context, Devin-style agents |

Select your tier with `skills-check init --budget compact`. Compact is the default.

## Project Structure

```
skills-library/
├── README.md  PROPOSAL.md  ARCHITECTURE.md  PHASES.md  PROGRESS.md  LICENSE
├── skills/                              # Skill definitions (the core product)
│   ├── secret-detection/
│   │   ├── SKILL.md                     # Human + machine-readable manifest
│   │   ├── rules/
│   │   │   ├── dlp_patterns.json        # Aho-Corasick + regex patterns
│   │   │   └── dlp_exclusions.json      # False positive suppressions
│   │   └── tests/
│   │       └── corpus.json              # Test fixtures for validation
│   ├── dependency-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   │       └── known_malicious.json
│   ├── secure-code-review/
│   │   ├── SKILL.md
│   │   └── checklists/
│   │       ├── owasp_top10.yaml
│   │       └── injection_patterns.yaml
│   ├── supply-chain-security/
│   │   ├── SKILL.md
│   │   └── rules/
│   │       ├── typosquat_patterns.json
│   │       └── dependency_confusion.json
│   ├── infrastructure-security/
│   │   ├── SKILL.md
│   │   └── checklists/
│   │       ├── k8s_hardening.yaml
│   │       ├── docker_security.yaml
│   │       └── terraform_security.yaml
│   ├── api-security/
│   │   ├── SKILL.md
│   │   └── checklists/
│   │       ├── auth_patterns.yaml
│   │       └── input_validation.yaml
│   ├── compliance-awareness/
│   │   ├── SKILL.md
│   │   └── frameworks/
│   │       ├── owasp_mapping.yaml
│   │       └── cwe_mapping.yaml
│   ├── iac-security/                    # Terraform / CloudFormation / Pulumi
│   ├── container-security/              # Dockerfile / K8s / Helm
│   ├── frontend-security/               # XSS, CSP, CORS, SRI, trusted types
│   ├── database-security/               # SQL injection, ORM safety, RLS
│   ├── crypto-misuse/                   # weak ciphers, bad RNG, KDF
│   ├── auth-security/                   # JWT, OAuth, sessions, MFA
│   ├── serverless-security/             # Lambda / Cloud Functions IAM
│   ├── mobile-security/                 # Android exported components, iOS ATS
│   ├── ml-security/                     # prompt injection, model poisoning
│   ├── protocol-security/               # TLS 1.2+, mTLS, HSTS, gRPC
│   ├── error-handling-security/         # information disclosure
│   ├── logging-security/                # secrets/PII in logs, log injection
│   └── cors-security/                   # origin allowlists, preflight
├── vulnerabilities/                     # Supply chain vulnerability database
│   ├── manifest.json                    # Versioned, checksummed, delta-updatable
│   ├── supply-chain/
│   │   ├── malicious-packages/
│   │   │   ├── npm.json
│   │   │   ├── pypi.json
│   │   │   ├── crates.json
│   │   │   └── go.json
│   │   ├── typosquat-db/
│   │   │   └── known_typosquats.json
│   │   └── dependency-confusion/
│   │       └── patterns.json
│   └── cve/
│       └── code-relevant/               # CVEs that affect code patterns, not just versions
│           └── cve_patterns.json
├── rules/                               # Detection rules (Sigma format)
│   ├── cloud/
│   │   ├── aws/                          # CloudTrail / IAM / S3
│   │   ├── gcp/                          # Cloud Audit Logs / IAM / VPC
│   │   └── azure/                        # Activity Log / Azure AD / NSG
│   ├── endpoint/
│   │   ├── linux/                        # auditd / reverse shell, cron persistence
│   │   ├── macos/                        # UnifiedLog / LaunchAgent persistence
│   │   └── windows/                      # Sysmon / Mimikatz / encoded PowerShell
│   ├── container/
│   │   └── k8s/                          # API audit / privileged pod / exec
│   └── saas/
│       └── o365/                         # Mailbox forwarding / admin roles
├── dictionaries/                        # Reference data for AI context
│   ├── security_terms.yaml
│   ├── cwe_top25.yaml
│   ├── owasp_top10_2025.yaml
│   └── attack_techniques.yaml           # MITRE ATT&CK subset
├── dist/                                # Pre-compiled IDE-specific files
│   ├── CLAUDE.md
│   ├── .cursorrules
│   ├── copilot-instructions.md
│   ├── AGENTS.md
│   ├── .windsurfrules
│   ├── devin.md
│   ├── .clinerules
│   └── SECURITY-SKILLS.md               # Universal format
├── cmd/
│   ├── skills-check/                    # CLI tool (Go, single binary)
│   │   └── main.go
│   └── skills-mcp/                      # MCP server over JSON-RPC stdio
│       └── main.go
├── packaging/                            # OS installers / package manager manifests
│   ├── macos/                            # pkgbuild + productbuild
│   ├── windows/                          # WiX MSI
│   ├── linux/                            # nfpm .deb + .rpm
│   ├── homebrew/                         # Homebrew tap formula
│   ├── winget/                           # Winget manifest
│   ├── scoop/                            # Scoop bucket manifest
│   ├── apt-yum/                          # GitHub Pages-hosted APT / YUM repos
│   └── codesign/                         # macOS notarization + Windows Authenticode docs
├── docs/                                 # Install + admin docs
│   ├── install-macos.md
│   ├── install-linux.md
│   ├── install-windows.md
│   ├── admin-team-rollout.md
│   └── air-gapped-install.md
├── profiles/                            # Enterprise --profile mappings
│   ├── financial-services.yaml
│   ├── healthcare.yaml
│   └── government.yaml
├── compliance/                          # Framework control mappings
│   ├── soc2_mapping.yaml
│   ├── hipaa_mapping.yaml
│   └── pci_dss_mapping.yaml
├── sdk/                                 # Programmatic access
│   ├── go/                              # Re-exports of internal/skill
│   ├── python/                          # skillslib Python package
│   └── typescript/                      # @skills-library/skillslib npm pkg
├── locales/                             # Translated SKILL.md (informational)
│   ├── es/
│   ├── fr/
│   └── de/
├── manifest.json                        # Root manifest for remote updates
└── .github/
    └── workflows/
        ├── validate.yml                 # CI: validate all skills, rules, manifests
        └── release.yml                  # CI: build CLI, tag release, publish manifests
```

## Documentation

- [PROPOSAL.md](./PROPOSAL.md) — Problem statement, design principles, target audience,
  scope boundaries, and the canonical `SKILL.md` format specification.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — System diagrams, compiler architecture, update
  protocol, CLI layout, scheduler implementation, and signing model.
- [PHASES.md](./PHASES.md) — Phased delivery plan with deliverable checklists and a
  difficulty assessment per component.
- [PROGRESS.md](./PROGRESS.md) — Live progress tracker mirroring the deliverables in
  PHASES.md.
- [docs/](./docs/) — Install guides (macOS / Linux / Windows / air-gapped) and the
  team rollout admin guide.
- [packaging/codesign/README.md](./packaging/codesign/README.md) — macOS notarization and
  Windows Authenticode signing in the release workflow.

## CLI Package Layout

```
cmd/skills-check/
├── main.go                    # Cobra root command
├── cmd/                       # init / update / validate / list / regenerate / version / manifest / scheduler / self-update
└── internal/
    ├── token/                 # tiktoken-go counter + 1.3x Claude multiplier
    ├── compiler/              # 8 IDE-specific formatters + core compile loop
    ├── manifest/              # manifest.json: load, checksum, Ed25519 sign/verify, delta, atomic write
    ├── updater/               # Remote update: HTTP / dir / tarball sources, verify-before-replace, rollback
    └── scheduler/             # Cross-platform scheduled updates (launchd / systemd / Task Scheduler)

cmd/skills-mcp/                # Model Context Protocol server (JSON-RPC 2.0 over stdio)
├── main.go
└── internal/
    ├── mcp/                   # JSON-RPC dispatch + tool definitions
    └── tools/                 # lookup_vulnerability, check_secret_pattern, get_skill, search_skills

internal/skill/                # SKILL.md parser (shared between skills-check and skills-mcp)
```

## MCP Server

`skills-mcp` exposes the Skills Library to AI tools that speak the
Model Context Protocol. It runs as a short-lived child process spoken to
over stdio:

```bash
go build -o skills-mcp ./cmd/skills-mcp
skills-mcp --path /path/to/skills-library
```

The server registers 4 tools on `tools/list`:

- `lookup_vulnerability(package, ecosystem?, version?)` — search the
  supply-chain malicious-packages database and the typosquat DB.
- `check_secret_pattern(text)` — run the secret-detection regex rules
  against `text`, returning matches with severity and whether they are
  known false positives.
- `get_skill(skill_id, budget?)` — return the requested skill at the
  requested tier (`minimal` / `compact` / `full`).
- `search_skills(query)` — substring match across skill metadata.

The library root is resolved from `--path`, then `$SKILLS_LIBRARY_PATH`,
then the directory containing the binary.

## Building and Running Tests

```bash
go build -trimpath -ldflags "-s -w" -o skills-check ./cmd/skills-check
go build -trimpath -ldflags "-s -w" -o skills-mcp   ./cmd/skills-mcp
go test ./...                                       # covers CLI + MCP server
./skills-check validate
./skills-check list
./skills-check regenerate
./skills-check manifest compute --path . --write   # recompute SHA-256 checksums
./skills-check manifest verify  --path .            # verify committed checksums
```

The same commands run in CI on every PR. `skills-check validate` enforces the per-skill
token budgets declared in each `SKILL.md` frontmatter; `skills-check regenerate` rebuilds
every file in `dist/` and CI fails if the committed copy differs from the regenerated
output.

## Signing Model

Release manifests are signed with Ed25519. The public key is embedded in the CLI binary at
build time via `-ldflags -X`. See [SIGNING.md](./SIGNING.md) for the out-of-band YubiKey-backed
signing procedure and key management policy.

## Platform Support

| OS | Architectures | CLI install method | Scheduled updates |
|----|---------------|--------------------|-------------------|
| macOS | `amd64`, `arm64` | `brew install skills-check`, `go install` | `launchd` |
| Linux | `amd64`, `arm64` | `.deb`, `.rpm`, `go install` | `systemd` timer |
| Windows | `amd64` | MSI, `winget`, `scoop`, `go install` | Task Scheduler |

## Skill Catalogue

| Skill | Category | Severity | Languages |
|-------|----------|----------|-----------|
| `secret-detection` | prevention | critical | * |
| `dependency-audit` | supply-chain | high | * |
| `secure-code-review` | prevention | high | * |
| `supply-chain-security` | supply-chain | critical | * |
| `infrastructure-security` | hardening | high | yaml, hcl, dockerfile |
| `api-security` | prevention | high | * |
| `compliance-awareness` | compliance | medium | * |
| `iac-security` | hardening | high | hcl, yaml, json |
| `container-security` | hardening | high | dockerfile, yaml |
| `frontend-security` | prevention | high | javascript, typescript, html |
| `database-security` | prevention | high | sql, javascript, typescript, python, java, go |
| `crypto-misuse` | prevention | high | * |
| `auth-security` | prevention | critical | * |
| `serverless-security` | hardening | high | python, javascript, typescript, java, yaml |
| `mobile-security` | hardening | high | java, kotlin, swift, objective-c |
| `ml-security` | prevention | high | python, jupyter |
| `protocol-security` | hardening | high | * |
| `error-handling-security` | prevention | medium | * |
| `logging-security` | prevention | high | * |
| `cors-security` | hardening | medium | javascript, typescript, python, go, java |
| `cicd-security` | prevention | critical | yaml, shell, * |
| `ssrf-prevention` | prevention | critical | * |
| `deserialization-security` | prevention | critical | java, python, csharp, php, ruby, javascript, typescript |
| `graphql-security` | prevention | high | javascript, typescript, python, go, java, kotlin, csharp, ruby |
| `file-upload-security` | prevention | high | * |
| `websocket-security` | prevention | high | javascript, typescript, python, go, java, csharp, ruby, elixir |

## Enterprise profiles

`skills-check init` and `skills-check regenerate` accept `--profile <name>`
to pick a curated, compliance-aligned subset of skills:

| Profile | Frameworks | Use case |
|---|---|---|
| `financial-services` | PCI-DSS v4.0, SOC 2 | Banks, fintech, payment processors |
| `healthcare` | HIPAA Security Rule | Hospitals, telehealth, claims processing |
| `government` | FedRAMP, NIST SP 800-53 Rev. 5 | Public-sector workloads |

Profile definitions live under [`profiles/`](./profiles).

## Compliance evidence

```bash
skills-check evidence --framework SOC2 --format markdown --out evidence.md
skills-check evidence --framework HIPAA --format json
skills-check evidence --framework PCI-DSS --format markdown
```

The command maps controls to installed skills using YAML files in
[`compliance/`](./compliance) and emits a timestamped audit report suitable
for handing to auditors.

## Private repositories

For air-gapped or internal deployments, point the CLI at your own signed
bundle:

```bash
skills-check configure \
  --source https://skills.internal.example.com \
  --bearer-token-env SKILLS_TOKEN \
  --trusted-key /etc/skills/orgkey.pem \
  --profile financial-services
```

This writes `.skills-check.yaml` next to the repo. The updater accepts
multiple trusted Ed25519 keys (`VerifyAny`) and authenticated HTTPS pulls.

## SDKs

Minimal Go, Python, and TypeScript SDKs live under [`sdk/`](./sdk).

```go
import skillslib "github.com/kennguy3n/skills-library/sdk/go"

s, _ := skillslib.LoadSkill("skills/secret-detection/SKILL.md")
fmt.Println(skillslib.Extract(s, skillslib.TierCompact))
```

```python
import skillslib
s = skillslib.load_skill("skills/secret-detection/SKILL.md")
print(skillslib.extract(s, "compact"))
```

```ts
import { loadSkill, extract } from "@skills-library/skillslib";
const s = loadSkill("skills/secret-detection/SKILL.md");
console.log(extract(s, "compact"));
```

## Localization

Translated copies of the top 3 skills (Spanish, French, German) live under
[`locales/`](./locales). Translations are informational — the canonical
English file under `skills/<id>/SKILL.md` remains the source of truth for
the validator and IDE config generators.

## Contributing

- **Skill contributions** — add a new directory under `skills/` with a `SKILL.md` and
  associated rules. Use `skills/secret-detection/` as the reference implementation.
- **Vulnerability data** — add entries to `vulnerabilities/supply-chain/` JSON files via PR.
  Every entry must include at least one external reference (CVE ID, advisory URL, or
  reputable blog post).
- **Detection rules** — add Sigma YAML files to `rules/`. Follow the existing taxonomy
  (`cloud/`, `endpoint/`, `container/`).
- **False positive fixes** — update the relevant `dlp_exclusions.json` (or skill-specific
  exclusion file). False positive PRs are merged fast.
- **IDE integration** — improve the templates in the `dist/` compiler for specific tools.
- Run `skills-check validate` before submitting any PR. CI runs the same validator and
  rejects PRs that fail.

## License

[MIT](./LICENSE)
