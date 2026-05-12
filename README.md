# Skills Library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Skills](https://img.shields.io/badge/skills-7-blue)](#skill-catalogue)
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
| **Vulnerability Database** | `vulnerabilities/` | Curated supply-chain vulnerability data: malicious packages, typosquat patterns, dependency confusion rules, CVE-to-package mappings. Incrementally updatable. |
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
│   └── compliance-awareness/
│       ├── SKILL.md
│       └── frameworks/
│           ├── owasp_mapping.yaml
│           └── cwe_mapping.yaml
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
├── rules/                               # Detection rules (Sigma format, Phase 4)
│   ├── cloud/
│   │   ├── aws/
│   │   └── gcp/
│   ├── endpoint/
│   │   ├── linux/
│   │   ├── macos/
│   │   └── windows/
│   └── container/
│       └── k8s/
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
│   └── skills-check/                    # CLI tool (Go, single binary)
│       └── main.go
├── sdk/                                 # Programmatic access
│   ├── go/
│   ├── python/
│   └── typescript/
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

## Project Structure (Phase 1)

```
skills-library/
├── cmd/skills-check/
│   ├── main.go                    # Cobra root command
│   ├── cmd/                       # init / update / validate / list / regenerate / version
│   └── internal/
│       ├── skill/                 # SKILL.md parser (frontmatter + body + tier extraction)
│       ├── token/                 # tiktoken-go counter + 1.3x Claude multiplier
│       ├── compiler/              # 8 IDE-specific formatters + core compile loop
│       └── manifest/              # manifest.json reader (Phase 2 will use signing)
├── skills/                        # 7 SKILL.md manifests + their rule files
├── dictionaries/                  # security_terms / cwe_top25 / owasp_top10_2025 / attack_techniques
├── vulnerabilities/               # Supply-chain vulnerability data + root manifest.json
├── dist/                          # Generated IDE configs (regenerate via skills-check)
├── .github/workflows/validate.yml # CI: JSON/YAML, frontmatter, rule schema, go build/test, token budgets, dist drift
├── go.mod / go.sum
└── README.md / PROPOSAL.md / ARCHITECTURE.md / PHASES.md / PROGRESS.md
```

## Building and Running Tests

```bash
go build -trimpath -ldflags "-s -w" -o skills-check ./cmd/skills-check
go test ./...
./skills-check validate
./skills-check list
./skills-check regenerate
```

The same commands run in CI on every PR. `skills-check validate` enforces the per-skill
token budgets declared in each `SKILL.md` frontmatter; `skills-check regenerate` rebuilds
every file in `dist/` and CI fails if the committed copy differs from the regenerated
output.

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

Additional skills land in Phase 4. See [PHASES.md](./PHASES.md#phase-4-detection-rules--mcp-server) for the full Phase 4 list.

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
