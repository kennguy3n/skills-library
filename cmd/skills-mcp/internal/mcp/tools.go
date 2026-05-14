package mcp

// toolDefinitions returns the MCP tool descriptors served on tools/list.
// The schemas follow the MCP `tools/list` definition: name, description,
// and an inputSchema JSON-Schema-shaped object describing the arguments.
func toolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "lookup_vulnerability",
			"description": "Look up a package in the Skills Library supply-chain vulnerability database. Returns malicious package entries and known typosquats that match the package name.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name to look up."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "One of npm, pypi, crates, go, rubygems, maven, nuget, github-actions, docker. Optional — defaults to all ecosystems.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
					"version": map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "check_secret_pattern",
			"description": "Run the Skills Library secret-detection rules against the supplied text and return matches with severity, name, and whether the match is a known false positive.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"text": map[string]string{"type": "string", "description": "Text to scan for secrets."},
				},
				"required": []string{"text"},
			},
		},
		{
			"name":        "get_skill",
			"description": "Return the requested tier of a Skills Library skill (minimal, compact, or full).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]string{"type": "string", "description": "Skill ID, e.g. 'secret-detection'."},
					"budget":   map[string]string{"type": "string", "description": "One of minimal, compact, full. Default: compact."},
				},
				"required": []string{"skill_id"},
			},
		},
		{
			"name":        "search_skills",
			"description": "Search the Skills Library by substring match against title, description, ID, and category. Returns matching skill metadata.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]string{"type": "string", "description": "Substring query."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "scan_secrets",
			"description": "Scan text or a local file for secrets and DLP patterns using the Skills Library secret-detection rules. Pass `text` for inline content or `file_path` for an absolute path on the host running the MCP server. Returns structured matches with severity, location, and whether the match is a known false positive.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"text":      map[string]string{"type": "string", "description": "Inline text to scan. Mutually exclusive with file_path."},
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a local file to scan. Files larger than 10 MiB are rejected."},
				},
			},
		},
		{
			"name":        "check_dependency",
			"description": "Check a package name (and optional version) against the malicious-packages database for one ecosystem. Returns malicious matches, typosquat matches, and any CVE patterns that mention the package. Use this when an LLM is about to import or install a new dependency.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name."},
					"version": map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "Package ecosystem.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
				},
				"required": []string{"package", "ecosystem"},
			},
		},
		{
			"name":        "check_typosquat",
			"description": "Check a package name against the known typosquat database. Returns every typosquat entry where the supplied name appears as the target (legitimate package being squatted) or as a known typosquat. Useful for catching dependency-confusion attempts before the install lands.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name to check."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "Optional ecosystem filter.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "map_compliance_control",
			"description": "Map a Skills Library skill ID, category, or free-text term to the controls in SOC 2 / HIPAA / PCI DSS that cover it. Returns the matching controls grouped by framework so an LLM can cite the right control alongside a fix.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]string{"type": "string", "description": "A Skills Library skill ID (e.g. 'secret-detection'). Either skill_id or query is required."},
					"query":    map[string]string{"type": "string", "description": "Free-text query matched case-insensitively against control title and description."},
					"framework": map[string]interface{}{
						"type":        "string",
						"description": "Optional framework filter.",
						"enum":        []string{"soc2", "hipaa", "pci-dss"},
					},
				},
			},
		},
		{
			"name":        "get_sigma_rule",
			"description": "Return one or more Sigma-format detection rules from the rules/ directory. Either pass `rule_id` for an exact match or `query` for a substring search against title / id / tags. Optionally filter by `category` (cloud, container, endpoint, saas).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"rule_id": map[string]string{"type": "string", "description": "Exact Sigma rule UUID."},
					"query":   map[string]string{"type": "string", "description": "Substring search against title, id, and tags."},
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Optional category filter (top-level rules/ subdir).",
						"enum":        []string{"cloud", "container", "endpoint", "saas"},
					},
				},
			},
		},
		{
			"name":        "version_status",
			"description": "Return the Skills Library data version, release timestamp, signature status, and a summary of how many files are tracked in the root manifest. Use this before relying on results from the other tools so the LLM can disclose data freshness and trust state.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}
