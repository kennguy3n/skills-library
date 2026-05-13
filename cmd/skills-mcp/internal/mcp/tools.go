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
					"package":   map[string]string{"type": "string", "description": "Package name to look up."},
					"ecosystem": map[string]string{"type": "string", "description": "One of npm, pypi, crates, go. Optional — defaults to all ecosystems."},
					"version":   map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
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
	}
}
