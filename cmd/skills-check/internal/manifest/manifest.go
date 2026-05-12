// Package manifest reads the root manifest.json. Phase 1 only needs version
// reporting; signing and delta application are Phase 2.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
)

// File is a single file entry in the manifest.
type File struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Action    string `json:"action,omitempty"`
	DeltaFrom string `json:"delta_from,omitempty"`
}

// Manifest is the typed root manifest.json structure.
type Manifest struct {
	SchemaVersion   string `json:"schema_version"`
	Version         string `json:"version"`
	PreviousVersion any    `json:"previous_version,omitempty"`
	ReleasedAt      string `json:"released_at"`
	Signature       string `json:"signature,omitempty"`
	PublicKeyID     string `json:"public_key_id,omitempty"`
	Description     string `json:"description,omitempty"`
	Files           []File `json:"files,omitempty"`
}

// Load reads and decodes the manifest file at path.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", path, err)
	}
	return &m, nil
}
