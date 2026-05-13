package updater

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/manifest"
)

// BackupDirName is where the last applied update stashes the files it
// replaced so --rollback can restore them.
const BackupDirName = ".skills-check-previous"

// Options control how Apply behaves. All fields are optional.
type Options struct {
	// PublicKey, when set, is used to verify the remote manifest's
	// signature. If nil, the embedded key in the manifest package is used.
	PublicKey ed25519.PublicKey
	// SkipSignature disables signature verification entirely. Intended for
	// tests and the rare bootstrap case where no key exists yet. The user
	// must opt in explicitly.
	SkipSignature bool
}

// Change describes one file the updater will modify when Apply is called.
type Change struct {
	Path   string
	Action string // "added", "updated", "removed"
	From   string
	To     string
	Size   int64
}

// CheckResult is what CheckOnly returns: the new manifest fetched from the
// source plus the list of changes that would be applied.
type CheckResult struct {
	Source         Source
	RemoteManifest *manifest.Manifest
	Changes        []Change
}

// CheckOnly fetches the remote manifest, verifies its signature, and returns
// the diff against the local manifest. No filesystem changes are made.
func CheckOnly(localRoot string, src Source, opts Options) (*CheckResult, error) {
	local, err := loadLocalManifest(localRoot)
	if err != nil {
		return nil, err
	}
	remote, err := src.Manifest()
	if err != nil {
		return nil, fmt.Errorf("fetch remote manifest: %w", err)
	}
	if err := verifyRemoteSignature(remote, opts); err != nil {
		return nil, err
	}
	return &CheckResult{
		Source:         src,
		RemoteManifest: remote,
		Changes:        diffManifests(local, remote),
	}, nil
}

// Apply downloads every changed file, verifies its SHA-256, and atomically
// renames it into place. The previous on-disk content is moved into
// BackupDirName so a later --rollback can restore it.
func Apply(localRoot string, src Source, opts Options) (*CheckResult, error) {
	res, err := CheckOnly(localRoot, src, opts)
	if err != nil {
		return nil, err
	}
	backupRoot := filepath.Join(localRoot, BackupDirName)
	// Clean a stale backup so the rollback set is always exactly the
	// previous applied update.
	if err := os.RemoveAll(backupRoot); err != nil && !os.IsNotExist(err) {
		return res, fmt.Errorf("reset backup dir: %w", err)
	}

	for _, change := range res.Changes {
		switch change.Action {
		case "added", "updated":
			if err := applyOne(localRoot, backupRoot, src, change, res.RemoteManifest); err != nil {
				return res, fmt.Errorf("apply %s: %w", change.Path, err)
			}
		case "removed":
			if err := backupExisting(localRoot, backupRoot, change.Path); err != nil {
				return res, fmt.Errorf("backup remove %s: %w", change.Path, err)
			}
			abs := filepath.Join(localRoot, filepath.FromSlash(change.Path))
			if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
				return res, fmt.Errorf("remove %s: %w", change.Path, err)
			}
		}
	}

	// Swap manifest into place atomically, but only after every file has
	// been written successfully — see "verify-before-replace" in
	// ARCHITECTURE.md.
	mfPath := filepath.Join(localRoot, "manifest.json")
	// Backup old manifest too.
	if err := backupExisting(localRoot, backupRoot, "manifest.json"); err != nil {
		return res, fmt.Errorf("backup manifest: %w", err)
	}
	if err := res.RemoteManifest.Save(mfPath); err != nil {
		return res, fmt.Errorf("write manifest: %w", err)
	}
	return res, nil
}

// Rollback restores files from BackupDirName, undoing the most recent Apply.
func Rollback(localRoot string) error {
	backupRoot := filepath.Join(localRoot, BackupDirName)
	st, err := os.Stat(backupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("no previous update to roll back from")
		}
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", backupRoot)
	}
	err = filepath.Walk(backupRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(backupRoot, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(localRoot, rel)
		return manifest.CopyFileAtomic(p, dst, info.Mode())
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(backupRoot)
}

// FormatChanges renders the change list as a small human-readable summary.
func FormatChanges(changes []Change) string {
	if len(changes) == 0 {
		return "already up to date\n"
	}
	var added, updated, removed int
	for _, c := range changes {
		switch c.Action {
		case "added":
			added++
		case "updated":
			updated++
		case "removed":
			removed++
		}
	}
	out := fmt.Sprintf("%d added, %d updated, %d removed\n", added, updated, removed)
	sorted := append([]Change(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Action != sorted[j].Action {
			return sorted[i].Action < sorted[j].Action
		}
		return sorted[i].Path < sorted[j].Path
	})
	for _, c := range sorted {
		out += fmt.Sprintf("  [%s] %s\n", c.Action, c.Path)
	}
	return out
}

func loadLocalManifest(root string) (*manifest.Manifest, error) {
	path := filepath.Join(root, "manifest.json")
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &manifest.Manifest{Files: nil}, nil
		}
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	return manifest.Load(path)
}

func verifyRemoteSignature(m *manifest.Manifest, opts Options) error {
	if opts.SkipSignature {
		return nil
	}
	switch {
	case opts.PublicKey != nil:
		return m.VerifyWith(opts.PublicKey)
	case manifest.HasEmbeddedKey():
		return m.VerifyManifest()
	}
	// No key available at all. Refuse silently to walk a signed manifest;
	// however an unsigned manifest is permitted as long as the caller is
	// aware (and CheckOnly will report it).
	if m.Signature != "" && m.Signature != manifest.PlaceholderSignature {
		return errors.New("remote manifest is signed but no public key is available; use --skip-signature to override")
	}
	return nil
}

func diffManifests(local, remote *manifest.Manifest) []Change {
	localIdx := make(map[string]manifest.File, len(local.Files))
	for _, f := range local.Files {
		localIdx[f.Path] = f
	}
	remoteIdx := make(map[string]manifest.File, len(remote.Files))
	for _, f := range remote.Files {
		remoteIdx[f.Path] = f
	}

	var out []Change
	for _, f := range remote.Files {
		prev, ok := localIdx[f.Path]
		switch {
		case !ok:
			out = append(out, Change{Path: f.Path, Action: "added", To: f.SHA256, Size: f.Size})
		case prev.SHA256 != f.SHA256:
			out = append(out, Change{
				Path: f.Path, Action: "updated", From: prev.SHA256, To: f.SHA256, Size: f.Size,
			})
		}
	}
	for _, f := range local.Files {
		if _, ok := remoteIdx[f.Path]; !ok {
			out = append(out, Change{Path: f.Path, Action: "removed", From: f.SHA256})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func applyOne(localRoot, backupRoot string, src Source, change Change, remote *manifest.Manifest) error {
	entry := remote.FileByPath(change.Path)
	if entry == nil {
		return fmt.Errorf("manifest is missing file entry for %s", change.Path)
	}
	body, err := src.File(change.Path)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	got := manifest.HashBytes(data)
	if got != entry.SHA256 {
		return fmt.Errorf("sha256 mismatch (want %s, got %s)", entry.SHA256, got)
	}
	if err := backupExisting(localRoot, backupRoot, change.Path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	dst := filepath.Join(localRoot, filepath.FromSlash(change.Path))
	return manifest.WriteFileAtomic(dst, data, 0o644)
}

func backupExisting(localRoot, backupRoot, relPath string) error {
	src := filepath.Join(localRoot, filepath.FromSlash(relPath))
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dst := filepath.Join(backupRoot, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return manifest.CopyFileAtomic(src, dst, 0o644)
}
