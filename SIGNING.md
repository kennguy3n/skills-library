# Manifest Signing Procedure

This document describes the out-of-band signing step required to authenticate
Skills Library releases. The Ed25519 private key **never** enters CI; signing
happens offline on a hardware-backed device.

## Rationale

A compromise of the CI environment should not be sufficient to ship a
malicious update. By signing the manifest offline, we guarantee that a
supply-chain attacker who gains write access to the repository or CI runner
must *also* possess the physical signing device.

## Prerequisites

| Component | Notes |
|-----------|-------|
| **YubiKey 5** or similar hardware key | must hold an Ed25519 private key |
| `ykman` (YubiKey Manager CLI) | `brew install ykman` / `sudo apt install yubikey-manager` |
| `openssl` >= 3.0 | or Go's stdlib via a local helper script |
| Repository release tag | e.g. `v2026.05.12` |

## Workflow

1. **CI builds and publishes.** The `release.yml` workflow produces binaries,
   computes the manifest checksums, and uploads them as GitHub Release assets.
   The manifest is published **without** a signature at this stage; the
   `signature` field is set to `"TBD"`.

2. **Release manager downloads the unsigned manifest.**

   ```bash
   gh release download v2026.05.12 -p manifest.json -D /tmp/release-staging/
   ```

3. **Sign offline.**

   ```bash
   # Option A — Go helper in this repo (recommended)
   go run ./cmd/skills-check manifest sign \
     --path /tmp/release-staging \
     --key /dev/stdin <(ykman piv keys export 9c -)

   # Option B — raw ed25519 seed file from a secure vault
   go run ./cmd/skills-check manifest sign \
     --path /tmp/release-staging \
     --key /path/to/ed25519.seed
   ```

   The command reads the private key, computes the canonical JSON (stripping
   the `signature` field), signs it with Ed25519, and writes the result back
   to `manifest.json` as `"ed25519:<base64>"`.

4. **Upload the signed manifest.**

   ```bash
   gh release upload v2026.05.12 /tmp/release-staging/manifest.json --clobber
   ```

5. **Verify the upload.**

   ```bash
   go run ./cmd/skills-check manifest verify \
     --path /tmp/release-staging \
     --public-key keys/skills-library-release-2026.pub
   ```

## Key Rotation

1. Generate a new Ed25519 keypair:
   ```bash
   go run ./cmd/skills-check manifest keygen   # future — currently manual
   # or: openssl genpkey -algorithm Ed25519 -out new.pem
   ```

2. Embed the new public key in the CLI binary by updating the build-time
   `-ldflags`:
   ```
   -X github.com/.../manifest.EmbeddedPublicKey=$(base64 -w0 < new.pub)
   -X github.com/.../manifest.EmbeddedPublicKeyID=skills-library-release-YYYY
   ```

3. Tag a new release with the updated binary. Older CLI versions will reject
   manifests signed with the new key — this is by design so that operators
   upgrade before trusting the new chain.

4. Revoke the old key by removing its `.pub` from the `keys/` directory in a
   subsequent commit.

## Emergency Revocation

If the signing key is compromised:

1. Generate a new key immediately.
2. Publish a new release signed with the new key.
3. Announce the compromised key's fingerprint and the safe replacement via
   GitHub Security Advisory.
4. Operators must upgrade their `skills-check` binary to one that trusts the
   new key.

## Public Key Listing

| Key ID | Fingerprint (SHA-256) | Status |
|--------|-----------------------|--------|
| `skills-library-release-2026` | *(populated at release time)* | active |
