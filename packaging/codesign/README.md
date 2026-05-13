# Code signing — macOS and Windows

The release workflow (`.github/workflows/release.yml`) has conditional steps
that sign the macOS and Windows artifacts. The steps are **no-ops unless the
corresponding secrets are configured** — the release still succeeds without
code signing, but the binaries are not notarized and Windows will show a
SmartScreen warning.

## macOS — Developer ID + notarization

The signing path uses Apple's `codesign` and `xcrun notarytool`. To enable
the step, set the following secrets on the GitHub repository:

| Secret | Description |
|--------|-------------|
| `APPLE_DEVELOPER_ID` | Identity string, e.g. `Developer ID Application: Skills Library (TEAMID)` |
| `APPLE_DEVELOPER_ID_CERT_P12_BASE64` | Base64-encoded `.p12` export of the Developer ID certificate |
| `APPLE_DEVELOPER_ID_CERT_PASSWORD` | Password for the `.p12` |
| `APPLE_ID` | Apple ID email used for notarytool authentication |
| `APPLE_TEAM_ID` | Apple Developer team ID |
| `APPLE_NOTARY_PASSWORD` | App-specific password for notarytool |

The signing step imports the certificate into a temporary keychain, signs the
binary with the hardened runtime, then submits the binary to the notary
service and waits for the response. A failed notarization fails the release.

## Windows — Authenticode

The signing path uses `signtool` (shipped with the Windows SDK on the
`windows-latest` runner). To enable, set:

| Secret | Description |
|--------|-------------|
| `WINDOWS_CERT_PFX` | Base64-encoded `.pfx` Authenticode code-signing certificate |
| `WINDOWS_CERT_PFX_PASSWORD` | Password for the `.pfx` |

Signing uses SHA-256 hashing and a DigiCert timestamp server so signatures
remain valid past the certificate expiry.

## Self-signed / development builds

For development releases you can skip signing entirely. The CLI still emits
correct SHA-256 checksums and the `manifest.json` signature continues to use
the project's Ed25519 release key (see [`SIGNING.md`](../../SIGNING.md)).
