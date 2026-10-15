# code-detector (Go)

Pre-packaging Veracode gate: does this repo/package hold scannable code or artifacts **before** you bundle and upload it?

- `true` = scannable module found → upload to SAST
- `false` = SBOM/manifest/docs only (or a language outside SAST) → **skip without error** instead of getting `No modules found`

Single Go binary (stdlib-only, zero dependencies), ideal for CI.

## Install (via Release)

Download the ready-made binary from the repository **Releases** page
(`code-detector_<version>_<OS>_<arch>.tar.gz` + `checksums.txt`):

```bash
# Example: Linux amd64, v1.0.0:
curl -sL -o code-detector.tar.gz \
  https://github.com/appsecomega/code-detector/releases/download/v1.0.0/code-detector_v1.0.0_Linux_x86_64.tar.gz
tar -xzf code-detector.tar.gz
./code-detector --version
```

Or build locally:

```bash
go build -o code-detector .
# or: make build
```

## Usage (pre-packaging check)

```bash
# 1) Check the source repo BEFORE zipping:
./code-detector ./my-repo -q --mode veracode
# true  -> safe to package + upload
# false -> skip SAST (SBOM/manifest only)

# 2) JSON for pipeline logs:
./code-detector ./my-repo --json

# 3) Pipeline with exit code (0=scan, 2=skip):
./code-detector ./my-repo --mode veracode --fail-on-no-code -q

# 4) Check the already-built package:
./code-detector app.zip --mode veracode
```

Shell example:

```bash
if [ "$(./code-detector ./src -q --mode veracode)" = "true" ]; then
  zip -r app.zip src/
  # veracode upload...
else
  echo "no scannable module — skipping SAST without failing the build."
fi
```

## Categories

| category | `veracode_scannable` | action |
|---|---|---|
| `code` | ✅ | `scan` |
| `artifact` (`.jar/.war/.ear/.dll/.exe/.apk/.aar`) | ✅ | `scan` |
| `sbom-only` | ❌ | `skip` |
| `manifest-only` | ❌ | `skip` |
| `code-unsupported-by-veracode` (e.g. only `.sh/.sql/.tf`) | ❌ | `skip` |
| `non-scannable-only` / `empty` | ❌ | `skip` |

## Development

```bash
go test ./...
go vet ./...
gofmt -l .
# or: make test
```

## Publishing a new version (automatic release)

The `.github/workflows/release.yml` workflow publishes the Release **on its own**
whenever a `v*.*.*` tag is pushed. Binaries
(linux/darwin/windows × amd64/arm64) + `checksums.txt` get attached:

```bash
# 1) Push the code to main
git push origin main

# 2) Tag and push the new version
git tag v1.1.0
git push origin v1.1.0

# 3) Wait for the "release" workflow under Actions — the Release shows up ready to download.
```

To test the packaging locally without publishing (requires `goreleaser`):

```bash
make snapshot   # builds local dist/
```
