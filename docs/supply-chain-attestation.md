# Supply-Chain Attestation Guide

This guide adds cryptographic supply-chain proof on top of Omar Gate findings so enterprise reviewers can verify provenance and SBOM integrity.

## 1. Emit SLSA provenance from GitHub Actions

Use GitHub attestation permissions and provenance generation in your release workflow.

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make release
      - name: Attest build provenance
        uses: actions/attest-build-provenance@v4
        with:
          subject-path: "dist/*"
```

## 2. Attach an SPDX SBOM attestation for containers

```bash
COSIGN_EXPERIMENTAL=1 cosign attest \
  --predicate sbom.spdx.json \
  --type spdx \
  oci://registry/org/image:tag
```

## 3. Publish verify commands for buyer review

```bash
# Provenance verification (GitHub Attestations)
gh attestation verify dist/myapp-linux-amd64 -R org/repo

# SBOM attestation verification (Cosign)
cosign verify-attestation --type spdx oci://registry/org/image:tag
```

## 4. Suggested checklist

1. Omar Gate PR run passes required severity gate.
2. Release build emits provenance attestation.
3. Container image has signed SPDX SBOM attestation.
4. README includes verify commands above for third-party auditors.
5. Release notes include artifact name, digest, and attestation references.
