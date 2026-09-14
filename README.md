# Numina hosted builder

This reusable GitHub Actions workflow builds the Numina 3.0 application from the protected `main` branch of `skott34-dot/numina-production` (repository ID 1367647143). Callers pin this workflow by its full commit SHA.

The source build has read-only repository access, no checkout credential persistence, no OIDC permission and no application secrets. A separate fresh GitHub-hosted job downloads immutable artifacts from that build and creates a generated SLSA provenance statement for both the exact deployment archive and application inventory. Source code is never executed in the signing job. Actions and Node are pinned. No test suite is run.

The `numina-provenance` environment is owner-governed and restricted to protected main. This setup does not claim independent human review. The `verify_release.py` gate checks cryptographic signatures, expected source and signer identities, immutable revisions, hosted run and artifacts, and the complete archive inventory before deployment. The detached bundle must remain separate so the signed artifact bytes never change.

A workflow file alone establishes no SLSA level. Retain actual successful run, bundle, verification output and exact deployment binding as the evidence for each release. Current per-release assessments are in the Numina release records.

Public source access does not grant new copyright or trademark licenses. Existing third-party licenses remain applicable.

The rc26 verifier workflow packages the reconstructed Python source from the same protected Numina repository. It checks the exact 105 frozen-core files and Python syntax, then signs the source archive and a newly measured inventory in a fresh job. The recovered production manifest is retained byte-for-byte, with differences recorded in the new inventory. This workflow performs source packaging; it does not install dependencies, run tests, start the service, evaluate production readiness, or deploy. The application verification policy now requires an explicit runtime version.

The Site 3.0 verifier requires all three release inventory aliases (`application-release-v3.json`, `application-release-v2.json` and `release.json`) to match byte-for-byte. The inventory schema remains `numina.application-release.v2`; application version and schema version are separate identities.
