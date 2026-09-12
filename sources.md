# Primary references observed 12 September 2026

- [SLSA v1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements): authentic/unforgeable provenance and hosted/isolated execution; not an achieved-level certificate for this package.
- [SLSA platform assessment](https://slsa.dev/spec/v1.2/assessing-build-platforms): platform control evidence and assessment boundaries.
- [GitHub reusable workflows and Build L3](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating): documented reusable-workflow attestation approach, described against SLSA v1.0; assess actual implementation against v1.2.
- [GitHub artifact attestation implementation and plan availability](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations): current `actions/attest@v4`, required permissions and repository availability.
- [GitHub attestation security model](https://docs.github.com/en/actions/concepts/security/artifact-attestations): keyless GitHub/Sigstore identities, public/private trust infrastructure.
- [GitHub CLI verification](https://cli.github.com/manual/gh_attestation_verify): source/signer digest and ref policy, deny-self-hosted, bundle/JSON verification; certificate metadata versus caller-controlled predicate fields.
- [GitHub workflow security](https://docs.github.com/en/actions/reference/security/secure-use): full-SHA pins, minimal privileges, safe expression handling, code-owner review and dependency maintenance.
- [Official Actions artifact REST response contracts](https://docs.github.com/en/rest/actions/artifacts): artifact ID, workflow association and service digest used by the verifier. Review current API behavior during adoption.
- [Official Actions workflow-run REST response contracts](https://docs.github.com/en/rest/actions/workflow-runs): source, attempt and completed run evidence used by the verifier.
- [actions/attest v4.2.1](https://github.com/actions/attest/releases/tag/v4.2.1), [pinned metadata](https://raw.githubusercontent.com/actions/attest/508db95dd578ae2727ebd6217d5ba78e4fbda05d/action.yml).
- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [actions/setup-node v7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0).
- [actions/upload-artifact v7.0.1 metadata](https://raw.githubusercontent.com/actions/upload-artifact/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/action.yml): `archive: false` uploads the single raw archive without a ZIP wrapper.
- [actions/download-artifact v8.0.1](https://github.com/actions/download-artifact/releases/tag/v8.0.1), [pinned usage](https://raw.githubusercontent.com/actions/download-artifact/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/README.md): raw download support and `digest-mismatch: error`.
- [Official Node 24 checksums](https://nodejs.org/download/release/latest-v24.x/SHASUMS256.txt): observed version/checksum recorded in `action-pins.json`; the workflow uses an exact version rather than this mutable latest URL.

Full upstream commit links and exact revisions are recorded in `action-pins.json`. No source repository, hosted builder run, signature or provider attestation was invented from these references.
