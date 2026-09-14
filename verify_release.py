#!/usr/bin/env python3
"""Read-only provenance/digest gate. Does not deploy, sign, execute or extract.

Use reviewed Python 3.12+ and a trusted current GitHub CLI installation.
Inputs: policy.json artifact.tar.gz provenance.jsonl result.json
Writes a result only after every gate succeeds. Never consume an old result
after a nonzero exit. This candidate has not been executed or tested.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile
from datetime import datetime, timezone


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def gh(*args):
    # Ignore an unrelated GH_HOST configuration: this policy trusts github.com.
    if args and args[0] == "api":
        args = ("api", "--hostname", "github.com", "-H", "X-GitHub-Api-Version: 2026-03-10", *args[1:])
    return subprocess.check_output(
        ["gh", *args], text=True, timeout=90, stderr=subprocess.PIPE
    )


def archive_inventory(path):
    require(path.stat().st_size <= 100 * 1024**2, "Archive exceeds approved size")
    records = {}
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for count, member in enumerate(archive):
            require(count < 20000, "Too many archive entries")
            name = member.name.rstrip("/")
            parts = name.split("/")
            require(parts[0] == "dist" and all(p not in ("", ".", "..") for p in parts), "Unsafe archive path")
            require("\\" not in name and not name.startswith("/") and all(ord(c) >= 32 for c in name), "Unsafe archive path")
            require(member.isdir() or member.isfile(), "Links and special archive entries are prohibited")
            if member.isdir():
                continue
            relative = name.removeprefix("dist/")
            require(relative != "dist" and relative not in records, "Duplicate or invalid file")
            total += member.size
            require(member.size <= 100 * 1024**2 and total <= 512 * 1024**2, "Expanded archive exceeds policy")
            with archive.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            require(len(data) == member.size, "Truncated archive member")
            records[relative] = {"sha256": sha(data), "bytes": data}
    return records


def main():
    require(len(sys.argv) == 5, "Usage: verify_release.py policy.json artifact.tar.gz provenance.jsonl result.json")
    policy_path, artifact, bundle, output = map(pathlib.Path, sys.argv[1:])
    require(output.resolve() not in {p.resolve() for p in (policy_path, artifact, bundle)}, "Output would overwrite an input")
    # Remove a stale local decision so a failed new check cannot look successful.
    output.unlink(missing_ok=True)
    policy = json.loads(policy_path.read_text(encoding="utf-8-sig"))
    require(policy.get("configured") is True, "Repository and release policy is not configured")
    for key in ("source_repository", "signer_repository"):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", policy.get(key) or ""), "Missing or invalid " + key)
    for key in ("source_sha", "signer_sha"):
        require(re.fullmatch(r"[0-9a-f]{40}", policy.get(key) or ""), "Missing immutable " + key)
    for key in ("artifact_sha256", "application_inventory_sha256", "application_build_id"):
        require(re.fullmatch(r"[0-9a-f]{64}", policy.get(key) or ""), "Missing approved " + key)
    for key in ("source_repository_id", "run_id", "run_attempt", "artifact_id"):
        require(type(policy.get(key)) is int and policy[key] > 0, "Missing positive " + key)
    require(re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]+", policy.get("source_ref") or ""), "Protected branch ref required")
    require(policy["predicate_type"] == "https://slsa.dev/provenance/v1", "Unexpected predicate policy")
    require(policy["oidc_issuer"] == "https://token.actions.githubusercontent.com", "Unexpected issuer")
    require(policy["deny_self_hosted_runners"] is True, "Hosted-runner requirement disabled")
    require(policy["application_version"] == "4.0.0", "This gate is scoped to Site 4.0.0")
    actual_digest = digest_file(artifact)
    require(actual_digest == policy["artifact_sha256"], "Deployment archive digest does not match approval")

    repo = policy["source_repository"]
    run = json.loads(gh("api", f"repos/{repo}/actions/runs/{policy['run_id']}"))
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "Hosted workflow did not succeed")
    require(run.get("head_sha") == policy["source_sha"], "Run used a different source commit")
    require(run.get("run_attempt") == policy["run_attempt"], "Run attempt changed; review again")
    require(run.get("event") == "workflow_dispatch", "Unexpected triggering event")
    require(run.get("head_branch") == policy["source_ref"].removeprefix("refs/heads/"), "Unexpected source branch")
    expected_path = policy["caller_workflow_path"]
    # GitHub's documented REST example includes a ref suffix; older responses
    # omit it. Accept only the exact approved branch/commit when one is present.
    accepted_paths = {expected_path, *(expected_path + "@" + ref for ref in (
        policy["source_ref"], policy["source_ref"].removeprefix("refs/heads/"), policy["source_sha"]))}
    require(run.get("path") in accepted_paths, "Unexpected caller workflow")
    require(run.get("repository", {}).get("id") == policy["source_repository_id"], "Source repository identity changed")
    hosted_artifact = json.loads(gh("api", f"repos/{repo}/actions/artifacts/{policy['artifact_id']}"))
    require(hosted_artifact.get("expired") is False, "Hosted artifact expired")
    require(hosted_artifact.get("workflow_run", {}).get("id") == policy["run_id"], "Artifact belongs to another run")
    require(hosted_artifact.get("workflow_run", {}).get("head_sha") == policy["source_sha"], "Artifact source mismatch")
    require(hosted_artifact.get("name") == "numina-site-v4.0.0.tar.gz", "Unexpected artifact name")
    # The workflow uploads archive:false, so this service digest covers the raw
    # deployment archive, not an extra GitHub-generated ZIP wrapper.
    require(hosted_artifact.get("digest") == "sha256:" + actual_digest, "Hosted artifact digest mismatch")

    verified = json.loads(gh(
        "attestation", "verify", str(artifact.resolve()),
        "--hostname", "github.com",
        "--bundle", str(bundle.resolve()), "--repo", repo,
        "--signer-workflow", policy["signer_repository"] + "/" + policy["signer_workflow_path"],
        "--signer-digest", policy["signer_sha"],
        "--source-digest", policy["source_sha"], "--source-ref", policy["source_ref"],
        "--cert-oidc-issuer", policy["oidc_issuer"],
        "--predicate-type", policy["predicate_type"],
        "--deny-self-hosted-runners", "--format", "json",
    ))
    require(isinstance(verified, list) and verified, "No verified provenance")
    invocation = f"https://github.com/{repo}/actions/runs/{policy['run_id']}/attempts/{policy['run_attempt']}"
    # Trust these predicate fields only after checking the exact reviewed
    # reusable signer whose fresh job generates them, above.
    matching = [item for item in verified if
        item.get("verificationResult", {}).get("statement", {}).get("predicate", {})
        .get("runDetails", {}).get("metadata", {}).get("invocationId") == invocation]
    require(matching, "Signed provenance is not from the approved run attempt")

    files = archive_inventory(artifact)
    manifest_name = "client/downloads/application-release-v4.json"
    manifest_aliases = {manifest_name, "client/downloads/application-release-v3.json", "client/downloads/application-release-v2.json", "client/downloads/release.json"}
    manifest_bytes = files[manifest_name]["bytes"]
    inventory_digest = sha(manifest_bytes)
    require(inventory_digest == policy["application_inventory_sha256"], "Application inventory digest differs from approval")
    require(any(any(subject.get("digest", {}).get("sha256") == inventory_digest
                    for subject in item["verificationResult"]["statement"].get("subject", []))
                for item in matching), "Verified statement does not also sign this exact inventory")
    require(all(manifest_bytes == files[name]["bytes"] for name in manifest_aliases), "Release manifests disagree")
    manifest = json.loads(manifest_bytes)
    require(manifest.get("schema") == "numina.application-release.v2" and manifest.get("schema_version") == 2, "Unsupported manifest")
    require(manifest.get("version") == "4.0.0" and manifest.get("release") == "numina-v4.0.0", "Release version mismatch")
    measured = [{"path": name, "sha256": record["sha256"]} for name, record in sorted(files.items())
                if name not in manifest_aliases]
    require(measured == manifest.get("artifacts"), "Manifest does not cover exactly the archive files")
    tree_digest = sha("".join(row["sha256"] + "  " + row["path"] + "\n" for row in measured).encode())
    require(tree_digest == manifest.get("build_id") == policy["application_build_id"], "Application artifact tree mismatch")
    require(files["server/index.js"]["sha256"] == manifest.get("workerSha256"), "Worker digest mismatch")
    require(json.loads(files[".openai/hosting.json"]["bytes"])["project_id"] == policy["project_id"], "Wrong deployment project")
    require(policy.get("runtime_version") == "1.9.0-rc26", "Explicit reviewed runtime version required")
    require(manifest.get("runtime_dependency", {}).get("version") == policy["runtime_version"], "Runtime composition differs from policy")
    result = {
        "schema": "numina.provenance-gate-result.v1",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "decision": "artifact_and_provenance_verified_deployment_not_performed",
        "policy_sha256": digest_file(policy_path), "bundle_sha256": digest_file(bundle),
        "artifact_sha256": actual_digest, "application_build_id": tree_digest,
        "application_inventory_sha256": inventory_digest,
        "source_repository": repo, "source_sha": policy["source_sha"],
        "signer_sha": policy["signer_sha"], "run_url": invocation,
        "artifact_id": policy["artifact_id"], "project_id": policy["project_id"],
        "github_cli_version": gh("--version").splitlines()[0],
        "verification": matching, "slsa_level_claimed": None,
        "deployment_verified": False,
    }
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Verified the approved artifact and provenance. No deployment was performed.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        # Do not print command stderr, which might contain authentication data.
        print("Verification refused: " + str(error), file=sys.stderr)
        sys.exit(1)
