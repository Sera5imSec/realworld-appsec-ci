"""Build a local-CD artifact only for the current main commit with successful CI."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request


PROJECTS = {
    "eks": ("Sera5imSec/eks-boundary-matrix-ci", "app/Dockerfile", "app", "/", "healthy", True),
    "realworld": ("Sera5imSec/realworld-appsec-ci", "Dockerfile", ".", "/api/ping/", "message", "pong"),
}


def api(route):
    request = urllib.request.Request("https://api.github.com" + route, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json", "User-Agent": "boundary-local-cd",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def trusted_ci(run, repository, revision):
    return (run.get("conclusion") == "success" and run.get("status") == "completed"
            and run.get("head_sha") == revision and run.get("head_branch") == "main"
            and run.get("event") in ("push", "workflow_dispatch")
            and run.get("head_repository", {}).get("full_name") == repository
            and run.get("path") == ".github/workflows/ci.yml")


def verify_ci(repository, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid revision")
    root = "/repos/" + repository
    if api(root + "/commits/main")["sha"] != revision:
        raise ValueError("This revision is no longer main; delivery stopped")
    runs = api(root + "/actions/workflows/ci.yml/runs?head_sha=" + revision + "&per_page=30")["workflow_runs"]
    relevant = [run for run in runs if run.get("event") in ("push", "workflow_dispatch") and run.get("head_branch") == "main"]
    if not relevant or not trusted_ci(relevant[0], repository, revision):
        raise ValueError("The latest main CI for this exact revision must succeed")
    return relevant[0]["id"]


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def smoke(image, project):
    route, field, expected = PROJECTS[project][3:]
    command = ["run", "--detach", "--rm", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
               "--publish", "127.0.0.1::8080", "--env", "GIN_MODE=release",
               "--env", "JWT_SECRET=synthetic-cd-smoke-only",
               "--env", "DB_PATH=/tmp/smoke.db", image]
    container = docker(*command)
    try:
        inspection = json.loads(docker("inspect", container))[0]
        port = inspection["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
        for _ in range(45):
            try:
                with urllib.request.urlopen("http://127.0.0.1:" + port + route, timeout=2) as response:
                    if response.status == 200 and json.load(response).get(field) == expected:
                        return
            except (OSError, ValueError, urllib.error.URLError):
                pass
            time.sleep(1)
        raise RuntimeError("The built image did not pass its HTTP smoke check")
    finally:
        subprocess.run(["docker", "rm", "--force", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    project = os.environ["CD_PROJECT"]
    repository, dockerfile, context, *_ = PROJECTS[project]
    if os.environ["GITHUB_REPOSITORY"] != repository:
        raise ValueError("Unapproved repository")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    ci_run = verify_ci(repository, revision)
    image = "boundary-cd/" + project + ":" + revision
    subprocess.run(["docker", "build", "--platform=linux/amd64", "--label", "org.opencontainers.image.revision=" + revision,
                    "--label", "org.opencontainers.image.source=https://github.com/" + repository,
                    "--tag", image, "--file", dockerfile, context], check=True)
    smoke(image, project)
    destination = Path("artifacts/cd-release")
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / "image.tar.gz"
    with gzip.open(archive, "wb", compresslevel=1) as output:
        save = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE)
        try:
            shutil.copyfileobj(save.stdout, output)
        finally:
            save.stdout.close()
        if save.wait() != 0:
            raise RuntimeError("Image export failed")
    digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    manifest = {"schema_version": 1, "project": project, "repository": repository,
                "revision": revision, "ci_run_id": ci_run, "delivery_run_id": int(os.environ["GITHUB_RUN_ID"]),
                "image_id": docker("image", "inspect", "--format", "{{.Id}}", image),
                "archive_sha256": digest, "platform": "linux/amd64"}
    (destination / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
