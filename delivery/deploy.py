"""Install a verified CD image on the loopback-only Docker test stand."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

BASE = Path("/var/lib/boundary-local-cd")
PROJECTS = {
    "eks": {"repository": "Sera5imSec/eks-boundary-matrix-ci", "port": 18081, "uid": 1000,
            "route": "/", "field": "healthy", "expected": True},
    "realworld": {"repository": "Sera5imSec/realworld-appsec-ci", "port": 18082, "uid": 10001,
                  "route": "/api/ping/", "field": "message", "expected": "pong"},
}


def docker(*args, allow_failure=False):
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if result.returncode and not allow_failure:
        raise RuntimeError(result.stderr.strip() or "Docker operation failed")
    return result.stdout.strip()


def inspect(name):
    value = docker("inspect", name, allow_failure=True)
    rows = json.loads(value) if value else []
    return rows[0] if rows else None


def owned_remove(name, project):
    value = inspect(name)
    if value:
        if value["Config"].get("Labels", {}).get("boundary.cd.project") != project:
            raise RuntimeError("Refusing to change an unrelated container: " + name)
        docker("rm", "--force", name)


def healthy(port, config, attempts=35):
    for _ in range(attempts):
        try:
            with urllib.request.urlopen("http://127.0.0.1:" + str(port) + config["route"], timeout=2) as response:
                if response.status == 200 and json.load(response).get(config["field"]) == config["expected"]:
                    return True
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(1)
    return False


def snapshot(source, destination, uid):
    if source.exists():
        with sqlite3.connect(source) as before, sqlite3.connect(destination) as after:
            before.backup(after)
        os.chown(destination, uid, uid)


def start(name, project, image, data, env, port):
    config = PROJECTS[project]
    args = ["run", "--detach", "--name", name, "--label", "boundary.cd.project=" + project,
            "--user", str(config["uid"]) + ":" + str(config["uid"]), "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--memory=256m", "--cpus=1", "--pids-limit=128",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--env-file", str(env),
            "--publish", "127.0.0.1:" + str(port) + ":8080"]
    if project == "realworld":
        args += ["--mount", "type=bind,src=" + str(data) + ",dst=/data"]
    if port:
        args += ["--restart", "unless-stopped"]
    docker(*args, image)
    assigned = inspect(name)["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
    return int(assigned)


def deploy(archive, project, revision, ci_run, delivery_run):
    config = PROJECTS[project]
    directory = BASE / project
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    with (directory / "deployment.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix="artifact-", dir=directory) as temporary:
            temp = Path(temporary)
            with zipfile.ZipFile(archive) as bundle:
                if sorted(bundle.namelist()) != ["image.tar.gz", "release.json"]:
                    raise ValueError("Artifact must contain exactly image.tar.gz and release.json")
                if any(row.file_size > 750 * 1024 * 1024 for row in bundle.infolist()):
                    raise ValueError("Artifact is too large")
                for name in bundle.namelist():
                    with bundle.open(name) as source, (temp / name).open("wb") as target:
                        shutil.copyfileobj(source, target)
            manifest = json.loads((temp / "release.json").read_text())
            if (manifest.get("schema_version") != 1 or manifest.get("project") != project or
                    manifest.get("repository") != config["repository"] or manifest.get("revision") != revision or
                    manifest.get("ci_run_id") != ci_run or manifest.get("delivery_run_id") != delivery_run or
                    not re.fullmatch(r"[0-9a-f]{40}", revision) or manifest.get("platform") != "linux/amd64" or
                    not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest.get("image_id", ""))):
                raise ValueError("Artifact identity is invalid")
            with (temp / "image.tar.gz").open("rb") as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != manifest.get("archive_sha256"):
                    raise ValueError("Image archive checksum mismatch")
            docker("load", "--input", str(temp / "image.tar.gz"))
            image = manifest["image_id"]
            labels = json.loads(docker("image", "inspect", image))[0]["Config"].get("Labels", {})
            if (labels.get("org.opencontainers.image.revision") != revision or
                    labels.get("org.opencontainers.image.source") != "https://github.com/" + config["repository"]):
                raise ValueError("Loaded image labels do not match the admitted revision")
            name = "boundary-cd-" + project
            old = inspect(name)
            if old and old["Config"].get("Labels", {}).get("boundary.cd.project") != project:
                raise RuntimeError("Container name belongs to another application")
            data = directory / "data"
            data.mkdir(exist_ok=True)
            os.chown(data, config["uid"], config["uid"])
            env = directory / "runtime.env"
            if not env.exists():
                fd = os.open(env, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "w") as target:
                    target.write("GIN_MODE=release\nPORT=8080\nDB_PATH=/data/gorm.db\nJWT_SECRET=" + secrets.token_urlsafe(48) + "\n")
            candidate = name + "-candidate"
            previous = name + "-previous"
            owned_remove(candidate, project)
            candidate_data = temp / "candidate-data"
            candidate_data.mkdir(mode=0o750)
            os.chown(candidate_data, config["uid"], config["uid"])
            # The container user must be able to traverse the candidate path.
            os.chmod(temp, 0o755)
            if project == "realworld":
                snapshot(data / "gorm.db", candidate_data / "gorm.db", config["uid"])
            try:
                candidate_port = start(candidate, project, image, candidate_data, env, "")
                if not healthy(candidate_port, config):
                    raise RuntimeError("Candidate failed HTTP validation; current deployment was retained")
            finally:
                owned_remove(candidate, project)
            owned_remove(previous, project)
            backup = directory / "before-deploy.db"
            if backup.exists():
                backup.unlink()
            if old:
                docker("stop", "--time", "15", name)
                docker("rename", name, previous)
            try:
                if project == "realworld":
                    snapshot(data / "gorm.db", backup, config["uid"])
                start(name, project, image, data, env, config["port"])
                if not healthy(config["port"], config):
                    raise RuntimeError("Promoted container failed HTTP validation")
            except Exception:
                owned_remove(name, project)
                if project == "realworld" and backup.exists():
                    shutil.copy2(backup, data / "gorm.db")
                    os.chown(data / "gorm.db", config["uid"], config["uid"])
                if old:
                    docker("rename", previous, name)
                    docker("start", name)
                    if not healthy(config["port"], config):
                        raise RuntimeError("Deployment and restoration both failed")
                raise
            result = {"status": "DEPLOYED", "project": project, "revision": revision, "image_id": image,
                      "url": "http://localhost:" + str(config["port"]) + config["route"],
                      "previous_image_id": old["Image"] if old else None}
            (directory / "current.json").write_text(json.dumps(result, indent=2) + "\n")
            return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", choices=PROJECTS, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--ci-run", type=int, required=True)
    parser.add_argument("--delivery-run", type=int, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(deploy(args.archive, args.project, args.revision, args.ci_run, args.delivery_run)))
    except Exception as error:
        print(json.dumps({"status": "ERROR", "reason": str(error)}))
        raise SystemExit(1)
