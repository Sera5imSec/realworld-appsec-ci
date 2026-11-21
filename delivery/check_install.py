"""Explicit integration check: real Docker install, update, checksum rejection and rollback."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import zipfile

from deploy import BASE, PROJECTS, deploy, docker, healthy, inspect
import deploy as installer


def bundle(project, revision, image, destination, corrupt=False):
    reference = "boundary-cd/" + project + ":" + revision
    docker("tag", image, reference)
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        archive = folder / "image.tar.gz"
        with gzip.open(archive, "wb", compresslevel=1) as output:
            save = subprocess.Popen(["docker", "save", reference], stdout=subprocess.PIPE)
            shutil.copyfileobj(save.stdout, output)
            save.stdout.close()
            if save.wait():
                raise RuntimeError("Image export failed")
        with archive.open("rb") as source:
            checksum = hashlib.file_digest(source, "sha256").hexdigest()
        manifest = {"schema_version": 1, "project": project, "repository": PROJECTS[project]["repository"],
                    "revision": revision, "ci_run_id": 0, "delivery_run_id": 0,
                    "platform": "linux/amd64", "image_reference": reference,
                    "image_id": "sha256:" + "f" * 64,
                    "archive_sha256": "0" * 64 if corrupt else checksum}
        (folder / "release.json").write_text(json.dumps(manifest))
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as output:
            for name in ("image.tar.gz", "release.json"):
                output.write(folder / name, name)


def main():
    outcomes = []
    directory = Path(__file__).resolve().parent / "artifacts"
    directory.mkdir(exist_ok=True)
    for project in PROJECTS:
        first, second = "1" * 40, "2" * 40
        image = "boundary-cd/" + project + ":local-check"
        archive = directory / (project + "-first.zip")
        bundle(project, first, image, archive)
        before = deploy(archive, project, first, 0, 0)
        assert before["status"] == "DEPLOYED"
        outcomes.append({"project": project, "check": "portable-image-identity", "status": "PASS"})
        if project == "realworld":
            with sqlite3.connect(BASE / project / "data/gorm.db") as connection:
                connection.execute("CREATE TABLE IF NOT EXISTS cd_persistence_probe (value TEXT)")
                connection.execute("INSERT INTO cd_persistence_probe VALUES ('kept-across-release')")
        with tempfile.TemporaryDirectory() as context:
            Path(context, "Dockerfile").write_text("FROM " + image + "\nLABEL org.opencontainers.image.revision=" + second + "\n")
            upgraded = "boundary-cd/" + project + ":second-check"
            subprocess.run(["docker", "build", "-t", upgraded, context], check=True)
        archive2 = directory / (project + "-second.zip")
        bundle(project, second, upgraded, archive2)
        after = deploy(archive2, project, second, 0, 0)
        assert after["image_id"] != before["image_id"]
        assert after["previous_image_id"] == before["image_id"]
        outcomes.append({"project": project, "check": "real-image-update", "status": "PASS"})
        corrupt = directory / (project + "-corrupt.zip")
        bundle(project, second, upgraded, corrupt, corrupt=True)
        try:
            deploy(corrupt, project, second, 0, 0)
            raise AssertionError("Corrupted archive was admitted")
        except ValueError as error:
            assert "checksum" in str(error)
        assert inspect("boundary-cd-" + project)["Image"] == after["image_id"]
        outcomes.append({"project": project, "check": "corrupt-artifact-rejected", "status": "PASS"})
        original = installer.healthy
        calls = 0
        def failure_during_promotion(port, config, attempts=35):
            nonlocal calls
            calls += 1
            return False if calls == 2 else original(port, config, attempts)
        installer.healthy = failure_during_promotion
        try:
            try:
                deploy(archive, project, first, 0, 0)
                raise AssertionError("Promotion failure was ignored")
            except RuntimeError as error:
                assert "Promoted container" in str(error)
        finally:
            installer.healthy = original
        assert inspect("boundary-cd-" + project)["Image"] == after["image_id"]
        assert healthy(PROJECTS[project]["port"], PROJECTS[project])
        outcomes.append({"project": project, "check": "failed-promotion-restores-previous-image", "status": "PASS"})
        if project == "realworld":
            with sqlite3.connect(BASE / project / "data/gorm.db") as connection:
                assert connection.execute("SELECT value FROM cd_persistence_probe").fetchone()[0] == "kept-across-release"
            outcomes.append({"project": project, "check": "database-persists-through-update-and-rollback", "status": "PASS"})
    (directory / "installation-checks.json").write_text(json.dumps(outcomes, indent=2) + "\n")
    print(json.dumps(outcomes))


if __name__ == "__main__":
    main()
