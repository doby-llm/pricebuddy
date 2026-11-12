from __future__ import annotations

import json
import pathlib
import sys
import tarfile
import tempfile
import types
import uuid
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest import mock


BACKUP_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKUP_DIR))

import pricebuddy_backup as backup  # noqa: E402


class ManifestTests(unittest.TestCase):
    def make_manifest(self, root: pathlib.Path, *, remote_capable: bool = False) -> dict:
        dump = root / "mysql.sql"
        storage = root / "storage.tar"
        marker = root / backup.RESTORE_SECRET_MARKER
        compose_provenance = root / backup.COMPOSE_PROVENANCE_FILENAME
        compose = root / "docker-compose.yml"
        env = root / ".env"

        dump.write_text("-- deterministic schema only\n", encoding="utf-8")
        storage.write_bytes(b"storage-tar")
        backup.write_restore_secret_marker(marker)
        compose.write_text(
            "services:\n  app:\n    environment:\n      APP_KEY: TEST_ONLY_NOT_A_SECRET_APP_KEY\n",
            encoding="utf-8",
        )
        env.write_text(
            "APP_KEY=TEST_ONLY_NOT_A_SECRET_APP_KEY\nPUBLIC_NAME=TEST_ONLY_NOT_A_SECRET_PUBLIC_NAME\n",
            encoding="utf-8",
        )
        backup.write_compose_provenance(root, compose_provenance)

        return backup.build_manifest(
            created_at="2026-08-23T12:00:00Z",
            backup_id="pricebuddy-test",
            repo_root=root,
            database_container="pricebuddy-database-1",
            storage_volume="pricebuddy_storage",
            files=[dump, storage, marker, compose_provenance],
            restore_marker=marker,
            remote_capable=remote_capable,
        )

    def make_archive(self, root: pathlib.Path, *, version: int = 3, name: str = "backup.tar") -> pathlib.Path:
        manifest = self.make_manifest(root, remote_capable=version == 4)
        if version == 2:
            manifest.update(
                manifest_version=2,
                local_only=False,
                network_upload=True,
                remote_deletion=True,
                remote_transport={
                    "provider": "google_drive",
                    "scope": backup.LEGACY_DRIVE_SCOPE,
                    "folder_name": backup.LEGACY_DRIVE_FOLDER_NAME,
                    "credentials_in_manifest": False,
                },
            )
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        backup.write_sha256_sidecar(manifest_path)
        archive_path = root / name
        with tarfile.open(archive_path, "w") as archive:
            for entry in manifest["files"]:
                archive.add(root / entry["name"], arcname=entry["name"])
            archive.add(manifest_path, arcname="manifest.json")
        backup.write_sha256_sidecar(archive_path)
        return archive_path

    def test_manifest_validation_accepts_local_only_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)

            backup.validate_manifest(manifest)

            self.assertTrue(manifest["local_only"])
            self.assertFalse(manifest["network_upload"])
            self.assertFalse(manifest["remote_deletion"])
            self.assertNotIn("remote_transport", manifest)
            self.assertEqual(manifest["manifest_version"], 3)
            self.assertTrue(manifest["restore"]["secrets_required_separately"])
            self.assertEqual(manifest["source"]["mysql_dump"]["credentials_source"], "container_environment")
            self.assertNotIn("sanitized_excerpt", manifest["provenance"]["compose_files"][0])
            self.assertFalse(manifest["provenance"]["compose_files"][0]["contents_copied"])
            self.assertEqual(
                manifest["provenance"]["compose_files"][0]["redacted_artifact"],
                backup.COMPOSE_PROVENANCE_FILENAME,
            )
            self.assertEqual(
                manifest["provenance"]["compose_provenance_artifact"]["name"],
                backup.COMPOSE_PROVENANCE_FILENAME,
            )
            self.assertNotIn("TEST_ONLY_NOT_A_SECRET_APP_KEY", json.dumps(manifest))

    def test_v2_v3_v4_archives_are_fully_verified_offline(self) -> None:
        for version in (2, 3, 4):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp_name:
                root = pathlib.Path(temp_name)
                archive = self.make_archive(root, version=version)

                backup.verify_local(archive)

                manifest = backup.extract_manifest_from_archive(archive)
                backup.validate_manifest(manifest, set(backup.inspect_archive(archive)))
                self.assertEqual(manifest["manifest_version"], version)
                self.assertTrue(manifest["restore"]["secrets_required_separately"])
                if version == 4:
                    self.assertEqual(manifest["remote_transport"]["scope"], backup.DRIVE_SCOPE)
                    self.assertEqual(manifest["remote_transport"]["folder_name"], backup.DRIVE_FOLDER_NAME)
                    self.assertFalse(manifest["remote_transport"]["credentials_in_manifest"])
                    self.assertFalse(manifest["remote_upload_verified"])
                else:
                    self.assertNotIn("remote_upload_verified", manifest)

    def test_write_compose_provenance_redacts_values_and_records_source_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            compose = root / "docker-compose.yml"
            output = root / backup.COMPOSE_PROVENANCE_FILENAME
            compose.write_text(
                "services:\n  app:\n    environment:\n      APP_KEY: TEST_ONLY_NOT_A_SECRET_APP_KEY\n",
                encoding="utf-8",
            )

            backup.write_compose_provenance(root, output)

            text = output.read_text(encoding="utf-8")
            self.assertIn("# source_path: docker-compose.yml", text)
            self.assertIn(f"# source_sha256: {backup.sha256_file(compose)}", text)
            self.assertIn("APP_KEY: [REDACTED]", text)
            self.assertNotIn("TEST_ONLY_NOT_A_SECRET_APP_KEY", text)

    def test_manifest_validation_rejects_missing_secret_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest["files"] = [entry for entry in manifest["files"] if entry["name"] != backup.RESTORE_SECRET_MARKER]

            with self.assertRaisesRegex(backup.BackupError, "restore secret marker"):
                backup.validate_manifest(manifest)

    def test_manifest_validation_rejects_missing_compose_provenance_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest["files"] = [
                entry for entry in manifest["files"] if entry["name"] != backup.COMPOSE_PROVENANCE_FILENAME
            ]

            with self.assertRaisesRegex(backup.BackupError, "redacted compose provenance"):
                backup.validate_manifest(manifest)

    def test_manifest_validation_rejects_malformed_sections_without_attribute_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest["restore"] = "not-a-dict"

            with self.assertRaisesRegex(backup.BackupError, "restore section"):
                backup.validate_manifest(manifest)

    def test_manifest_validation_rejects_password_like_key_value_without_real_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest["provenance"]["unsafe_fixture"] = {
                "DB_PASSWORD": "TEST_ONLY_NOT_A_REAL_PASSWORD_VALUE",
            }

            with self.assertRaisesRegex(backup.BackupError, "unredacted secret value"):
                backup.validate_manifest(manifest)

    def test_verify_local_rejects_checksum_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest_path = root / "manifest.json"
            archive_path = root / "backup.tar"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

            with tarfile.open(archive_path, "w") as archive:
                for entry in manifest["files"]:
                    archive.add(root / entry["name"], arcname=entry["name"])
                archive.add(manifest_path, arcname="manifest.json")

            backup.write_sha256_sidecar(archive_path)
            backup.write_sha256_sidecar(manifest_path)
            archive_path.write_bytes(archive_path.read_bytes() + b"tamper")

            with self.assertRaisesRegex(backup.BackupError, "Checksum mismatch"):
                backup.verify_local(archive_path)

    def test_verify_local_rejects_inner_payload_checksum_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest_path = root / "manifest.json"
            archive_path = root / "backup.tar"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

            (root / "mysql.sql").write_bytes(b"x" * (root / "mysql.sql").stat().st_size)
            with tarfile.open(archive_path, "w") as archive:
                for entry in manifest["files"]:
                    archive.add(root / entry["name"], arcname=entry["name"])
                archive.add(manifest_path, arcname="manifest.json")

            backup.write_sha256_sidecar(archive_path)
            backup.write_sha256_sidecar(manifest_path)

            with self.assertRaisesRegex(backup.BackupError, "checksum mismatch for mysql.sql"):
                backup.verify_local(archive_path)

    def test_verify_local_rejects_raw_env_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest_path = root / "manifest.json"
            archive_path = root / "backup.tar"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

            with tarfile.open(archive_path, "w") as archive:
                for entry in manifest["files"]:
                    archive.add(root / entry["name"], arcname=entry["name"])
                archive.add(root / ".env", arcname=".env")
                archive.add(manifest_path, arcname="manifest.json")

            backup.write_sha256_sidecar(archive_path)
            backup.write_sha256_sidecar(manifest_path)

            with self.assertRaisesRegex(backup.BackupError, "raw compose or env"):
                backup.verify_local(archive_path)

    def test_verify_local_rejects_raw_compose_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest_path = root / "manifest.json"
            archive_path = root / "backup.tar"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

            with tarfile.open(archive_path, "w") as archive:
                for entry in manifest["files"]:
                    archive.add(root / entry["name"], arcname=entry["name"])
                archive.add(root / "docker-compose.yml", arcname="docker-compose.yml")
                archive.add(manifest_path, arcname="manifest.json")

            backup.write_sha256_sidecar(archive_path)
            backup.write_sha256_sidecar(manifest_path)

            with self.assertRaisesRegex(backup.BackupError, "raw compose or env"):
                backup.verify_local(archive_path)

    def test_verify_local_rejects_unredacted_compose_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = self.make_manifest(root)
            manifest_path = root / "manifest.json"
            archive_path = root / "backup.tar"
            provenance = root / backup.COMPOSE_PROVENANCE_FILENAME
            provenance.write_text(
                provenance.read_text(encoding="utf-8").replace(
                    "APP_KEY: [REDACTED]",
                    "APP_KEY: TEST_ONLY_NOT_A_SECRET_APP_KEY",
                ),
                encoding="utf-8",
            )
            for entry in manifest["files"]:
                if entry["name"] == backup.COMPOSE_PROVENANCE_FILENAME:
                    entry["size"] = provenance.stat().st_size
                    entry["sha256"] = backup.sha256_file(provenance)
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

            with tarfile.open(archive_path, "w") as archive:
                for entry in manifest["files"]:
                    archive.add(root / entry["name"], arcname=entry["name"])
                archive.add(manifest_path, arcname="manifest.json")

            backup.write_sha256_sidecar(archive_path)
            backup.write_sha256_sidecar(manifest_path)

            with self.assertRaisesRegex(backup.BackupError, "unredacted secret"):
                backup.verify_local(archive_path)


class RedactionTests(unittest.TestCase):
    def test_safe_redaction_removes_secret_values_and_keeps_public_values(self) -> None:
        fixture = """services:
  app:
    environment:
      APP_KEY: TEST_ONLY_NOT_A_SECRET_APP_KEY
      DB_PASSWORD: TEST_ONLY_NOT_A_SECRET_DB_PASSWORD
      TELEGRAM_BOT_TOKEN: TEST_ONLY_NOT_A_SECRET_TELEGRAM_BOT_TOKEN
      APP_USER_EMAIL: TEST_ONLY_NOT_A_SECRET_APP_USER_EMAIL
      PUBLIC_NAME: TEST_ONLY_NOT_A_SECRET_PUBLIC_NAME
"""
        redacted = backup.redact_text(fixture)

        self.assertIn("APP_KEY: [REDACTED]", redacted)
        self.assertIn("DB_PASSWORD: [REDACTED]", redacted)
        self.assertIn("TELEGRAM_BOT_TOKEN: [REDACTED]", redacted)
        self.assertIn("APP_USER_EMAIL: [REDACTED]", redacted)
        self.assertIn("PUBLIC_NAME: TEST_ONLY_NOT_A_SECRET_PUBLIC_NAME", redacted)
        self.assertNotIn("TEST_ONLY_NOT_A_SECRET_APP_KEY", redacted)
        self.assertNotIn("TEST_ONLY_NOT_A_SECRET_DB_PASSWORD", redacted)
        self.assertNotIn("TEST_ONLY_NOT_A_SECRET_TELEGRAM_BOT_TOKEN", redacted)
        self.assertNotIn("TEST_ONLY_NOT_A_SECRET_APP_USER_EMAIL", redacted)
        self.assertNotIn("TEST_ONLY_NOT_A_SECRET_MYSQL_ROOT_PASSWORD", redacted)


class BackupModeContractTests(unittest.TestCase):
    def test_cli_has_explicit_mutually_exclusive_modes(self) -> None:
        parser = backup.build_parser()
        options = {option for action in parser._actions for option in action.option_strings}
        self.assertIn("--drive", options)
        self.assertIn("--verify-drive", options)
        self.assertIn("--verify-local", options)
        self.assertNotIn("--upload-drive", options)

    def test_default_create_only_and_verify_local_do_not_load_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            archive = pathlib.Path(temp_name) / "local.tar"
            archive.write_bytes(b"local fixture archive")
            with (
                mock.patch.object(backup, "create_backup", return_value=archive),
                mock.patch.object(backup, "verify_local") as verify,
                mock.patch.object(backup, "load_drive_transport", side_effect=AssertionError("transport loaded")) as load,
                redirect_stdout(StringIO()),
            ):
                self.assertEqual(backup.main(["--output-dir", temp_name]), 0)
                self.assertEqual(backup.main(["--create-only", "--output-dir", temp_name]), 0)
                self.assertEqual(backup.main(["--verify-local", str(archive)]), 0)
            load.assert_not_called()
            verify.assert_called_once_with(archive.resolve())

    def test_invalid_mode_combinations_fail_before_capture_or_transport(self) -> None:
        for options in (
            ["--drive", "--verify-drive"],
            ["--drive", "--create-only"],
            ["--verify-local", "some.tar", "--verify-drive"],
            ["--create-only", "--drive-transport", "/tmp/transport.py"],
        ):
            with self.subTest(options=options):
                with (
                    mock.patch.object(backup, "create_backup") as capture,
                    mock.patch.object(backup, "load_drive_transport") as load,
                    redirect_stderr(StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    backup.main(options)
                capture.assert_not_called()
                load.assert_not_called()

    def test_drive_upload_failure_keeps_local_archive_and_sanitizes_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            archive = pathlib.Path(temp_name) / "pricebuddy-20261017T100000Z-aaaa1234.tar"
            archive.write_bytes(b"verified local archive fixture")

            class FailedTransport:
                def __init__(self, *, timeout: int) -> None:
                    self.timeout = timeout

                def upload_and_verify(self, *_args: object, **_kwargs: object) -> list[dict]:
                    raise RuntimeError("refresh_token=TEST_ONLY_NOT_A_SECRET")

            module = type("TransportModule", (), {"DriveBackupTransport": FailedTransport})
            stderr = StringIO()
            with (
                mock.patch.object(backup, "create_backup", return_value=archive),
                mock.patch.object(backup, "load_drive_transport", return_value=module),
                redirect_stderr(stderr),
                redirect_stdout(StringIO()),
            ):
                result = backup.main(["--drive", "--output-dir", temp_name, "--drive-transport", "/tmp/fixture.py"])

            self.assertEqual(result, 1)
            self.assertTrue(archive.is_file())
            self.assertIn("local archive was retained", stderr.getvalue())
            self.assertNotIn("TEST_ONLY_NOT_A_SECRET", stderr.getvalue())
            self.assertNotIn("refresh_token", stderr.getvalue())

    def test_new_capture_names_use_full_random_uuid_and_old_names_still_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            repo = root / "repo"
            output = root / "archives"
            repo.mkdir()
            output.mkdir()
            (repo / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            args = types.SimpleNamespace(
                repo_root=repo,
                output_dir=output,
                database_container="db",
                storage_volume="storage",
                helper_image="pinned-image",
                timeout=30,
                create_only=True,
                drive=False,
            )
            identifiers = [uuid.UUID(hex="a" * 32), uuid.UUID(hex="b" * 32)]

            def fake_dump(_container: str, path: pathlib.Path, _timeout: int) -> None:
                path.write_bytes(b"mysql fixture")

            def fake_storage(_volume: str, path: pathlib.Path, _image: str, _timeout: int) -> None:
                path.write_bytes(b"storage fixture")

            def fake_archive(_staging: pathlib.Path, archive_base: pathlib.Path) -> pathlib.Path:
                path = archive_base.with_suffix(".tar")
                path.write_bytes(b"archive fixture")
                return path

            with (
                mock.patch.object(backup, "utc_now", return_value="2026-10-17T10:00:00Z"),
                mock.patch.object(backup.uuid, "uuid4", side_effect=identifiers),
                mock.patch.object(backup, "dump_mysql", side_effect=fake_dump),
                mock.patch.object(backup, "capture_storage_volume", side_effect=fake_storage),
                mock.patch.object(backup, "make_archive", side_effect=fake_archive),
            ):
                first = backup.create_backup(args)
                second = backup.create_backup(args)

            self.assertNotEqual(first.name, second.name)
            for archive in (first, second):
                match = backup.ARCHIVE_NAME_RE.fullmatch(archive.name)
                self.assertIsNotNone(match)
                self.assertEqual(len(archive.stem.rsplit("-", 1)[1]), 32)
            self.assertTrue(backup.ARCHIVE_NAME_RE.fullmatch("pricebuddy-20261016T100000Z-aaaa1234.tar.zst"))

    def test_verify_drive_uses_newest_local_archive_and_does_not_fall_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            older_dir = root / "older"
            older_dir.mkdir()
            older = ManifestTests().make_archive(
                older_dir, name="pricebuddy-20261016T100000Z-aaaa1234.tar"
            )
            newest_dir = root / "newest"
            newest_dir.mkdir()
            newest = ManifestTests().make_archive(
                newest_dir, name="pricebuddy-20261017T100000Z-bbbb1234.tar"
            )
            output_dir = root / "archives"
            output_dir.mkdir()
            (output_dir / older.name).write_bytes(older.read_bytes())
            backup.write_sha256_sidecar(output_dir / older.name)
            (output_dir / newest.name).write_bytes(newest.read_bytes())
            backup.write_sha256_sidecar(output_dir / newest.name)

            class MissingNewest:
                calls: list[str] = []

                def __init__(self, *, timeout: int) -> None:
                    self.timeout = timeout

                def verify_remote(self, **kwargs: object) -> dict:
                    self.calls.append(str(kwargs["expected_artifact"]))
                    raise RuntimeError("remote object absent")

            module = type("TransportModule", (), {"DriveBackupTransport": MissingNewest})
            with mock.patch.object(backup, "load_drive_transport", return_value=module):
                with redirect_stderr(StringIO()):
                    result = backup.main([
                        "--verify-drive", "--output-dir", str(output_dir), "--drive-transport", "/tmp/fixture.py"
                    ])
            self.assertEqual(result, 1)
            self.assertEqual(MissingNewest.calls, [newest.name])

    def test_verify_drive_stops_before_transport_when_newest_local_archive_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            output_dir = pathlib.Path(temp_name)
            newest = output_dir / "pricebuddy-20261017T100000Z-bbbb1234.tar"
            newest.write_bytes(b"invalid local archive")

            class UnusedTransport:
                called = False

                def __init__(self, *, timeout: int) -> None:
                    pass

                def verify_remote(self, **_kwargs: object) -> dict:
                    self.called = True
                    raise AssertionError("remote verification must not run")

            module = type("TransportModule", (), {"DriveBackupTransport": UnusedTransport})
            stderr = StringIO()
            with (
                mock.patch.object(backup, "load_drive_transport", return_value=module),
                mock.patch.object(backup, "verify_local", side_effect=backup.BackupError("checksum failure")),
                redirect_stderr(stderr),
            ):
                result = backup.main([
                    "--verify-drive", "--output-dir", temp_name, "--drive-transport", "/tmp/fixture.py"
                ])
            self.assertEqual(result, 1)
            self.assertIn("failed local verification", stderr.getvalue())
            self.assertFalse(UnusedTransport.called)

    def test_legacy_drive_archive_manifest_remains_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            manifest = ManifestTests().make_manifest(root)
            manifest.update(
                manifest_version=2,
                local_only=False,
                network_upload=True,
                remote_deletion=True,
                remote_transport={
                    "provider": "google_drive",
                    "scope": backup.LEGACY_DRIVE_SCOPE,
                    "folder_name": backup.LEGACY_DRIVE_FOLDER_NAME,
                    "credentials_in_manifest": False,
                },
            )
            backup.validate_manifest(manifest)

    def test_helper_image_is_pinned_and_only_scheduled_service_opts_into_drive(self) -> None:
        self.assertIn("@sha256:", backup.DEFAULT_HELPER_IMAGE)
        self.assertTrue(backup.HELPER_IMAGE_ARCHIVE.is_file())
        self.assertEqual(backup.sha256_file(backup.HELPER_IMAGE_ARCHIVE), backup.HELPER_IMAGE_ARCHIVE_SHA256)
        unit = (BACKUP_DIR / "pricebuddy-backup.service").read_text(encoding="utf-8")
        self.assertIn(f"--helper-image {backup.DEFAULT_HELPER_IMAGE}", unit)
        self.assertIn("--drive", unit)
        self.assertNotIn("network-online.target", unit)

    def test_storage_capture_preflights_pinned_image_and_is_network_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            output = root / "storage.tar"
            calls: list[list[str]] = []

            def fake_safe_run(args: list[str], *, stdout: object = None, timeout: int = 120) -> backup.CommandResult:
                calls.append(args)
                if args[1:3] == ["image", "inspect"]:
                    return backup.CommandResult(0, backup.DEFAULT_HELPER_IMAGE_ID.encode() + b"\n", b"")
                if args[1] == "run":
                    output.write_bytes(b"test volume archive")
                return backup.CommandResult(0, b"[]", b"")

            with mock.patch.object(backup, "safe_run", side_effect=fake_safe_run):
                backup.capture_storage_volume("test-volume", output, backup.DEFAULT_HELPER_IMAGE, 17)

            self.assertEqual(calls[1], ["docker", "image", "inspect", "--format", "{{.Id}}", backup.DEFAULT_HELPER_IMAGE])
            run = calls[2]
            self.assertIn("--pull=never", run)
            self.assertIn("--network=none", run)
            self.assertIn("--entrypoint=/bin/tar", run)
            self.assertIn(backup.DEFAULT_HELPER_IMAGE_ID, run)
            self.assertEqual(output.read_bytes(), b"test volume archive")

    def test_missing_helper_is_restored_from_checksum_verified_local_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            archive = root / "helper.tar"
            archive.write_bytes(b"known helper image archive")
            archive_sha256 = backup.sha256_file(archive)
            output = root / "storage.tar"
            calls: list[list[str]] = []

            def fake_safe_run(args: list[str], *, stdout: object = None, timeout: int = 120) -> backup.CommandResult:
                calls.append(args)
                if args[1:3] == ["image", "inspect"] and args[-1] == backup.DEFAULT_HELPER_IMAGE:
                    raise backup.BackupError("Command failed: docker exited 1: No such image: pinned helper")
                if args[1:3] == ["image", "inspect"] and args[-1] == backup.DEFAULT_HELPER_IMAGE_ID:
                    return backup.CommandResult(0, backup.DEFAULT_HELPER_IMAGE_ID.encode() + b"\n", b"")
                if args[1] == "run":
                    output.write_bytes(b"restored volume archive")
                return backup.CommandResult(0, b"loaded", b"")

            with (
                mock.patch.object(backup, "HELPER_IMAGE_ARCHIVE", archive),
                mock.patch.object(backup, "HELPER_IMAGE_ARCHIVE_SHA256", archive_sha256),
                mock.patch.object(backup, "safe_run", side_effect=fake_safe_run),
            ):
                backup.capture_storage_volume("test-volume", output, backup.DEFAULT_HELPER_IMAGE, 1800)

            self.assertEqual(calls[2], ["docker", "image", "load", "--input", str(archive)])
            self.assertIn(backup.DEFAULT_HELPER_IMAGE_ID, calls[4])
            self.assertIn("--network=none", calls[4])
            self.assertEqual(output.read_bytes(), b"restored volume archive")

    def test_missing_helper_archive_with_bad_checksum_fails_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            archive = root / "helper.tar"
            archive.write_bytes(b"corrupted helper archive")
            calls: list[list[str]] = []

            def fake_safe_run(args: list[str], *, stdout: object = None, timeout: int = 120) -> backup.CommandResult:
                calls.append(args)
                if args[1:3] == ["image", "inspect"]:
                    raise backup.BackupError("Command failed: docker exited 1: No such image: pinned helper")
                return backup.CommandResult(0, b"[]", b"")

            with (
                mock.patch.object(backup, "HELPER_IMAGE_ARCHIVE", archive),
                mock.patch.object(backup, "HELPER_IMAGE_ARCHIVE_SHA256", "0" * 64),
                mock.patch.object(backup, "safe_run", side_effect=fake_safe_run),
                self.assertRaisesRegex(backup.BackupError, "checksum mismatch"),
            ):
                backup.capture_storage_volume("test-volume", root / "storage.tar", backup.DEFAULT_HELPER_IMAGE, 30)

            self.assertEqual(len(calls), 2)


class LocalRetentionTests(unittest.TestCase):
    def test_prune_local_keeps_three_complete_sets_and_ignores_unmatched_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            output_dir = pathlib.Path(temp_name)
            backup_ids = [
                "pricebuddy-20260918T070844Z-b11bb0a5",
                "pricebuddy-20260925T112238Z-21669972",
                "pricebuddy-20260930T090822Z-61f5ee9c",
                "pricebuddy-20261001T090822Z-abcdef12",
                "pricebuddy-20261002T090822Z-1234abcd",
            ]
            for backup_id in backup_ids:
                archive = output_dir / f"{backup_id}.tar.zst"
                archive.write_bytes(b"archive")
                (output_dir / f"{archive.name}.sha256").write_text("sidecar", encoding="utf-8")
                manifest = output_dir / f"{backup_id}.manifest.json"
                manifest.write_text("{}", encoding="utf-8")
                (output_dir / f"{manifest.name}.sha256").write_text("sidecar", encoding="utf-8")
            sentinel = output_dir / "manual-recovery-note.txt"
            sentinel.write_text("leave me", encoding="utf-8")

            removed = backup.prune_local(output_dir)

            self.assertEqual(
                [path.name for path in backup.local_archives(output_dir)],
                [f"{backup_id}.tar.zst" for backup_id in sorted(backup_ids[-3:], reverse=True)],
            )
            self.assertEqual(len(removed), 8)
            self.assertTrue(sentinel.exists())
            self.assertFalse((output_dir / f"{backup_ids[0]}.tar.zst").exists())
            self.assertFalse((output_dir / f"{backup_ids[1]}.manifest.json").exists())


class DumpOnlyArgParseTests(unittest.TestCase):
    """--dump-only --out PATH is the pibackup pre-hook: it writes the dump and nothing else."""

    def test_dump_only_parses_with_out(self) -> None:
        args = backup.build_parser().parse_args(["--dump-only", "--out", "db.sql"])
        self.assertTrue(args.dump_only)
        self.assertEqual(args.out, pathlib.Path("db.sql"))

    def test_dump_only_is_exclusive_with_drive(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            backup.build_parser().parse_args(["--dump-only", "--out", "db.sql", "--drive"])

    def test_dump_only_requires_out(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            backup.main(["--dump-only"])
        self.assertEqual(raised.exception.code, 2)

    def test_out_requires_dump_only(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            backup.main(["--out", "db.sql"])
        self.assertEqual(raised.exception.code, 2)

    def test_dump_only_writes_the_dump_and_skips_the_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "db.sql"
            with (
                mock.patch.object(backup, "dump_mysql") as dump,
                mock.patch.object(backup, "create_backup", side_effect=AssertionError("archive built")) as archive,
                mock.patch.object(backup, "load_drive_transport", side_effect=AssertionError("transport loaded")) as load,
            ):
                self.assertEqual(backup.main(["--dump-only", "--out", str(out)]), 0)
            dump.assert_called_once_with(backup.DEFAULT_DATABASE_CONTAINER, out, 600)
            archive.assert_not_called()
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
