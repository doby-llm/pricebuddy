#!/usr/bin/env python3
"""Create and verify PriceBuddy backups, with an explicit optional Drive path.

The helper runs on the host, captures the live database and storage volume via
Docker, and writes a sanitized manifest plus checksums. PriceBuddy backup data
is never uploaded or deleted remotely by this workflow.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from typing import Any, Iterable


MANIFEST_VERSION = 3
DRIVE_MANIFEST_VERSION = 4
LEGACY_DRIVE_SCOPE = "pricebuddy"
LEGACY_DRIVE_FOLDER_NAME = "PriceBuddy Backups"
DRIVE_SCOPE = "pricebuddy_hdd_drive"
DRIVE_FOLDER_NAME = "PriceBuddy Backups - HDD and Drive"
DEFAULT_DRIVE_TRANSPORT = pathlib.Path("/home/mflova/docker/backup-ops/drive_backup_transport.py")
DRIVE_TIMEOUT = 180
DEFAULT_DATABASE_CONTAINER = "pricebuddy-database-1"
DEFAULT_STORAGE_VOLUME = "pricebuddy_storage"
DEFAULT_HELPER_IMAGE = "alpine/git@sha256:a299a963fbe31628ab481ca42907bcf0691d004f86734c02638abdf513691d42"
DEFAULT_HELPER_IMAGE_ID = "sha256:a299a963fbe31628ab481ca42907bcf0691d004f86734c02638abdf513691d42"
HELPER_IMAGE_ARCHIVE = (
    pathlib.Path.home()
    / ".local/share/pricebuddy-backup/alpine-git-a299a963fbe31628ab481ca42907bcf0691d004f86734c02638abdf513691d42.tar"
)
HELPER_IMAGE_ARCHIVE_SHA256 = "1a338a06a65342a68f6ce3fcf765246964178da116aa0fab34f276f4ed21ac33"
COMPOSE_PROVENANCE_FILENAME = "compose.provenance.yml"
RESTORE_SECRET_MARKER = "RESTORE_SECRETS_REQUIRED.txt"
SECRET_PATTERNS = (
    "PASSWORD",
    "PASS",
    "SECRET",
    "TOKEN",
    "KEY",
    "API_KEY",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "COOKIE",
    "EMAIL",
)
REDACTION = "[REDACTED]"
PUBLIC_SECRET_METADATA_KEYS = {
    "SECRET_MARKER_FILE",
    "SECRETS_REQUIRED_SEPARATELY",
}
FORBIDDEN_ARCHIVE_NAMES = {
    ".env",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
}
MAX_MANIFEST_BYTES = 1024 * 1024
LOCAL_RETENTION = 3
ARCHIVE_NAME_RE = re.compile(r"^pricebuddy-[0-9]{8}T[0-9]{6}Z-(?:[0-9a-f]{8}|[0-9a-f]{32})\.(?:tar|tar\.zst)$")


class BackupError(RuntimeError):
    """Bounded operational failure with a user-safe message."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256_sidecar(path: pathlib.Path) -> pathlib.Path:
    digest = sha256_file(path)
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return sidecar


def read_sha256_sidecar(path: pathlib.Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    digest = text.split()[0] if text else ""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise BackupError(f"Invalid SHA-256 sidecar: {path}")
    return digest.lower()


def verify_sha256_sidecar(path: pathlib.Path) -> None:
    sidecar = path.with_name(path.name + ".sha256")
    if not sidecar.exists():
        raise BackupError(f"Missing SHA-256 sidecar for {path.name}")
    expected = read_sha256_sidecar(sidecar)
    actual = sha256_file(path)
    if actual != expected:
        raise BackupError(f"Checksum mismatch for {path.name}")


def local_archives(output_dir: pathlib.Path) -> list[pathlib.Path]:
    """Return only valid PriceBuddy archive names, newest first."""
    if not output_dir.is_dir():
        return []
    return sorted(
        (path for path in output_dir.iterdir() if path.is_file() and ARCHIVE_NAME_RE.fullmatch(path.name)),
        key=lambda path: path.name,
        reverse=True,
    )


def prune_local(output_dir: pathlib.Path, keep: int = LOCAL_RETENTION) -> list[pathlib.Path]:
    """Keep complete recent backup sets and leave unmatched files untouched."""
    if keep < 1:
        raise ValueError("local retention must keep at least one archive")
    removed: list[pathlib.Path] = []
    for archive in local_archives(output_dir)[keep:]:
        if archive.name.endswith(".tar.zst"):
            base = archive.name[: -len(".tar.zst")]
        else:
            base = archive.name[: -len(".tar")]
        related = (
            archive,
            output_dir / f"{archive.name}.sha256",
            output_dir / f"{base}.manifest.json",
            output_dir / f"{base}.manifest.json.sha256",
        )
        for path in related:
            path.unlink(missing_ok=True)
            removed.append(path)
    return removed


def is_secret_key(key: str) -> bool:
    upper = key.upper()
    if upper in PUBLIC_SECRET_METADATA_KEYS:
        return False
    parts = [part for part in re.split(r"[^A-Z0-9]+", upper) if part]
    return any(pattern in parts for pattern in SECRET_PATTERNS)


def has_unredacted_secret_assignment(text: str) -> bool:
    assignment = re.compile(r"^\s*(?:[-]\s*)?([A-Za-z_][A-Za-z0-9_]*)(\s*[:=]\s*)(.*?)\s*(?:#.*)?$")
    inline_assignment = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)(=)([^\s,;]+)")

    for line in text.splitlines() or [text]:
        match = assignment.match(line)
        if match and is_secret_key(match.group(1)) and match.group(3) != REDACTION:
            return True
        for inline_match in inline_assignment.finditer(line):
            if is_secret_key(inline_match.group(1)) and inline_match.group(3) != REDACTION:
                return True
    return False


def validate_no_unredacted_secret_values(data: Any) -> None:
    if isinstance(data, dict):
        for raw_key, value in data.items():
            key = str(raw_key)
            if is_secret_key(key) and value != REDACTION:
                raise BackupError("Manifest appears to contain an unredacted secret value")
            validate_no_unredacted_secret_values(value)
        return
    if isinstance(data, list):
        for item in data:
            validate_no_unredacted_secret_values(item)
        return
    if isinstance(data, str) and has_unredacted_secret_assignment(data):
        raise BackupError("Manifest appears to contain an unredacted secret value")


def sanitize_scalar(key: str, value: Any) -> Any:
    if is_secret_key(key):
        return REDACTION
    return value


def redact_mapping(data: Any) -> Any:
    if isinstance(data, dict):
        return {str(key): redact_mapping(sanitize_scalar(str(key), value)) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_mapping(item) for item in data]
    return data


def redact_text(text: str) -> str:
    lines: list[str] = []
    assignment = re.compile(r"^(\s*(?:[-]\s*)?([A-Za-z_][A-Za-z0-9_]*)(\s*[:=]\s*))(.*?)(\s*(?:#.*)?)$")
    inline_assignment = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)(=)([^\s,;]+)")

    for line in text.splitlines():
        match = assignment.match(line)
        if match and is_secret_key(match.group(2)):
            lines.append(f"{match.group(1)}{REDACTION}{match.group(5)}")
            continue

        def replace_inline(match_obj: re.Match[str]) -> str:
            key = match_obj.group(1)
            if is_secret_key(key):
                return f"{key}={REDACTION}"
            return match_obj.group(0)

        lines.append(inline_assignment.sub(replace_inline, line))

    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def parse_env_keys(env_path: pathlib.Path) -> list[str]:
    if not env_path.exists():
        return []
    keys: list[str] = []
    for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            keys.append(key)
    return sorted(set(keys))


def safe_run(args: list[str], *, stdout: Any = subprocess.PIPE, timeout: int = 120) -> CommandResult:
    try:
        completed = subprocess.run(
            args,
            stdout=stdout,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BackupError(f"Required command not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackupError(f"Command timed out: {args[0]}") from exc

    stdout_bytes = completed.stdout if isinstance(completed.stdout, bytes) else b""
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise BackupError(f"Command failed: {args[0]} exited {completed.returncode}: {redact_text(stderr)}")

    return CommandResult(completed.returncode, stdout_bytes, completed.stderr)


def require_database_env(container: str) -> None:
    command = (
        "missing=; "
        "for key in MYSQL_DATABASE MYSQL_USER MYSQL_PASSWORD; do "
        'eval "value=\\${$key:-}"; '
        '[ -n "$value" ] || missing="$missing $key"; '
        "done; "
        '[ -z "$missing" ] || { printf "missing required env keys:%s\\n" "$missing" >&2; exit 2; }'
    )
    result = safe_run(["docker", "exec", container, "sh", "-lc", command], timeout=30)
    if result.stdout.strip():
        raise BackupError("Unexpected output while checking database container environment")


def dump_mysql(container: str, output: pathlib.Path, timeout: int) -> None:
    require_database_env(container)
    command = (
        'exec mysqldump --single-transaction --quick --skip-lock-tables '
        '--routines --triggers --events '
        '-u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"'
    )
    with output.open("wb") as handle:
        safe_run(["docker", "exec", container, "sh", "-lc", command], stdout=handle, timeout=timeout)
    if output.stat().st_size == 0:
        raise BackupError("MySQL dump is empty")


def inspect_helper_image(image_ref: str) -> str:
    result = safe_run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
        timeout=30,
    )
    image_id = result.stdout.decode("utf-8", errors="replace").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise BackupError("Docker returned an invalid helper image ID")
    return image_id


def ensure_helper_image(helper_image: str, timeout: int) -> str:
    try:
        image_id = inspect_helper_image(helper_image)
    except BackupError as exc:
        missing = "No such image:" in str(exc) or "No such object:" in str(exc)
        if helper_image != DEFAULT_HELPER_IMAGE or not missing:
            raise BackupError(f"Unable to inspect local backup helper image: {helper_image}") from exc
        archive = HELPER_IMAGE_ARCHIVE
        if not archive.is_file():
            raise BackupError(f"Pinned helper image and local recovery archive are missing: {archive}") from exc
        try:
            archive_sha256 = sha256_file(archive)
        except OSError as archive_exc:
            raise BackupError(f"Unable to read pinned helper recovery archive: {archive}") from archive_exc
        if archive_sha256 != HELPER_IMAGE_ARCHIVE_SHA256:
            raise BackupError("Pinned helper recovery archive checksum mismatch")
        try:
            safe_run(["docker", "image", "load", "--input", str(archive)], timeout=min(timeout, 300))
            image_id = inspect_helper_image(DEFAULT_HELPER_IMAGE_ID)
        except BackupError as load_exc:
            raise BackupError("Unable to restore the pinned helper image from its verified local archive") from load_exc
        if image_id != DEFAULT_HELPER_IMAGE_ID:
            raise BackupError("Restored helper image ID does not match the pinned image")
        return image_id

    if helper_image == DEFAULT_HELPER_IMAGE and image_id != DEFAULT_HELPER_IMAGE_ID:
        raise BackupError("Pinned helper image resolved to an unexpected image ID")
    return image_id


def capture_storage_volume(volume: str, output: pathlib.Path, helper_image: str, timeout: int) -> None:
    safe_run(["docker", "volume", "inspect", volume], timeout=30)
    image_id = ensure_helper_image(helper_image, timeout)
    safe_run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--entrypoint=/bin/tar",
            "-v",
            f"{volume}:/source:ro",
            "-v",
            f"{output.parent}:/backup",
            image_id,
            "-C",
            "/source",
            "-cf",
            f"/backup/{output.name}",
            ".",
        ],
        timeout=timeout,
    )
    if output.stat().st_size == 0:
        raise BackupError("Storage archive is empty")


def write_restore_secret_marker(path: pathlib.Path) -> None:
    path.write_text(
        "\n".join(
            [
                "PriceBuddy restore secrets are required separately.",
                "",
                "This backup intentionally does not contain plaintext .env values, passwords,",
                "API keys, notification tokens, app keys, or provider credentials.",
                "",
                "Before restore, supply a reviewed PriceBuddy .env or equivalent runtime",
                "configuration for the scratch app and database containers.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def build_provenance(repo_root: pathlib.Path, compose_files: Iterable[pathlib.Path]) -> dict[str, Any]:
    compose_entries: list[dict[str, Any]] = []
    for compose_file in compose_files:
        if not compose_file.exists():
            continue
        raw = compose_file.read_text(encoding="utf-8", errors="replace")
        compose_entries.append(
            {
                "path": str(compose_file.relative_to(repo_root)),
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "contents_copied": False,
                "redacted_artifact": COMPOSE_PROVENANCE_FILENAME,
            }
        )

    env_path = repo_root / ".env"
    git_head = None
    try:
        git_head = safe_run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], timeout=10).stdout.decode().strip()
    except BackupError:
        git_head = None

    return {
        "host": socket.gethostname(),
        "repo_root": str(repo_root),
        "git_head": git_head,
        "compose_files": compose_entries,
        "compose_provenance_artifact": {
            "name": COMPOSE_PROVENANCE_FILENAME,
            "contains_redacted_contents": True,
            "contains_raw_contents": False,
        },
        "env_file": {
            "path": ".env",
            "present": env_path.exists(),
            "keys_present": parse_env_keys(env_path),
            "values_copied": False,
        },
    }


def write_compose_provenance(repo_root: pathlib.Path, output: pathlib.Path) -> None:
    compose_path = repo_root / "docker-compose.yml"
    if not compose_path.exists():
        raise BackupError(f"Required compose file is missing: {compose_path}")
    raw = compose_path.read_text(encoding="utf-8", errors="replace")
    source_path = str(compose_path.relative_to(repo_root))
    source_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    output.write_text(
        "\n".join(
            [
                "# PriceBuddy redacted Docker Compose provenance",
                f"# source_path: {source_path}",
                f"# source_sha256: {source_sha256}",
                "# redaction: secret-like values are replaced with [REDACTED]",
                redact_text(raw).rstrip("\n"),
                "",
            ]
        ),
        encoding="utf-8",
    )


def build_manifest(
    *,
    created_at: str,
    backup_id: str,
    repo_root: pathlib.Path,
    database_container: str,
    storage_volume: str,
    files: Iterable[pathlib.Path],
    restore_marker: pathlib.Path,
    remote_capable: bool = False,
) -> dict[str, Any]:
    file_entries = []
    for path in sorted(files, key=lambda item: item.name):
        file_entries.append(
            {
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    manifest = {
        "manifest_version": DRIVE_MANIFEST_VERSION if remote_capable else MANIFEST_VERSION,
        "backup_id": backup_id,
        "created_at": created_at,
        "local_only": not remote_capable,
        "network_upload": remote_capable,
        "remote_deletion": remote_capable,
        "source": {
            "database_container": database_container,
            "storage_volume": storage_volume,
            "mysql_dump": {
                "consistent_logical_dump": True,
                "credentials_source": "container_environment",
                "credentials_in_manifest": False,
            },
        },
        "restore": {
            "secrets_required_separately": True,
            "secret_marker_file": restore_marker.name,
            "scratch_verification_document": "RESTORE.md",
        },
        "provenance": build_provenance(repo_root, [repo_root / "docker-compose.yml"]),
        "files": file_entries,
    }
    if remote_capable:
        manifest["remote_transport"] = {
            "provider": "google_drive",
            "scope": DRIVE_SCOPE,
            "folder_name": DRIVE_FOLDER_NAME,
            "credentials_in_manifest": False,
        }
        # This records the requested transport mode, not a completed upload.
        manifest["remote_upload_verified"] = False
    return redact_mapping(manifest)


def validate_manifest(manifest: dict[str, Any], archive_names: set[str] | None = None) -> None:
    if not isinstance(manifest, dict):
        raise BackupError("Manifest must be a JSON object")
    required_top = {
        "manifest_version",
        "backup_id",
        "created_at",
        "local_only",
        "network_upload",
        "remote_deletion",
        "source",
        "restore",
        "provenance",
        "files",
    }
    missing = required_top.difference(manifest)
    if missing:
        raise BackupError(f"Manifest missing required keys: {', '.join(sorted(missing))}")
    if manifest["manifest_version"] not in (2, MANIFEST_VERSION, DRIVE_MANIFEST_VERSION):
        raise BackupError("Unsupported manifest version")
    if manifest["manifest_version"] == 2:
        # Historical archives remain readable; accepting their metadata does
        # not enable any network activity in this script.
        if manifest["local_only"] is not False or manifest["network_upload"] is not True or manifest["remote_deletion"] is not True:
            raise BackupError("Legacy manifest Drive-backed flags are invalid")
        remote_transport = manifest.get("remote_transport")
        if (
            not isinstance(remote_transport, dict)
            or remote_transport.get("provider") != "google_drive"
            or remote_transport.get("scope") != LEGACY_DRIVE_SCOPE
            or remote_transport.get("folder_name") != LEGACY_DRIVE_FOLDER_NAME
            or remote_transport.get("credentials_in_manifest") is not False
        ):
            raise BackupError("Legacy manifest Drive transport metadata is invalid")
    elif manifest["manifest_version"] == MANIFEST_VERSION:
        if manifest["local_only"] is not True or manifest["network_upload"] is not False or manifest["remote_deletion"] is not False:
            raise BackupError("Manifest local-only flags are invalid")
        if "remote_transport" in manifest:
            raise BackupError("Local-only manifest must not declare remote transport")
    else:
        if manifest["local_only"] is not False or manifest["network_upload"] is not True or manifest["remote_deletion"] is not True:
            raise BackupError("Manifest Drive-capable flags are invalid")
        remote_transport = manifest.get("remote_transport")
        if (
            not isinstance(remote_transport, dict)
            or remote_transport.get("provider") != "google_drive"
            or remote_transport.get("scope") != DRIVE_SCOPE
            or remote_transport.get("folder_name") != DRIVE_FOLDER_NAME
            or remote_transport.get("credentials_in_manifest") is not False
            or manifest.get("remote_upload_verified") is not False
        ):
            raise BackupError("Manifest Drive transport declaration is invalid")
    if not isinstance(manifest["restore"], dict):
        raise BackupError("Manifest restore section is invalid")
    if not isinstance(manifest["source"], dict):
        raise BackupError("Manifest source section is invalid")
    if not isinstance(manifest["provenance"], dict):
        raise BackupError("Manifest provenance section is invalid")
    if manifest["restore"].get("secrets_required_separately") is not True:
        raise BackupError("Manifest must mark restore secrets as required separately")
    marker_name = manifest["restore"].get("secret_marker_file")
    if marker_name != RESTORE_SECRET_MARKER:
        raise BackupError("Manifest restore secret marker is invalid")
    if not isinstance(manifest["files"], list) or not manifest["files"]:
        raise BackupError("Manifest must list artifact files")

    names: set[str] = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict):
            raise BackupError("Manifest file entry is invalid")
        name = entry.get("name")
        size = entry.get("size")
        digest = entry.get("sha256")
        if not isinstance(name, str) or not is_safe_archive_name(name):
            raise BackupError("Manifest file entry has an unsafe name")
        if name in FORBIDDEN_ARCHIVE_NAMES:
            raise BackupError("Manifest must not reference raw compose or env files")
        if name in names:
            raise BackupError(f"Manifest contains duplicate file entry: {name}")
        if not isinstance(size, int) or size < 0:
            raise BackupError(f"Manifest file entry has invalid size: {name}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise BackupError(f"Manifest file entry has invalid SHA-256: {name}")
        names.add(name)

    if RESTORE_SECRET_MARKER not in names:
        raise BackupError("Manifest artifact list is missing restore secret marker")
    if COMPOSE_PROVENANCE_FILENAME not in names:
        raise BackupError("Manifest artifact list is missing redacted compose provenance")
    if archive_names is not None and not names.issubset(archive_names):
        missing_from_archive = sorted(str(name) for name in names.difference(archive_names))
        raise BackupError(f"Manifest references files not present in archive: {', '.join(missing_from_archive)}")

    provenance = manifest["provenance"]
    compose_artifact = provenance.get("compose_provenance_artifact")
    if (
        not isinstance(compose_artifact, dict)
        or compose_artifact.get("name") != COMPOSE_PROVENANCE_FILENAME
        or compose_artifact.get("contains_redacted_contents") is not True
        or compose_artifact.get("contains_raw_contents") is not False
    ):
        raise BackupError("Manifest redacted compose provenance artifact is invalid")
    compose_files = provenance.get("compose_files", [])
    if not isinstance(compose_files, list) or not compose_files:
        raise BackupError("Manifest compose provenance is invalid")
    for compose_entry in compose_files:
        if not isinstance(compose_entry, dict):
            raise BackupError("Manifest compose provenance entry is invalid")
        if compose_entry.get("redacted_artifact") != COMPOSE_PROVENANCE_FILENAME:
            raise BackupError("Manifest compose provenance artifact reference is invalid")
        if compose_entry.get("contents_copied") is not False:
            raise BackupError("Manifest must not copy raw compose contents")
        if "sanitized_excerpt" in compose_entry or "contents" in compose_entry:
            raise BackupError("Manifest must not include compose contents")
    env_file = provenance.get("env_file")
    if not isinstance(env_file, dict) or env_file.get("values_copied") is not False:
        raise BackupError("Manifest must not copy raw env contents")

    validate_no_unredacted_secret_values(manifest)


def validate_compose_provenance_text(text: str, manifest: dict[str, Any]) -> None:
    provenance = manifest["provenance"]
    compose_files = provenance.get("compose_files", [])
    if not compose_files:
        raise BackupError("Manifest compose provenance is invalid")
    source_path = compose_files[0].get("path")
    source_sha256 = compose_files[0].get("sha256")
    expected_header = [
        "# PriceBuddy redacted Docker Compose provenance",
        f"# source_path: {source_path}",
        f"# source_sha256: {source_sha256}",
    ]
    for header in expected_header:
        if header not in text:
            raise BackupError("Redacted compose provenance metadata is invalid")

    assignment = re.compile(r"^\s*(?:[-]\s*)?([A-Za-z_][A-Za-z0-9_]*)(\s*[:=]\s*)(.*?)\s*(?:#.*)?$")
    inline_assignment = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)(=)([^\s,;]+)")
    for line in text.splitlines():
        match = assignment.match(line)
        if match and is_secret_key(match.group(1)) and match.group(3) != REDACTION:
            raise BackupError("Redacted compose provenance contains an unredacted secret value")
        for inline_match in inline_assignment.finditer(line):
            if is_secret_key(inline_match.group(1)) and inline_match.group(3) != REDACTION:
                raise BackupError("Redacted compose provenance contains an unredacted secret value")


def write_manifest(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    validate_manifest(manifest)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_archive(staging: pathlib.Path, archive_base: pathlib.Path) -> pathlib.Path:
    zstd = shutil.which("zstd")
    if zstd:
        tar_path = archive_base.with_suffix(".tar")
        with tarfile.open(tar_path, "w") as archive:
            for child in sorted(staging.iterdir(), key=lambda item: item.name):
                archive.add(child, arcname=child.name)
        zst_path = archive_base.with_suffix(".tar.zst")
        safe_run([zstd, "-q", "-f", "-T0", str(tar_path), "-o", str(zst_path)], timeout=600)
        tar_path.unlink(missing_ok=True)
        return zst_path

    tar_path = archive_base.with_suffix(".tar")
    with tarfile.open(tar_path, "w") as archive:
        for child in sorted(staging.iterdir(), key=lambda item: item.name):
            archive.add(child, arcname=child.name)
    return tar_path


def is_safe_archive_name(name: str) -> bool:
    path = pathlib.PurePosixPath(name)
    return (
        name == path.name
        and name not in {"", ".", ".."}
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def inspect_tar_archive(tar_path: pathlib.Path) -> dict[str, dict[str, Any]]:
    file_info: dict[str, dict[str, Any]] = {}
    with tarfile.open(tar_path, "r") as archive:
        for member in archive.getmembers():
            if not is_safe_archive_name(member.name):
                raise BackupError(f"Archive contains unsafe member path: {member.name}")
            name = pathlib.PurePosixPath(member.name).name
            if name in FORBIDDEN_ARCHIVE_NAMES:
                raise BackupError("Archive must not contain raw compose or env files")
            if not member.isfile():
                raise BackupError(f"Archive member is not a regular file: {member.name}")
            if name in file_info:
                raise BackupError(f"Archive contains duplicate file name: {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise BackupError(f"Archive member could not be read: {name}")
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
                if name == "manifest.json" and size > MAX_MANIFEST_BYTES:
                    raise BackupError("Archive manifest.json is too large")
            file_info[name] = {"size": size, "sha256": digest.hexdigest()}
    return file_info


def inspect_archive(archive_path: pathlib.Path) -> dict[str, dict[str, Any]]:
    if archive_path.name.endswith(".tar.zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            raise BackupError("zstd is required to verify .tar.zst archives")
        with tempfile.TemporaryDirectory(prefix="pricebuddy-verify-") as temp_name:
            tar_path = pathlib.Path(temp_name) / "archive.tar"
            safe_run([zstd, "-q", "-d", "-f", str(archive_path), "-o", str(tar_path)], timeout=600)
            return inspect_tar_archive(tar_path)

    return inspect_tar_archive(archive_path)


def list_archive_names(archive_path: pathlib.Path) -> set[str]:
    return set(inspect_archive(archive_path))


def extract_manifest_from_archive(archive_path: pathlib.Path) -> dict[str, Any]:
    if archive_path.name.endswith(".tar.zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            raise BackupError("zstd is required to verify .tar.zst archives")
        with tempfile.TemporaryDirectory(prefix="pricebuddy-manifest-") as temp_name:
            tar_path = pathlib.Path(temp_name) / "archive.tar"
            safe_run([zstd, "-q", "-d", "-f", str(archive_path), "-o", str(tar_path)], timeout=600)
            return extract_manifest_from_archive(tar_path)

    with tarfile.open(archive_path, "r") as archive:
        try:
            member = archive.getmember("manifest.json")
        except KeyError as exc:
            raise BackupError("Archive is missing manifest.json") from exc
        if not member.isfile() or member.size > MAX_MANIFEST_BYTES:
            raise BackupError("Archive manifest.json is invalid")
        handle = archive.extractfile(member)
        if handle is None:
            raise BackupError("Archive manifest.json could not be read")
        try:
            return json.loads(handle.read().decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError("Archive manifest.json is not valid JSON") from exc


def extract_text_file_from_archive(archive_path: pathlib.Path, name: str) -> str:
    if archive_path.name.endswith(".tar.zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            raise BackupError("zstd is required to verify .tar.zst archives")
        with tempfile.TemporaryDirectory(prefix="pricebuddy-artifact-") as temp_name:
            tar_path = pathlib.Path(temp_name) / "archive.tar"
            safe_run([zstd, "-q", "-d", "-f", str(archive_path), "-o", str(tar_path)], timeout=600)
            return extract_text_file_from_archive(tar_path, name)

    with tarfile.open(archive_path, "r") as archive:
        try:
            member = archive.getmember(name)
        except KeyError as exc:
            raise BackupError(f"Archive is missing {name}") from exc
        if not member.isfile():
            raise BackupError(f"Archive {name} is invalid")
        handle = archive.extractfile(member)
        if handle is None:
            raise BackupError(f"Archive {name} could not be read")
        return handle.read().decode("utf-8", errors="replace")


def verify_manifest_file_entries(manifest: dict[str, Any], archive_info: dict[str, dict[str, Any]]) -> None:
    for entry in manifest["files"]:
        name = entry["name"]
        actual = archive_info.get(name)
        if actual is None:
            raise BackupError(f"Manifest references files not present in archive: {name}")
        if actual["size"] != entry["size"]:
            raise BackupError(f"Archive file size mismatch for {name}")
        if actual["sha256"] != entry["sha256"].lower():
            raise BackupError(f"Archive file checksum mismatch for {name}")


def verify_local(archive_path: pathlib.Path) -> None:
    if not archive_path.exists():
        raise BackupError(f"Archive does not exist: {archive_path}")
    verify_sha256_sidecar(archive_path)
    archive_info = inspect_archive(archive_path)
    manifest_path = archive_path.with_name("manifest.json")
    archived_manifest = extract_manifest_from_archive(archive_path)
    if manifest_path.exists():
        verify_sha256_sidecar(manifest_path)
        try:
            sidecar_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError("Sidecar manifest.json is not valid JSON") from exc
        if sidecar_manifest != archived_manifest:
            raise BackupError("Sidecar manifest.json does not match archived manifest.json")
    validate_manifest(archived_manifest, set(archive_info))
    verify_manifest_file_entries(archived_manifest, archive_info)
    validate_compose_provenance_text(
        extract_text_file_from_archive(archive_path, COMPOSE_PROVENANCE_FILENAME),
        archived_manifest,
    )


def create_backup(args: argparse.Namespace) -> pathlib.Path:
    repo_root = pathlib.Path(args.repo_root).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    created_at = utc_now()
    backup_id = f"pricebuddy-{created_at.replace(':', '').replace('-', '').replace('Z', 'Z')}-{uuid.uuid4().hex}"

    with tempfile.TemporaryDirectory(prefix="pricebuddy-backup-") as temp_name:
        staging = pathlib.Path(temp_name)
        db_dump = staging / "mysql.sql"
        storage_tar = staging / "storage.tar"
        restore_marker = staging / RESTORE_SECRET_MARKER
        compose_provenance = staging / COMPOSE_PROVENANCE_FILENAME
        manifest_path = staging / "manifest.json"

        dump_mysql(args.database_container, db_dump, args.timeout)
        capture_storage_volume(args.storage_volume, storage_tar, args.helper_image, args.timeout)
        write_restore_secret_marker(restore_marker)
        write_compose_provenance(repo_root, compose_provenance)
        manifest = build_manifest(
            created_at=created_at,
            backup_id=backup_id,
            repo_root=repo_root,
            database_container=args.database_container,
            storage_volume=args.storage_volume,
            files=[db_dump, storage_tar, restore_marker, compose_provenance],
            restore_marker=restore_marker,
            remote_capable=bool(getattr(args, "drive", False)),
        )
        write_manifest(manifest_path, manifest)
        write_sha256_sidecar(db_dump)
        write_sha256_sidecar(storage_tar)
        write_sha256_sidecar(restore_marker)
        write_sha256_sidecar(compose_provenance)
        write_sha256_sidecar(manifest_path)

        archive_path = make_archive(staging, output_dir / backup_id)
        manifest_copy = output_dir / f"{backup_id}.manifest.json"
        manifest_copy.write_text(manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
        write_sha256_sidecar(archive_path)
        write_sha256_sidecar(manifest_copy)

    if not args.create_only:
        verify_local(archive_path)
    if not args.create_only:
        prune_local(output_dir)
    return archive_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create or verify a PriceBuddy backup archive.")
    parser.add_argument("--repo-root", default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", default=pathlib.Path(__file__).resolve().parent / "archives")
    parser.add_argument("--database-container", default=DEFAULT_DATABASE_CONTAINER)
    parser.add_argument("--storage-volume", default=DEFAULT_STORAGE_VOLUME)
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE)
    parser.add_argument("--timeout", type=int, default=600)

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--create-only", action="store_true", help="Create artifacts without running local verification.")
    mode.add_argument("--verify-local", metavar="ARCHIVE", help="Verify an existing local .tar or .tar.zst backup.")
    mode.add_argument("--drive", action="store_true", help="Create, locally verify, then upload this capture to Google Drive.")
    mode.add_argument("--verify-drive", action="store_true", help="Verify the newest valid local capture against its exact Drive object.")
    mode.add_argument("--dump-only", action="store_true", help="Write only the MySQL dump to --out (pibackup pre-hook; no archive, no Drive).")
    parser.add_argument("--out", type=pathlib.Path, default=None, help="Output file for --dump-only.")
    parser.add_argument(
        "--drive-transport",
        type=pathlib.Path,
        default=None,
        help="Path to the existing host Drive transport helper (used only by --drive/--verify-drive).",
    )
    return parser


def load_drive_transport(path: pathlib.Path) -> Any:
    """Load the optional transport only for an explicitly remote operation."""
    try:
        spec = importlib.util.spec_from_file_location("pricebuddy_drive_backup_transport", path)
        if spec is None or spec.loader is None:
            raise ImportError
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "DriveBackupTransport"):
            raise ImportError
        return module
    except Exception as exc:
        raise BackupError("Drive transport helper is unavailable or invalid") from exc


def verify_drive_current(args: argparse.Namespace, transport_module: Any) -> dict[str, Any]:
    try:
        output_dir = pathlib.Path(args.output_dir).resolve()
        archives = local_archives(output_dir)
    except OSError as exc:
        raise BackupError("Local PriceBuddy archives could not be listed for Drive verification") from exc
    if not archives:
        raise BackupError("No local PriceBuddy archive is available for Drive verification")
    archive = archives[0]
    try:
        verify_local(archive)
        digest = sha256_file(archive)
    except (BackupError, OSError) as exc:
        raise BackupError("Newest local PriceBuddy archive failed local verification") from exc
    try:
        record = transport_module.DriveBackupTransport(timeout=DRIVE_TIMEOUT).verify_remote(
            scope=DRIVE_SCOPE,
            folder_name=DRIVE_FOLDER_NAME,
            expected_artifact=archive.name,
            expected_sha256=digest,
        )
    except Exception as exc:
        raise BackupError("Drive verification failed for the newest local PriceBuddy archive") from exc
    if (
        not isinstance(record, dict)
        or record.get("event") != "remote_verified"
        or record.get("remote_verified") is not True
        or record.get("expected_artifact_verified") is not True
        or record.get("name") != archive.name
        or str(record.get("sha256", "")).lower() != digest
        or record.get("content_bytes_verified") is not True
        or record.get("content_sha256_verified") is not True
        or not isinstance(record.get("checks"), dict)
        or not record["checks"]
        or any(value is not True for value in record["checks"].values())
    ):
        raise BackupError("Drive verification did not prove the newest local PriceBuddy archive")
    return {
        "event": "remote_verified",
        "state": "HEALTHY",
        "folder_name": DRIVE_FOLDER_NAME,
        "name": archive.name,
        "sha256": digest,
        "remote_verified": True,
        "expected_artifact_verified": True,
        "content_bytes_verified": record.get("content_bytes_verified") is True,
        "content_sha256_verified": record.get("content_sha256_verified") is True,
        "range_reads_verified": record.get("range_reads_verified", 0),
        "backup_count": record.get("backup_count", 0),
        "checks": record.get("checks", {}),
    }


def upload_drive_capture(archive: pathlib.Path, transport_module: Any) -> None:
    try:
        digest = sha256_file(archive)
    except OSError as exc:
        raise BackupError("Verified local archive could not be read for Drive upload") from exc
    try:
        records = transport_module.DriveBackupTransport(timeout=DRIVE_TIMEOUT).upload_and_verify(
            archive,
            scope=DRIVE_SCOPE,
            folder_name=DRIVE_FOLDER_NAME,
            sha256=digest,
        )
    except Exception as exc:
        raise BackupError("Drive upload or verification failed; the local archive was retained") from exc
    if not isinstance(records, list) or not any(
        isinstance(record, dict)
        and record.get("event") == "remote_verified"
        and record.get("remote_verified") is True
        and record.get("expected_artifact_verified") is True
        and record.get("name") == archive.name
        and str(record.get("sha256", "")).lower() == digest
        and record.get("content_bytes_verified") is True
        and record.get("content_sha256_verified") is True
        and isinstance(record.get("checks"), dict)
        and bool(record["checks"])
        and all(value is True for value in record["checks"].values())
        for record in records
    ):
        raise BackupError("Drive upload did not prove the exact PriceBuddy archive; the local archive was retained")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    remote_requested = args.drive or args.verify_drive
    if not remote_requested and args.drive_transport is not None:
        parser.error("--drive-transport requires --drive or --verify-drive")
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    if args.dump_only and args.out is None:
        parser.error("--dump-only requires --out")
    if args.out is not None and not args.dump_only:
        parser.error("--out requires --dump-only")
    try:
        if args.dump_only:
            dump_mysql(args.database_container, args.out, args.timeout)
            return 0
        transport_path = args.drive_transport or DEFAULT_DRIVE_TRANSPORT
        transport_module = load_drive_transport(transport_path) if remote_requested else None
        if args.verify_drive:
            evidence = verify_drive_current(args, transport_module)
            print(json.dumps(evidence, sort_keys=True))
            return 0
        if args.verify_local:
            verify_local(pathlib.Path(args.verify_local).resolve())
            print(f"Verified local PriceBuddy backup: {args.verify_local}")
            return 0

        archive_path = create_backup(args)
        if args.drive:
            upload_drive_capture(archive_path, transport_module)
        print(f"Created and locally verified PriceBuddy backup: {archive_path}")
        print(f"Manifest: {archive_path.with_name(archive_path.stem.split('.tar')[0] + '.manifest.json')}")
        return 0
    except BackupError as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
