# PriceBuddy Backup And Restore

These files describe the host-side PriceBuddy backup and restore flow. The
scheduled service captures to the HDD archive directory, verifies the archive
locally, then uploads it to the isolated `pricebuddy_hdd_drive` scope in the
`PriceBuddy Backups - HDD and Drive` folder. The existing transport retains
three Drive objects; the local helper retains three complete archive sets.
Neither archive nor manifest contains raw `docker-compose.yml` or plaintext
`.env` values.

## Create A Backup

Run from the repository root for a local-only capture:

```sh
python3.11 backup/pricebuddy_backup.py
```

The default command is local-only and does not import or call the Drive
transport. The systemd service explicitly adds `--drive`. A manually requested
dual-destination capture can use the same flag:

```sh
python3.11 backup/pricebuddy_backup.py --drive
```

`--drive` completes local capture, local verification, and local retention
before it contacts Drive. A failed Drive upload or proof returns a nonzero exit
while leaving the verified archive and sidecars on HDD. A v4 manifest records
the expected Drive provider, scope, and folder, with
`remote_upload_verified=false`; it declares the intended transport and is not
evidence that upload succeeded.

The default source is the local Docker database container
`pricebuddy-database-1` and the named Docker storage volume
`pricebuddy_storage`. Override them only for an equivalent local PriceBuddy
deployment:

```sh
python3.11 backup/pricebuddy_backup.py \
  --database-container pricebuddy-database-1 \
  --storage-volume pricebuddy_storage \
  --output-dir backup/archives
```

The script reads MySQL credentials only from the database container
environment. It does not print or hardcode those credentials. The scheduled
service captures the storage volume using this immutable helper image:
`alpine/git@sha256:a299a963fbe31628ab481ca42907bcf0691d004f86734c02638abdf513691d42`.
The script verifies that exact image is present before starting the helper and
overrides its `git` entrypoint with `/bin/tar`. Docker runs with `--pull=never`
and `--network=none`, so backup data stays local and the helper cannot reach a
network. If Docker has pruned the image, the script validates the SHA-256 of the
local recovery archive at `/home/mflova/.local/share/pricebuddy-backup/alpine-git-a299a963fbe31628ab481ca42907bcf0691d004f86734c02638abdf513691d42.tar`
and reloads it offline. If the archive is missing or corrupt, the service fails
before capture with an explicit preflight error.

Use `--create-only` when you want to create the archive and sidecars without
the immediate local verification pass:

```sh
python3.11 backup/pricebuddy_backup.py --create-only
```

A normal verified run keeps the newest three matching local archive sets
(archive, checksum, manifest, and manifest checksum). `--create-only` and
`--verify-local` do not prune existing history; unmatched recovery files remain
untouched.

## Verify A Local Archive And Its Current Drive Copy

The optional remote check first validates the newest matching local archive,
computes its digest, and proves the exact same name and SHA-256 in Drive. It
fails if that current local capture has not arrived remotely, even when older
Drive objects are healthy. It does not capture, upload, or prune:

```sh
python3.11 backup/pricebuddy_backup.py --verify-drive
```

Local archive verification remains available offline and does not need OAuth:

```sh
python3.11 backup/pricebuddy_backup.py --verify-local backup/archives/ARCHIVE.tar
python3.11 backup/pricebuddy_backup.py --verify-local backup/archives/ARCHIVE.tar.zst
```

Verification checks the archive SHA-256 sidecar, validates the sanitized JSON
manifest, checks that the archive contains the manifest-listed files, and
requires the restore secret marker. Historical v2 Drive manifests, v3
local-only manifests, and v4 Drive-capable manifests remain locally verifiable
without OAuth or network access. The new Drive scope is separate from the
historic `pricebuddy` scope and `PriceBuddy Backups` folder; this workflow does
not adopt or prune that legacy folder.

## Files Produced

Each backup contains:

- `mysql.sql`: consistent logical MySQL dump made with `mysqldump
  --single-transaction`.
- `storage.tar`: tar capture of the named app storage Docker volume.
- `manifest.json`: sanitized backup manifest.
- `compose.provenance.yml`: generated redacted compose provenance with source
  path and raw compose SHA-256 in comments.
- `RESTORE_SECRETS_REQUIRED.txt`: marker that restore secrets are required
  separately.
- `*.sha256`: SHA-256 sidecars for contained artifacts.

The output directory also receives the archive, an archive SHA-256 sidecar, a
copy of the sanitized manifest, and a manifest SHA-256 sidecar.

The manifest and provenance artifact must not contain passwords, tokens, SQL
rows, API keys, notification secrets, app keys, plaintext `.env` values, or raw
compose contents. Compose provenance keeps source path/hash metadata and a
redacted compose view for restore review.

## Restore Secrets Required Separately

A usable restore needs a reviewed PriceBuddy runtime configuration supplied
outside the backup. At minimum, prepare:

- Laravel `APP_KEY`.
- Database name, user, and password for the scratch MySQL container.
- Any mail, notification, AI provider, SearXNG, scraper, or proxy credentials.
- Any deployment-specific app URL, trusted proxy, or integration settings.

Do not recover these from `manifest.json`; they are intentionally absent.

## Scratch MySQL Verification

This is a local verification flow, not a production restore procedure.

1. Extract the archive into a scratch directory:

   ```sh
   mkdir -p /tmp/pricebuddy-restore
   tar -xf backup/archives/ARCHIVE.tar -C /tmp/pricebuddy-restore
   # For .tar.zst:
   zstd -dc backup/archives/ARCHIVE.tar.zst | tar -xf - -C /tmp/pricebuddy-restore
   ```

2. Start an isolated local MySQL container with new scratch credentials:

   ```sh
   docker run --rm --name pricebuddy-restore-mysql \
     -e MYSQL_DATABASE=pricebuddy_restore \
     -e MYSQL_USER=pricebuddy_restore \
     -e MYSQL_PASSWORD='replace-with-scratch-password' \
     -e MYSQL_ROOT_PASSWORD='replace-with-scratch-root-password' \
     -p 3307:3306 \
     mysql:8.2
   ```

3. Import the dump from another terminal:

   ```sh
   docker exec -i pricebuddy-restore-mysql sh -lc \
     'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
     < /tmp/pricebuddy-restore/mysql.sql
   ```

4. Run basic database checks:

   ```sh
   docker exec pricebuddy-restore-mysql sh -lc \
     'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SHOW TABLES;"'
   ```

## Scratch App Verification

1. Create a scratch storage volume and load `storage.tar`:

   ```sh
   docker volume create pricebuddy_restore_storage
   docker run --rm --pull=never --network=none \
     -v pricebuddy_restore_storage:/target \
     -v /tmp/pricebuddy-restore:/backup \
     busybox:1.36 sh -lc 'tar -C /target -xf /backup/storage.tar'
   ```

2. Prepare a scratch `.env` from your separate secret source. Point it at the
   scratch MySQL container and restored storage volume. Do not use production
   notification credentials until you intentionally test those channels.

3. Start a scratch PriceBuddy app container or compose project using the
   restored database and storage volume.

4. Verify the app without causing production side effects:

   ```sh
   php artisan migrate:status
   php artisan tinker --execute='echo \App\Models\Product::query()->count();'
   ```

5. Inspect representative products, price histories, images, and settings in
   the scratch app UI before considering any production restore.
