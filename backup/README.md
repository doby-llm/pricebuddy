# PriceBuddy HDD and Google Drive backups

The scheduled user-systemd service writes verified archives and sidecars to
`/home/mflova/git/pricebuddy/backup/archives`, then uploads that same archive
through the existing host `backup-ops/drive_backup_transport.py` transport. It
uses the isolated Drive scope `pricebuddy_hdd_drive` and folder
`PriceBuddy Backups - HDD and Drive`. Its Drive retention is three objects;
local retention also keeps the newest three complete archive sets.

The normal command-line mode remains local-only. It does not load the optional
Drive transport, make a network request, or remove remote data. `--create-only`
and `--verify-local` are also local-only and never prune. Use `--drive` only
when a manually started capture should be locally verified and then uploaded.
The archive's v4 manifest declares the intended Drive scope and folder; that
declaration does not prove that an upload completed. The command reports
success only after the transport verifies the exact uploaded filename and
SHA-256. A Drive error exits nonzero and leaves the locally verified archive
and its sidecars in place.

## Schedule and capture contract

`pricebuddy-backup.timer` runs Monday, Wednesday, and Friday at 00:10 in
`Europe/Zurich`, with `Persistent=true`. The service keeps its 45-minute hard
limit and requests a separate, bounded 180-second Drive transport timeout.
The mount preflight checks only the local HDD mount and has no Drive check.

The backup helper image is immutable and preloaded:

```text
alpine/git@sha256:a299a963fbe31628ab481ca42907bcf0691d004f86734c02638abdf513691d42
```

Before capturing the storage volume, the script checks that this pinned image
exists locally. If Docker has pruned it, the script verifies the SHA-256 of the
local recovery image archive and restores the image with `docker image load`;
this recovery is offline. The capture container uses `--pull=never` and
`--network=none`. The database dump, storage archive, manifest, and sidecars
are created and locally verified before Drive upload starts.

## Operate and verify

```sh
systemctl --user status pricebuddy-backup.timer pricebuddy-backup.service --no-pager -l
systemctl --user list-timers pricebuddy-backup.timer
systemctl --user start pricebuddy-backup.service
journalctl --user -u pricebuddy-backup.service --since today
```

Verify the newest matching local archive against its exact remote name and
SHA-256:

```sh
/usr/bin/python3 /home/mflova/git/pricebuddy/backup/pricebuddy_backup.py --verify-drive
```

This first validates the newest local archive, then asks the shared transport
to verify that exact Drive object. It fails when the newest local archive is
missing remotely, even if older remote backups are healthy. It does not capture,
upload, or prune. Local archive verification remains available without OAuth or
network access:

```sh
/usr/bin/python3 /home/mflova/git/pricebuddy/backup/pricebuddy_backup.py \
  --verify-local /home/mflova/git/pricebuddy/backup/archives/ARCHIVE.tar.zst
```

The local verifier accepts historical v2, local-only v3, and Drive-capable v4
manifests. The isolated legacy scope `pricebuddy` and folder
`PriceBuddy Backups` are preserved; this workflow neither adopts nor prunes
their objects.

Restore-time secrets remain separate from backup archives. See `RESTORE.md` for
the scratch restore procedure and required secret inputs.
