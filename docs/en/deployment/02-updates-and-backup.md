**English** · [简体中文](../../zh-cn/deployment/02-updates-and-backup.md)

# Updates and backup

Keeping a Docker deployment current, protecting the SQLite data volume, and making installs reproducible with declarative configuration.

- [Upgrading the container](#upgrading-the-container)
- [Dashboard update checker (#635 / #703)](#dashboard-update-checker-635--703)
- [Backing up the SQLite data volume](#backing-up-the-sqlite-data-volume)
- [Declarative config & catalog controls (#f4cd7b4)](#declarative-config--catalog-controls-f4cd7b4)

## Upgrading the container

Track `:latest` (or pin a release tag) and re-create the container on a new image:

```bash
docker compose pull && docker compose up -d
```

Two invariants across any upgrade:

1. **Keep the same `.env` `ENCRYPTION_KEY`.** Provider keys are encrypted at rest; a changed key makes every stored key undecryptable. See [02-security-and-keys.md](../env/02-security-and-keys.md).
2. **Keep the same data volume** (`freellmapi-data` at `/app/server/data`). Migrations run idempotently on boot.

The desktop dashboard's update dialog shows this exact command for Docker installs (see below).

## Dashboard update checker (#635 / #703)

Settings carries a single update surface: it reports the running release, lists recent commits, and — when the installation is Docker — prints the `docker compose pull && docker compose up -d` upgrade command. Relevant controls:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FREELLMAPI_UPDATE_CHECK` | Enabled | Set to `off` to hide the checker from Settings and prevent Git discovery or outbound update-check requests. This also switches off the automatic release reminder, a separate dashboard setting (Settings > General) that is off until turned on there. |
| `FREELLMAPI_UPDATE_GITHUB_TOKEN` | Empty (anonymous checks) | Optional token used only for update checks against GitHub. Use a narrowly scoped token only if higher rate limits are needed; generic `GITHUB_TOKEN` values are intentionally ignored. |

Two build-level facts back the version display: `FREELLMAPI_INSTALL_METHOD=docker` tells the server which upgrade path to suggest, and the runtime image copies `desktop/package.json` — where the release version lives, since `server/package.json` tracks the workspace — as a ~400-byte manifest so a container install can name its own version (#703).

## Backing up the SQLite data volume

Everything that matters lives in one place: the named volume `freellmapi-data` mounted at `/app/server/data`, containing the SQLite database (`freeapi.db`, or wherever `FREEAPI_DB_PATH` points), its `-wal`/`-shm` sidecars, and the `.encryption-key` file for dev-style installs. Back up all of it together, and keep the matching `ENCRYPTION_KEY` safe — without it, backed-up provider keys are undecryptable ciphertext.

Built-in encrypted backups (recommended, zero downtime). FreeLLMAPI can push an encrypted backup of the live database on a schedule:

```env
FREEAPI_DB_PATH=/app/server/data/freeapi.db
FREEAPI_DB_BACKUP_URL=https://<project-ref>.supabase.co/functions/v1/db-backup
FREEAPI_DB_BACKUP_TOKEN=<long-random-shared-token>
# Optional. If omitted, the backup uses ENCRYPTION_KEY.
FREEAPI_DB_BACKUP_KEY=<64-hex-character-key>
FREEAPI_DB_BACKUP_INTERVAL_MS=300000
```

### Supabase Storage backup bridge

The application protocol is authenticated `GET` to download and `PUT` with an `application/octet-stream` body to upload. Supabase Storage does not implement that contract directly, so use the included Edge Function as the bridge. The function stores the current backup at a stable path in a **private** bucket and keeps the prior encrypted object at the same path with `.previous` appended. It only upserts after receiving the complete request and validating the encrypted-envelope format. The Edge Function enforces a 50 MiB upload limit; keep the compressed encrypted backup below that limit.

1. In Supabase **Storage**, create a bucket named `freeapi-db-backups` and leave **Public bucket** disabled. Set its file size limit to 50 MiB. No public read or write policies are needed; the function accesses Storage with its server-side service-role key.
2. From the repository root, install/login to the Supabase CLI and link the project:

   ```sh
   supabase login
   supabase link --project-ref <project-ref>
   ```

3. Set function secrets. Generate `FREEAPI_DB_BACKUP_TOKEN` as a long random secret, then use the exact same value in Render. Do not put the service-role key or shared token in source control or client-side variables.

   ```sh
   supabase secrets set \
     SUPABASE_URL=https://<project-ref>.supabase.co \
     SUPABASE_SERVICE_ROLE_KEY=<service-role-key> \
     FREEAPI_DB_BACKUP_TOKEN=<long-random-shared-token>
   ```

   `SUPABASE_BACKUP_BUCKET` and `SUPABASE_BACKUP_OBJECT` are optional; they default to `freeapi-db-backups` and `freellmapi.db.backup`.
4. Deploy the function with Supabase JWT verification disabled. The function implements its own Bearer-token authentication; leaving gateway JWT verification enabled would reject the application's shared token before the function runs.

   ```sh
   supabase functions deploy db-backup --no-verify-jwt
   ```

5. In the Render service's environment, set:

   | Variable | Value / format |
   | --- | --- |
   | `FREEAPI_DB_PATH` | `/app/server/data/freeapi.db` |
   | `FREEAPI_DB_BACKUP_URL` | `https://<project-ref>.supabase.co/functions/v1/db-backup` |
   | `FREEAPI_DB_BACKUP_TOKEN` | The same long random value set as the Edge Function secret |
   | `ENCRYPTION_KEY` | Keep the exact existing 64-character hexadecimal key; do not rotate it for backup setup |
   | `FREEAPI_DB_BACKUP_KEY` | Optional, exactly 64 hexadecimal characters. Omit to use `ENCRYPTION_KEY`; if configured, retain it separately and permanently |
   | `FREEAPI_DB_BACKUP_INTERVAL_MS` | `300000` (five minutes) |

`FREEAPI_DB_BACKUP_KEY` protects the backup envelope using AES-256-GCM and does not replace or change `ENCRYPTION_KEY`. Losing the selected backup key means the encrypted backup cannot be restored. Keep the existing `ENCRYPTION_KEY` too: database rows containing provider credentials remain encrypted with it.

On every boot, FreeLLMAPI checks for the local database first. Only if the file is absent does it fetch the remote backup, decrypt and decompress it, run SQLite's integrity check, and atomically install it before migrations or model/profile seeding. An existing database is never overwritten by a remote backup. A missing remote object is logged and treated as a first boot; connection or validation errors are logged and stop startup rather than silently initializing an empty database. While running, the initial and recurring uploads use SQLite's consistent backup mechanism so committed WAL data is included. Transient upload errors receive bounded retries.

### Recovery and Render redeployment verification

1. Before recovery, confirm the Render values of `ENCRYPTION_KEY`, `FREEAPI_DB_BACKUP_KEY` (if set), the backup URL, and the shared token still match those used to create the backup. Do not rotate either encryption key.
2. To test restoration, first wait for an upload and confirm the Render logs show `[db-backup] uploaded`. Verify that the private bucket contains `freellmapi.db.backup` in Supabase Storage.
3. Trigger a Render redeploy or start a fresh instance with its ephemeral local data directory empty. Do **not** delete a database containing data you still need; this test deliberately relies on an empty instance.
4. Confirm Render logs show `[db-backup] restored ...` before `Database initialized ...`. The server should then complete initialization and become healthy.
5. Sign in with the existing dashboard account and verify provider credentials, API keys, and settings. Check the Supabase object's updated timestamp after the next five-minute backup run.

If the database exists locally, the restore is intentionally skipped. For a manual recovery test, use a fresh Render instance/database path rather than deleting the only local copy. If the remote backup is missing, the log says so and the instance proceeds as a first boot; if retrieval, decryption, or SQLite validation fails, startup fails without installing the invalid payload. An empty local DB file or orphaned WAL/SHM sidecars also stop startup rather than being mistaken for a fresh database.

To recover the previous upload, temporarily set Render's `FREEAPI_DB_BACKUP_URL` to the same Edge Function URL with `?version=previous` appended, then deploy a fresh instance with no local database. The authenticated GET restores the prior object; the startup upload writes the recovered database back to the current object. After confirming recovery, remove `?version=previous` so normal backups resume. Only one previous object is retained, so it protects against a bad latest upload but is not a long-term archive.

Volume snapshot (plain Docker approach). The standard pattern works unchanged:

```bash
docker run --rm -v freellmapi-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/freellmapi-data.tar.gz -C /data .
```

Because the server keeps the database open (WAL mode), prefer doing this while the container is stopped (`docker compose stop`) so you capture a quiescent copy, then `docker compose start`.

## Declarative config & catalog controls (#f4cd7b4)

For repeatable Docker/server installs, FreeLLMAPI can apply a JSON config on every boot. Set `FREEAPI_CONFIG_PATH=/path/to/freellmapi.config.json`, or put the same JSON inline in `FREEAPI_CONFIG_JSON`. The application is idempotent: existing keys, custom providers, model edits, fallback rows, and routing settings are updated instead of duplicated, after migrations, on every boot.

```json
{
  "keys": [
    { "platform": "groq", "key": "gsk_...", "label": "main" },
    { "platform": "google", "key": "AIza...", "enabled": true }
  ],
  "customProviders": [
    {
      "baseUrl": "http://host.docker.internal:11434/v1",
      "label": "Ollama",
      "models": [
        { "model": "llama3.1:8b", "displayName": "Local Llama", "supportsTools": true }
      ]
    }
  ],
  "models": [
    {
      "platform": "groq",
      "modelId": "llama-3.3-70b-versatile",
      "displayName": "Llama 3.3 70B",
      "supportsTools": true,
      "fallbackEnabled": true
    }
  ],
  "routing": { "strategy": "balanced" }
}
```

If two custom endpoints serve the same model id, add `"endpoint"` to a `models` or `fallback` entry to say which one you mean — the endpoint's URL, or the short handle the dashboard shows next to it. Without it, an entry that matches more than one endpoint is rejected rather than applied to an arbitrary one:

```json
{
  "models": [
    { "platform": "custom", "modelId": "deepseek-v3.1", "endpoint": "https://relay-b.example.com/v1", "enabled": false }
  ]
}
```

Catalog side: an install keeps its model roster current from the signed catalog feed (the full catalog is listed at freellmapi.co/models), so no manual roster maintenance is required alongside upgrades.
