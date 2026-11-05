import crypto from 'node:crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { gzipSync } from 'node:zlib';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { backupDbNow, parseHuggingFaceTarget, restoreDbBackupIfNeeded } from '../../lib/db-backup.js';
import { initDb } from '../../db/index.js';
import { createUser, userCount } from '../../services/auth.js';
import { aclEntries } from '../helpers/acl.js';

const ORIGINAL_BACKUP_PATH = process.env.FREEAPI_DB_BACKUP_PATH;
const ORIGINAL_BACKUP_TARGET = process.env.FREEAPI_DB_BACKUP_TARGET;
const ORIGINAL_BACKUP_URL = process.env.FREEAPI_DB_BACKUP_URL;
const ORIGINAL_BACKUP_KEY = process.env.FREEAPI_DB_BACKUP_KEY;
const ORIGINAL_BACKUP_TOKEN = process.env.FREEAPI_DB_BACKUP_TOKEN;
const ORIGINAL_ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

function restoreEnv() {
  if (ORIGINAL_BACKUP_PATH === undefined) delete process.env.FREEAPI_DB_BACKUP_PATH;
  else process.env.FREEAPI_DB_BACKUP_PATH = ORIGINAL_BACKUP_PATH;
  if (ORIGINAL_BACKUP_TARGET === undefined) delete process.env.FREEAPI_DB_BACKUP_TARGET;
  else process.env.FREEAPI_DB_BACKUP_TARGET = ORIGINAL_BACKUP_TARGET;
  if (ORIGINAL_BACKUP_URL === undefined) delete process.env.FREEAPI_DB_BACKUP_URL;
  else process.env.FREEAPI_DB_BACKUP_URL = ORIGINAL_BACKUP_URL;
  if (ORIGINAL_BACKUP_KEY === undefined) delete process.env.FREEAPI_DB_BACKUP_KEY;
  else process.env.FREEAPI_DB_BACKUP_KEY = ORIGINAL_BACKUP_KEY;
  if (ORIGINAL_BACKUP_TOKEN === undefined) delete process.env.FREEAPI_DB_BACKUP_TOKEN;
  else process.env.FREEAPI_DB_BACKUP_TOKEN = ORIGINAL_BACKUP_TOKEN;
  if (ORIGINAL_ENCRYPTION_KEY === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = ORIGINAL_ENCRYPTION_KEY;
  if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = ORIGINAL_NODE_ENV;
}

describe('encrypted SQLite backup', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    restoreEnv();
  });

  it('backs up and restores a SQLite file from a configured path', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    delete process.env.FREEAPI_DB_BACKUP_URL;
    delete process.env.FREEAPI_DB_BACKUP_TARGET;
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items (name) VALUES (\'survived\')');
    const backup = await backupDbNow(db, dbPath);
    db.close();

    expect(backup.ok).toBe(true);
    expect(fs.existsSync(backupPath)).toBe(true);
    expect(fs.readFileSync(backupPath).includes(Buffer.from('survived'))).toBe(false);

    fs.rmSync(dbPath);
    const restore = await restoreDbBackupIfNeeded(dbPath);
    expect(restore.restored).toBe(true);

    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('survived');
    restored.close();
  });

  it('snapshots committed WAL data without checkpointing the live database', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-wal-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('wal_autocheckpoint = 0');
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    const reader = new Database(dbPath);
    reader.exec('BEGIN');
    reader.prepare('SELECT * FROM items').all();
    db.prepare('INSERT INTO items (name) VALUES (?)').run('wal-only');
    expect(fs.statSync(`${dbPath}-wal`).size).toBeGreaterThan(0);

    await backupDbNow(db, dbPath);
    reader.exec('ROLLBACK');
    reader.close();
    db.close();
    fs.rmSync(dbPath);

    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);
    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('wal-only');
    restored.close();
  });

  it('overwrites a previous backup on later runs', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-overwrite-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    db.prepare('INSERT INTO items VALUES (?)').run('first');
    await backupDbNow(db, dbPath);
    const first = fs.readFileSync(backupPath);
    db.prepare('INSERT INTO items VALUES (?)').run('second');
    await backupDbNow(db, dbPath);
    const second = fs.readFileSync(backupPath);
    db.close();
    expect(second.equals(first)).toBe(false);
  });

  it('rejects a corrupt encrypted payload without installing a database', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-corrupt-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    await backupDbNow(db, dbPath);
    db.close();
    const encrypted = fs.readFileSync(backupPath);
    encrypted[encrypted.length - 1] ^= 0xff;
    fs.writeFileSync(backupPath, encrypted);
    fs.rmSync(dbPath);

    await expect(restoreDbBackupIfNeeded(dbPath)).rejects.toThrow(/validate or decrypt/);
    expect(fs.existsSync(dbPath)).toBe(false);
    expect(fs.readdirSync(dir).some(name => name.endsWith('.restore'))).toBe(false);
  });

  it('rejects an encrypted payload that does not contain a valid SQLite database', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-invalid-sqlite-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    const key = Buffer.from('a'.repeat(64), 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(gzipSync(Buffer.from('not sqlite'))), cipher.final()]);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    fs.writeFileSync(backupPath, Buffer.concat([
      Buffer.from('FAPIBK1\0'), iv, cipher.getAuthTag(), encrypted,
    ]));

    await expect(restoreDbBackupIfNeeded(dbPath)).rejects.toThrow(/not a valid SQLite database/);
    expect(fs.existsSync(dbPath)).toBe(false);
  });

  it('does not replace an existing database or fetch a remote backup', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-existing-'));
    const dbPath = path.join(dir, 'freeapi.db');
    process.env.FREEAPI_DB_BACKUP_URL = 'https://backup.example.test/state';
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items VALUES (\'local\')');
    db.close();
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    expect((await restoreDbBackupIfNeeded(dbPath)).skipped).toBe('database already exists');
    expect(fetchMock).not.toHaveBeenCalled();
    const existing = new Database(dbPath);
    expect((existing.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('local');
    existing.close();
    vi.unstubAllGlobals();
  });

  it('refuses to initialize over an empty database or orphaned WAL sidecar', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-incomplete-local-'));
    const dbPath = path.join(dir, 'freeapi.db');
    process.env.FREEAPI_DB_BACKUP_URL = 'https://backup.example.test/state';
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    fs.writeFileSync(dbPath, '');

    await expect(restoreDbBackupIfNeeded(dbPath)).rejects.toThrow(/database file is empty/);
    fs.rmSync(dbPath);
    fs.writeFileSync(`${dbPath}-wal`, 'potentially recoverable');
    await expect(restoreDbBackupIfNeeded(dbPath)).rejects.toThrow(/sidecar files exist/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not replace a database created while the remote backup is being fetched', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-restore-race-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    const source = new Database(backupPath.replace('backup.bin', 'source.db'));
    source.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items VALUES (\'remote\')');
    await backupDbNow(source, source.name);
    source.close();
    const payload = fs.readFileSync(backupPath);
    fs.rmSync(backupPath);

    vi.stubGlobal('fetch', vi.fn(async () => {
      const local = new Database(dbPath);
      local.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items VALUES (\'local\')');
      local.close();
      return new Response(payload, { status: 200 });
    }));
    process.env.FREEAPI_DB_BACKUP_URL = 'https://backup.example.test/state';
    delete process.env.FREEAPI_DB_BACKUP_PATH;

    expect((await restoreDbBackupIfNeeded(dbPath)).skipped).toBe('database created during restore');
    const existing = new Database(dbPath);
    expect((existing.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('local');
    existing.close();
  });

  it('prevents overlapping uploads for one database connection', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-overlap-'));
    const dbPath = path.join(dir, 'freeapi.db');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_URL = 'https://backup.example.test/state';
    let release!: (response: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>(resolve => { release = resolve; }));
    vi.stubGlobal('fetch', fetchMock);
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');

    const first = backupDbNow(db, dbPath);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    const second = await backupDbNow(db, dbPath);
    expect(second.skipped).toBe('backup already in progress');
    release(new Response(null, { status: 204 }));
    await first;
    expect(fetchMock).toHaveBeenCalledOnce();
    db.close();
    vi.unstubAllGlobals();
  });

  it('retries an interrupted upload and succeeds on the next attempt', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-retry-'));
    const dbPath = path.join(dir, 'freeapi.db');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_URL = 'https://backup.example.test/state';
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');

    expect((await backupDbNow(db, dbPath)).ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    db.close();
    vi.unstubAllGlobals();
  });

  it('fails clearly when the remote service is unavailable', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-unavailable-'));
    const dbPath = path.join(dir, 'freeapi.db');
    process.env.FREEAPI_DB_BACKUP_URL = 'https://user:secret@backup.example.test/state?token=private';
    const fetchMock = vi.fn().mockRejectedValue(new Error('fetch failed'));
    vi.stubGlobal('fetch', fetchMock);
    const errorLog = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    await expect(restoreDbBackupIfNeeded(dbPath)).rejects.toThrow(/could not retrieve remote database backup/);
    expect(fs.existsSync(dbPath)).toBe(false);
    expect(errorLog.mock.calls.flat().join(' ')).not.toMatch(/secret|private/);
    errorLog.mockRestore();
    vi.unstubAllGlobals();
  });

  it('reports a missing remote backup without creating a database', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-missing-'));
    const dbPath = path.join(dir, 'freeapi.db');
    process.env.FREEAPI_DB_BACKUP_URL = 'https://backup.example.test/state';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 404 })));

    expect((await restoreDbBackupIfNeeded(dbPath)).skipped).toBe('no backup found');
    expect(fs.existsSync(dbPath)).toBe(false);
    vi.unstubAllGlobals();
  });

  it('rejects backups encrypted with a different key', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-key-'));
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    await backupDbNow(db, dbPath);
    db.close();
    process.env.ENCRYPTION_KEY = 'b'.repeat(64);
    fs.rmSync(dbPath);

    await expect(restoreDbBackupIfNeeded(dbPath)).rejects.toThrow(/validate or decrypt/);
    expect(fs.existsSync(dbPath)).toBe(false);
  });

  it('restores profiles and seeded models before running fresh initialization', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-db-backup-startup-order-'));
    const sourcePath = path.join(dir, 'source.db');
    const targetPath = path.join(dir, 'restored.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;
    process.env.NODE_ENV = 'test';

    const source = initDb(sourcePath);
    createUser('persisted@example.test', 'backup-test-password');
    const sourceCounts = {
      profiles: (source.prepare('SELECT COUNT(*) AS count FROM profiles').get() as { count: number }).count,
      models: (source.prepare('SELECT COUNT(*) AS count FROM models').get() as { count: number }).count,
    };
    expect(sourceCounts.profiles).toBeGreaterThan(0);
    expect(sourceCounts.models).toBeGreaterThan(0);
    await backupDbNow(source, sourcePath);
    source.close?.();

    expect((await restoreDbBackupIfNeeded(targetPath)).restored).toBe(true);
    const restored = initDb(targetPath);
    expect(userCount()).toBe(1);
    expect((restored.prepare('SELECT COUNT(*) AS count FROM profiles').get() as { count: number }).count)
      .toBe(sourceCounts.profiles);
    expect((restored.prepare('SELECT COUNT(*) AS count FROM models').get() as { count: number }).count)
      .toBe(sourceCounts.models);
    restored.close?.();
  });
});

describe('backup file permissions', () => {
  // The blob is AES-256-GCM encrypted and the restored file is a plain SQLite
  // database, but both live on a host that also holds the key — usually in a
  // .env in the same tree — so neither may be left world-readable.
  //
  // As elsewhere, each platform asserts what it can actually enforce: Node
  // synthesizes a 0o666 mode on Windows regardless of the ACL, so a POSIX-mode
  // assertion there would pass or fail for reasons unrelated to the guarantee.
  const isWindows = process.platform === 'win32';
  const itPosix = it.skipIf(isWindows);
  const itWindows = it.skipIf(!isWindows);

  afterEach(() => restoreEnv());

  async function backupInto(dir: string): Promise<string> {
    const dbPath = path.join(dir, 'freeapi.db');
    const backupPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = backupPath;

    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL)');
    await backupDbNow(db, dbPath);
    db.close();
    return backupPath;
  }

  itPosix('writes the backup blob owner-only', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const backupPath = await backupInto(dir);

    expect(fs.statSync(backupPath).mode & 0o077).toBe(0);
  });

  itPosix('tightens a backup target that already existed', async () => {
    // writeFileSync's mode argument only applies when the file is created, so
    // every backup after the first overwrites a file that keeps whatever mode
    // it already had. Without the explicit restrict call this is the case that
    // stays group-readable forever.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const backupPath = path.join(dir, 'backup.bin');
    fs.writeFileSync(backupPath, 'stale');
    // chmod rather than a creation mode: the mode argument is filtered through
    // the runner's umask, so a strict umask would leave this pre-condition
    // asserting the very thing it means to rule out.
    fs.chmodSync(backupPath, 0o644);
    expect(fs.statSync(backupPath).mode & 0o077).not.toBe(0);

    await backupInto(dir);

    expect(fs.statSync(backupPath).mode & 0o077).toBe(0);
  });

  itPosix('writes the restored database owner-only', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const dbPath = path.join(dir, 'freeapi.db');
    await backupInto(dir);
    fs.rmSync(dbPath);

    // The restore lands before connectDb runs, and sometimes in a different
    // process entirely; the decrypted database must not be readable in between.
    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);
    expect(fs.statSync(dbPath).mode & 0o077).toBe(0);
  });

  itWindows('replaces the inherited ACL on the backup blob', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-backup-perms-'));
    const backupPath = await backupInto(dir);

    const entries = aclEntries(backupPath);
    expect(entries.filter(e => e.includes('(I)'))).toEqual([]);
    expect(entries).toHaveLength(3);
  });
});

describe('parseHuggingFaceTarget', () => {
  it('maps a dataset download URL onto the commit API', () => {
    expect(parseHuggingFaceTarget('https://huggingface.co/datasets/acme/state/resolve/main/backups/freeapi.db.enc')).toEqual({
      commitUrl: 'https://huggingface.co/api/datasets/acme/state/commit/main',
      filePath: 'backups/freeapi.db.enc',
    });
  });

  it('treats the prefix-less repo path as a model repo', () => {
    expect(parseHuggingFaceTarget('https://huggingface.co/acme/state/resolve/main/freeapi.db.enc')).toEqual({
      commitUrl: 'https://huggingface.co/api/models/acme/state/commit/main',
      filePath: 'freeapi.db.enc',
    });
  });

  it('maps a space download URL', () => {
    expect(parseHuggingFaceTarget('https://huggingface.co/spaces/acme/app/resolve/main/data/freeapi.db.enc')?.commitUrl)
      .toBe('https://huggingface.co/api/spaces/acme/app/commit/main');
  });

  it('leaves every other target alone', () => {
    expect(parseHuggingFaceTarget('https://example.com/acme/state/resolve/main/freeapi.db.enc')).toBeNull();
    // A HF URL that is not a /resolve/ download has no commit route to derive.
    expect(parseHuggingFaceTarget('https://huggingface.co/acme/state')).toBeNull();
    expect(parseHuggingFaceTarget('/var/backups/freeapi.db.enc')).toBeNull();
  });
});

describe('Hugging Face backup target', () => {
  // The /resolve/ URL a HF repo serves downloads from is read-only: the PUT this
  // used to send was answered 404 and the blob never landed, so an ephemeral
  // host restored nothing on its next cold start. Uploads go through the commit
  // API, and the blob travels as base64 text because repos on Xet storage reject
  // binary pushed through that route.
  const TARGET = 'https://huggingface.co/datasets/acme/state/resolve/main/backups/freeapi.db.enc';

  afterEach(() => {
    vi.unstubAllGlobals();
    restoreEnv();
  });

  function seedDb(dir: string): string {
    const dbPath = path.join(dir, 'freeapi.db');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE items (name TEXT NOT NULL); INSERT INTO items (name) VALUES (\'survived\')');
    db.close();
    return dbPath;
  }

  it('uploads through the commit API as base64 and restores it', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-backup-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    process.env.FREEAPI_DB_BACKUP_TOKEN = 'hf_token';

    let stored = '';
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      if (init.method === 'POST') {
        stored = String(init.body);
        return new Response('{}', { status: 200 });
      }
      return new Response(stored, { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);

    const db = new Database(dbPath);
    expect((await backupDbNow(db, dbPath)).ok).toBe(true);
    db.close();

    const [uploadUrl, uploadInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(uploadUrl).toBe('https://huggingface.co/api/datasets/acme/state/commit/main');
    expect(uploadInit.method).toBe('POST');
    expect((uploadInit.headers as Record<string, string>)['Content-Type']).toBe('application/x-ndjson');
    expect((uploadInit.headers as Record<string, string>).Authorization).toBe('Bearer hf_token');

    const [header, file] = String(uploadInit.body).split('\n').map(line => JSON.parse(line));
    expect(header).toEqual({ key: 'header', value: { summary: 'chore: update backups/freeapi.db.enc' } });
    expect(file.key).toBe('file');
    expect(file.value.path).toBe('backups/freeapi.db.enc');
    // Base64 text, not bytes — 'base64' here would make HF write the binary back.
    expect(file.value.encoding).toBe('utf-8');
    expect(file.value.content).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(file.value.content).not.toContain('survived');

    // What HF serves back from /resolve/ is that base64 text; the restore has to
    // decode it before it is a database again.
    stored = file.value.content;
    fs.rmSync(dbPath);
    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);

    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('survived');
    restored.close();
  });

  it('still restores a blob that was stored raw', async () => {
    // Anything a previous build managed to land is raw ciphertext. Sniffing the
    // magic header keeps that path recoverable instead of base64-decoding it
    // into garbage.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-legacy-'));
    const dbPath = seedDb(dir);
    const blobPath = path.join(dir, 'backup.bin');
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_PATH = blobPath;

    const db = new Database(dbPath);
    await backupDbNow(db, dbPath);
    db.close();
    const raw = fs.readFileSync(blobPath);

    delete process.env.FREEAPI_DB_BACKUP_PATH;
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(raw, { status: 200 })));

    fs.rmSync(dbPath);
    expect((await restoreDbBackupIfNeeded(dbPath)).restored).toBe(true);
    const restored = new Database(dbPath);
    expect((restored.prepare('SELECT name FROM items').get() as { name: string }).name).toBe('survived');
    restored.close();
  });

  it('refuses to upload without a token rather than 401ing on a schedule', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-token-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    delete process.env.FREEAPI_DB_BACKUP_TOKEN;

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const db = new Database(dbPath);
    await expect(backupDbNow(db, dbPath)).rejects.toThrow(/FREEAPI_DB_BACKUP_TOKEN is required/);
    db.close();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('surfaces a rejected commit', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-hf-error-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = TARGET;
    process.env.FREEAPI_DB_BACKUP_TOKEN = 'hf_token';
    vi.stubGlobal('fetch', vi.fn(async () => new Response('repo not found', { status: 404 })));

    const db = new Database(dbPath);
    await expect(backupDbNow(db, dbPath)).rejects.toThrow(/HF commit HTTP 404 — repo not found/);
    db.close();
  });

  it('leaves a plain HTTP target on the PUT path', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'freeapi-http-backup-'));
    const dbPath = seedDb(dir);
    process.env.ENCRYPTION_KEY = 'a'.repeat(64);
    process.env.FREEAPI_DB_BACKUP_TARGET = 'https://storage.example.com/freeapi.db.enc';
    process.env.FREEAPI_DB_BACKUP_TOKEN = 'plain_token';

    const fetchMock = vi.fn(async () => new Response('', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const db = new Database(dbPath);
    expect((await backupDbNow(db, dbPath)).ok).toBe(true);
    db.close();

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://storage.example.com/freeapi.db.enc');
    expect(init.method).toBe('PUT');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/octet-stream');
    expect(Buffer.isBuffer(init.body)).toBe(true);
  });
});
