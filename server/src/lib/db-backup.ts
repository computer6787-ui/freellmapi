import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { gzipSync, gunzipSync } from 'zlib';
import type { Db, DbFactory } from '../db/types.js';
import type { Scheduler } from './scheduler.js';
import { defaultDbFactory, getDefaultDbPath } from '../db/index.js';
import { restrictToOwner } from './file-permissions.js';

const MAGIC = Buffer.from('FAPIBK1\0');
const DEFAULT_INTERVAL_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 30 * 1000;
const PLACEHOLDER_KEY = 'replace-with-64-char-hex';
const MAX_UPLOAD_ATTEMPTS = 3;
const backupInProgress = new Set<string>();

export interface DbBackupResult {
  ok: boolean;
  target?: string;
  bytes?: number;
  restored?: boolean;
  skipped?: string;
}

function backupTarget(): string | null {
  const raw = process.env.FREEAPI_DB_BACKUP_TARGET
    ?? process.env.FREEAPI_DB_BACKUP_URL
    ?? process.env.FREEAPI_DB_BACKUP_PATH
    ?? '';
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function isDbBackupConfigured(): boolean {
  return backupTarget() !== null;
}

function backupIntervalMs(): number {
  const raw = process.env.FREEAPI_DB_BACKUP_INTERVAL_MS;
  if (!raw) return DEFAULT_INTERVAL_MS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_INTERVAL_MS;
}

function isHttpTarget(target: string): boolean {
  return target.startsWith('https://') || target.startsWith('http://');
}

function safeTarget(target: string): string {
  if (!/^https?:\/\//i.test(target)) return target;
  try {
    const url = new URL(target);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return target;
  }
}

function safeError(err: unknown): string {
  let message = err instanceof Error ? err.message : String(err);
  const token = process.env.FREEAPI_DB_BACKUP_TOKEN?.trim();
  if (token) message = message.split(token).join('[redacted]');
  return message.replace(/https?:\/\/[^\s"'<>]+/gi, value => safeTarget(value));
}

function parseBackupKey(): Buffer {
  const raw = (process.env.FREEAPI_DB_BACKUP_KEY || process.env.ENCRYPTION_KEY || '').trim();
  if (!raw || raw === PLACEHOLDER_KEY || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error('FREEAPI_DB_BACKUP_KEY or ENCRYPTION_KEY must be a 64-character hex key when DB backup is enabled');
  }
  return Buffer.from(raw, 'hex');
}

function encryptBackup(plain: Buffer): Buffer {
  const key = parseBackupKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, iv, tag, ciphertext]);
}

function decryptBackup(payload: Buffer): Buffer {
  if (payload.length < MAGIC.length + 12 + 16 || !payload.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('backup payload has an unsupported format');
  }
  const key = parseBackupKey();
  const ivStart = MAGIC.length;
  const tagStart = ivStart + 12;
  const bodyStart = tagStart + 16;
  const iv = payload.subarray(ivStart, tagStart);
  const tag = payload.subarray(tagStart, bodyStart);
  const ciphertext = payload.subarray(bodyStart);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Split a Hugging Face `/resolve/` download URL into the pieces the commit API
 * needs, or null for anything else.
 *
 * A HF repo serves downloads at `/{type}/{ns}/{repo}/resolve/{rev}/{path}`, but
 * that route is read-only: a PUT to it is answered 404/405 and the blob never
 * lands. Writes go through the commit API instead. Both halves are derived from
 * the one URL the operator configures, so FREEAPI_DB_BACKUP_TARGET stays the
 * plain download URL they can paste into a browser.
 *
 * Models are the type with no prefix segment (`/{ns}/{repo}/resolve/...`);
 * datasets and spaces name themselves. The API path pluralizes the type.
 */
export function parseHuggingFaceTarget(target: string): { commitUrl: string; filePath: string } | null {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return null;
  }
  if (url.hostname !== 'huggingface.co') return null;

  const segments = url.pathname.split('/').filter(Boolean);
  const prefixed = segments[0] === 'datasets' || segments[0] === 'spaces';
  const type = prefixed ? segments[0] : 'models';
  const rest = prefixed ? segments.slice(1) : segments;
  // ns / repo / 'resolve' / rev / path…
  if (rest.length < 5 || rest[2] !== 'resolve') return null;
  const [namespace, repo, , revision] = rest;
  const filePath = rest.slice(4).map(decodeURIComponent).join('/');
  if (!namespace || !repo || !revision || !filePath) return null;

  return {
    commitUrl: `https://huggingface.co/api/${type}/${namespace}/${repo}/commit/${revision}`,
    filePath,
  };
}

/**
 * Upload one file through the HF commit API: newline-delimited JSON, a header
 * line naming the commit followed by a line per file.
 *
 * The blob is sent as base64 TEXT rather than as bytes — `encoding: 'utf-8'`,
 * NOT 'base64', because that flag would tell HF to decode the content back to
 * binary before writing it, which is exactly what we are avoiding: repos on Xet
 * storage reject binary blobs pushed through this route. Base64 costs a third
 * more bytes and buys a file the route will actually accept. readTarget()
 * reverses it.
 */
async function uploadToHuggingFace(
  commitUrl: string,
  filePath: string,
  payload: Buffer,
  token: string,
): Promise<void> {
  const lines = [
    { key: 'header', value: { summary: `chore: update ${filePath}` } },
    { key: 'file', value: { path: filePath, content: payload.toString('base64'), encoding: 'utf-8' } },
  ];
  const res = await fetch(commitUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-ndjson',
      Authorization: `Bearer ${token}`,
    },
    body: lines.map(line => JSON.stringify(line)).join('\n'),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`backup upload failed: HF commit HTTP ${res.status}${detail ? ` — ${detail.slice(0, 200)}` : ''}`);
  }
}

/** Undo the base64 wrapper uploadToHuggingFace applies. Sniffed rather than
 *  assumed: a blob left behind by an older build is raw and starts with MAGIC,
 *  and a restore that silently base64-decoded it would turn a recoverable
 *  database into a corrupt one. */
function decodeHuggingFacePayload(raw: Buffer): Buffer {
  if (raw.subarray(0, MAGIC.length).equals(MAGIC)) return raw;
  return Buffer.from(raw.toString('utf8'), 'base64');
}

async function readTarget(target: string): Promise<Buffer | null> {
  if (isHttpTarget(target)) {
    const headers: Record<string, string> = {};
    const token = process.env.FREEAPI_DB_BACKUP_TOKEN?.trim();
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(target, { method: 'GET', headers, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (res.status === 404 || res.status === 204) return null;
    if (!res.ok) throw new Error(`backup restore failed: HTTP ${res.status}`);
    const raw = Buffer.from(await res.arrayBuffer());
    return parseHuggingFaceTarget(target) ? decodeHuggingFacePayload(raw) : raw;
  }

  if (!fs.existsSync(target)) return null;
  return fs.readFileSync(target);
}

async function writeTargetOnce(target: string, payload: Buffer): Promise<void> {
  if (isHttpTarget(target)) {
    const token = process.env.FREEAPI_DB_BACKUP_TOKEN?.trim();
    const huggingFace = parseHuggingFaceTarget(target);
    if (huggingFace) {
      // Anonymous writes do not exist on HF; without a token every upload would
      // 401 on a schedule and only ever be noticed as an empty restore.
      if (!token) throw new Error('FREEAPI_DB_BACKUP_TOKEN is required to upload a backup to Hugging Face');
      await uploadToHuggingFace(huggingFace.commitUrl, huggingFace.filePath, payload, token);
      return;
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(target, {
      method: 'PUT',
      headers,
      body: payload,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`backup upload failed: HTTP ${res.status}`);
    return;
  }

  fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true });
  // Encrypted, but not therefore safe to leave world-readable: the key is
  // FREEAPI_DB_BACKUP_KEY or ENCRYPTION_KEY, which on a normal install sits in a
  // .env file on the same host. The mode covers creation; restrictToOwner covers
  // the overwrite case, where an existing file keeps the mode it already had —
  // and covers Windows, where the mode argument is a no-op.
  const temporary = `${target}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporary, payload, { mode: 0o600, flag: 'wx' });
    if (!restrictToOwner(temporary)) {
      console.warn(`[db-backup] could not restrict permissions on ${safeTarget(target)} — it may be readable by other local accounts`);
    }
    fs.renameSync(temporary, target);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function isTransientUploadFailure(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /\bHTTP 5\d\d\b|\bHF commit HTTP 5\d\d\b|fetch failed|timed out|timeout|ECONNRESET|ECONNREFUSED|EPIPE|UND_ERR_/i.test(message);
}

async function writeTarget(target: string, payload: Buffer): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await writeTargetOnce(target, payload);
      return;
    } catch (err) {
      if (attempt >= MAX_UPLOAD_ATTEMPTS || !isTransientUploadFailure(err)) throw err;
      await new Promise(resolve => setTimeout(resolve, 500 * 2 ** (attempt - 1)));
    }
  }
}

function validateSqliteFile(filePath: string): void {
  const factory: DbFactory = defaultDbFactory();
  let validationDb: Db | undefined;
  try {
    validationDb = factory(filePath);
    const result = validationDb.pragma('integrity_check') as Array<{ integrity_check?: string }>;
    if (!Array.isArray(result) || result.length !== 1 || result[0]?.integrity_check !== 'ok') {
      throw new Error('SQLite integrity check failed');
    }
    const tables = validationDb.prepare(
      "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    ).get() as { count?: number } | undefined;
    if (!tables || tables.count === 0) throw new Error('SQLite backup contains no application tables');
  } finally {
    validationDb?.close?.();
  }
}

export async function restoreDbBackupIfNeeded(dbPath = getDefaultDbPath()): Promise<DbBackupResult> {
  const target = backupTarget();
  if (!target) return { ok: true, skipped: 'not configured' };
  if (dbPath === ':memory:') return { ok: true, target, skipped: 'memory database' };
  if (fs.existsSync(dbPath)) {
    if (fs.statSync(dbPath).size === 0) {
      throw new Error(`local database file is empty at ${safeTarget(dbPath)}; refusing to initialize over a potentially recoverable database`);
    }
    return { ok: true, target, skipped: 'database already exists' };
  }
  if (fs.existsSync(`${dbPath}-wal`) || fs.existsSync(`${dbPath}-shm`)) {
    throw new Error(`SQLite sidecar files exist without the database at ${safeTarget(dbPath)}; refusing remote restore to preserve recoverable data`);
  }

  let payload: Buffer | null;
  try {
    payload = await readTarget(target);
  } catch (err) {
    console.error(`[db-backup] failed to retrieve remote backup from ${safeTarget(target)}: ${safeError(err)}`);
    throw new Error(`could not retrieve remote database backup from ${safeTarget(target)}: ${safeError(err)}`);
  }
  if (!payload || payload.length === 0) {
    console.warn(`[db-backup] no remote backup found at ${safeTarget(target)}`);
    return { ok: true, target, skipped: 'no backup found' };
  }

  let restored: Buffer;
  try {
    restored = gunzipSync(decryptBackup(payload));
  } catch (err) {
    console.error(`[db-backup] remote backup validation/decryption failed for ${safeTarget(target)}: ${safeError(err)}`);
    throw new Error(`could not validate or decrypt database backup from ${safeTarget(target)}: ${safeError(err)}`);
  }

  const resolvedPath = path.resolve(dbPath);
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
  const temporary = `${resolvedPath}.${process.pid}.${crypto.randomUUID()}.restore`;
  try {
    // Keep decrypted credentials protected even before the DB connection hardens its directory.
    fs.writeFileSync(temporary, restored, { mode: 0o600, flag: 'wx' });
    if (!restrictToOwner(temporary)) {
      console.warn('[db-backup] could not restrict permissions on the temporary restored database');
    }
    try {
      validateSqliteFile(temporary);
    } catch (err) {
      console.error(`[db-backup] downloaded backup is not a valid SQLite database: ${safeError(err)}`);
      throw new Error(`downloaded backup is not a valid SQLite database: ${safeError(err)}`);
    }
    // link() installs the completed file atomically and fails rather than replacing
    // a database another process may have created while the remote fetch was running.
    try {
      fs.linkSync(temporary, resolvedPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
        return { ok: true, target, skipped: 'database created during restore' };
      }
      throw err;
    }
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  console.log(`[db-backup] restored ${restored.length} bytes from ${safeTarget(target)}`);
  return { ok: true, target, bytes: restored.length, restored: true };
}

export async function backupDbNow(db: Db, dbPath = getDefaultDbPath()): Promise<DbBackupResult> {
  const target = backupTarget();
  if (!target) return { ok: true, skipped: 'not configured' };
  if (dbPath === ':memory:') return { ok: true, target, skipped: 'memory database' };
  if (!fs.existsSync(dbPath)) return { ok: false, target, skipped: 'database file missing' };
  const resolvedPath = path.resolve(dbPath);
  if (backupInProgress.has(resolvedPath)) return { ok: true, target, skipped: 'backup already in progress' };
  backupInProgress.add(resolvedPath);
  const snapshot = `${resolvedPath}.${process.pid}.${crypto.randomUUID()}.snapshot`;
  try {
    if (typeof db.backup === 'function') {
      await db.backup(snapshot);
    } else {
      throw new Error('SQLite driver does not support consistent database backups');
    }
    const plain = fs.readFileSync(snapshot);
    const payload = encryptBackup(gzipSync(plain));
    try {
      await writeTarget(target, payload);
    } catch (err) {
      console.error(`[db-backup] upload failed to ${safeTarget(target)}: ${safeError(err)}`);
      throw err;
    }
    console.log(`[db-backup] uploaded ${plain.length} bytes to ${safeTarget(target)}`);
    return { ok: true, target, bytes: plain.length };
  } finally {
    backupInProgress.delete(resolvedPath);
    fs.rmSync(snapshot, { force: true });
    fs.rmSync(`${snapshot}-wal`, { force: true });
    fs.rmSync(`${snapshot}-shm`, { force: true });
  }
}

export function startDbBackupPump(db: Db, scheduler: Scheduler, dbPath = getDefaultDbPath()): (() => void) | null {
  if (!backupTarget()) return null;
  const run = () => {
    void backupDbNow(db, dbPath).catch(err => {
      console.warn(`[db-backup] ${safeError(err)}`);
    });
  };
  run();
  return scheduler.every(backupIntervalMs(), run);
}
