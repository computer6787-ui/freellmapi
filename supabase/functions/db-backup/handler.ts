const MAX_BACKUP_BYTES = 50 * 1024 * 1024;
const MAGIC = [0x46, 0x41, 0x50, 0x49, 0x42, 0x4b, 0x31, 0x00];

export interface BackupBridgeConfig {
  supabaseUrl: string;
  serviceRoleKey: string;
  backupToken: string;
  bucket?: string;
  objectPath?: string;
}

function unauthorized(): Response {
  return new Response('Unauthorized', { status: 401 });
}

function tokenMatches(expected: string, provided: string): boolean {
  const left = new TextEncoder().encode(expected);
  const right = new TextEncoder().encode(provided);
  let difference = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
    difference |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return difference === 0;
}

function storageObjectUrl(config: BackupBridgeConfig, objectPath = config.objectPath || 'freellmapi.db.backup'): string {
  const base = config.supabaseUrl.replace(/\/+$/, '');
  const bucket = encodeURIComponent(config.bucket || 'freeapi-db-backups');
  const object = objectPath
    .split('/')
    .map(encodeURIComponent)
    .join('/');
  return `${base}/storage/v1/object/${bucket}/${object}`;
}

function isEncryptedBackup(payload: Uint8Array): boolean {
  return payload.length >= MAGIC.length + 12 + 16 && MAGIC.every((byte, i) => payload[i] === byte);
}

function isMissingStorageObject(status: number, errorText: string): boolean {
  if (status === 404) return true;
  try {
    const errorData = JSON.parse(errorText);
    return errorData.code === 'NoSuchKey' || String(errorData.statusCode) === '404';
  } catch {
    return false;
  }
}

function toArrayBuffer(payload: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(payload.byteLength);
  new Uint8Array(buffer).set(payload);
  return buffer;
}

async function isPrivateBucket(
  config: BackupBridgeConfig,
  fetcher: typeof fetch,
): Promise<boolean> {
  const bucket = encodeURIComponent(config.bucket || 'freeapi-db-backups');
  const url = `${config.supabaseUrl.replace(/\/+$/, '')}/storage/v1/bucket/${bucket}`;
  const response = await fetcher(url, {
    method: 'GET',
    headers: {
      apikey: config.serviceRoleKey,
    },
  });
  if (!response.ok) return false;
  const metadata = await response.json();
  return metadata.public === false;
}

async function readBoundedBody(
  body: ReadableStream<Uint8Array> | null,
  length: string | null,
): Promise<Uint8Array | Response> {
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BACKUP_BYTES)) {
    return new Response('Backup payload is too large or has an invalid Content-Length', { status: 413 });
  }
  if (!body) return new Response('Backup payload is required', { status: 400 });

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BACKUP_BYTES) {
        await reader.cancel();
        return new Response('Backup payload is too large', { status: 413 });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const payload = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    payload.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (length !== null && Number(length) !== payload.length) {
    return new Response('Backup payload length does not match Content-Length', { status: 400 });
  }
  if (!isEncryptedBackup(payload)) {
    return new Response('Malformed encrypted backup', { status: 400 });
  }
  return payload;
}

export function createBackupHandler(
  config: BackupBridgeConfig,
  fetcher: typeof fetch = fetch,
): (request: Request) => Promise<Response> {
  return async request => {
    const authorization = request.headers.get('authorization') || '';
    const match = /^Bearer\s+(.+)$/i.exec(authorization);
    if (!config.backupToken || !match || !tokenMatches(config.backupToken, match[1])) {
      return unauthorized();
    }
    if (!config.supabaseUrl || !config.serviceRoleKey) {
      return new Response('Backup bridge is not configured', { status: 503 });
    }
    if (request.method !== 'GET' && request.method !== 'PUT') {
      return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, PUT' } });
    }

    const url = storageObjectUrl(config);
    const previousUrl = storageObjectUrl(config, `${config.objectPath || 'freellmapi.db.backup'}.previous`);
    const restoringPrevious = new URL(request.url).searchParams.get('version') === 'previous';
    const headers = {
      apikey: config.serviceRoleKey,
    };

    try {
      if (request.method === 'GET') {
        if (!(await isPrivateBucket(config, fetcher))) {
          return new Response('Backup bucket must exist and be private', { status: 503 });
        }
        const selectedUrl = restoringPrevious ? previousUrl : url;
        const stored = await fetcher(selectedUrl, { method: 'GET', headers });
        if (stored.status === 404) return new Response('Backup not found', { status: 404 });
        if (!stored.ok) {
          const responseText = await stored.text();
          if (isMissingStorageObject(stored.status, responseText)) {
            return new Response('Backup not found', { status: 404 });
          }
          const errorText = responseText.slice(0, 1000)
            .split(config.serviceRoleKey).join('[redacted]')
            .split(config.backupToken).join('[redacted]')
            .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');
          console.error('[db-backup] Storage GET failed:', {
            status: stored.status,
            error: errorText,
          });
          return new Response('Backup storage unavailable', { status: 502 });
        }
        return new Response(stored.body, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' },
        });
      }

      const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/octet-stream') {
        return new Response('Content-Type must be application/octet-stream', { status: 415 });
      }
      const payload = await readBoundedBody(request.body, request.headers.get('content-length'));
      if (payload instanceof Response) return payload;
      if (!(await isPrivateBucket(config, fetcher))) {
        return new Response('Backup bucket must exist and be private', { status: 503 });
      }

      const current = await fetcher(url, { method: 'GET', headers });
      if (current.status !== 404) {
        if (!current.ok) {
          const errorText = await current.text();
          if (!isMissingStorageObject(current.status, errorText)) {
            return new Response('Existing backup could not be preserved', { status: 502 });
          }
        } else {
          const oldPayload = await readBoundedBody(current.body, current.headers.get('content-length'));
          if (oldPayload instanceof Response || !isEncryptedBackup(oldPayload)) {
            if (!restoringPrevious) {
              return new Response('Existing backup is malformed and was not overwritten', { status: 409 });
            }
          } else {
            const preserved = await fetcher(previousUrl, {
              method: 'PUT',
              headers: {
                ...headers,
                'Content-Type': 'application/octet-stream',
                'x-upsert': 'true',
              },
              body: toArrayBuffer(oldPayload),
            });
            if (!preserved.ok) return new Response('Existing backup could not be preserved', { status: 502 });
          }
        }
      }

      const stored = await fetcher(url, {
        method: 'PUT',
        headers: {
          ...headers,
          'Content-Type': 'application/octet-stream',
          'x-upsert': 'true',
        },
        body: toArrayBuffer(payload),
      });
      if (!stored.ok) return new Response('Backup storage unavailable', { status: 502 });
      return new Response(null, { status: 204 });
    } catch {
      // Do not log request headers, payloads, or upstream service credentials.
      return new Response('Backup storage unavailable', { status: 502 });
    }
  };
}
