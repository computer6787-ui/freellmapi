import { describe, expect, it, vi } from 'vitest';
import { createBackupHandler } from '../../../../supabase/functions/db-backup/handler.js';

const config = {
  supabaseUrl: 'https://project.supabase.co',
  serviceRoleKey: 'service-secret',
  backupToken: 'backup-secret',
};
const encryptedBackup = new Uint8Array([
  0x46, 0x41, 0x50, 0x49, 0x42, 0x4b, 0x31, 0x00,
  ...new Uint8Array(28),
]);

describe('Supabase backup bridge', () => {
  it('rejects unauthorized requests without contacting Supabase', async () => {
    const fetcher = vi.fn();
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state', { method: 'GET' }));

    expect(response.status).toBe(401);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('returns a stored backup only to an authenticated caller', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(Response.json({ public: false }))
      .mockResolvedValueOnce(new Response(encryptedBackup, { status: 200 }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state', {
      headers: { Authorization: 'Bearer backup-secret' },
    }));

    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(encryptedBackup);
    expect(fetcher).toHaveBeenCalledWith(
      'https://project.supabase.co/storage/v1/object/freeapi-db-backups/freellmapi.db.backup',
      expect.objectContaining({ method: 'GET' }),
    );
    expect(fetcher.mock.calls[0][1].headers.Authorization).toBe('Bearer service-secret');
    expect(fetcher.mock.calls[1][1].headers.Authorization).toBe('Bearer service-secret');
  });

  it('rejects malformed or oversized uploads before storage writes', async () => {
    const fetcher = vi.fn();
    const handler = createBackupHandler(config, fetcher);
    const headers = {
      Authorization: 'Bearer backup-secret',
      'Content-Type': 'application/octet-stream',
    };
    const malformed = await handler(new Request('https://backup.test/state', {
      method: 'PUT', headers, body: 'not encrypted',
    }));
    const oversized = await handler(new Request('https://backup.test/state', {
      method: 'PUT',
      headers: { ...headers, 'Content-Length': String(51 * 1024 * 1024) },
      body: encryptedBackup,
    }));

    expect(malformed.status).toBe(400);
    expect(oversized.status).toBe(413);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('upserts a fully received encrypted payload and reports storage failures', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(Response.json({ public: false }))
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValue(new Response(null, { status: 200 }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state', {
      method: 'PUT',
      headers: {
        Authorization: 'Bearer backup-secret',
        'Content-Type': 'application/octet-stream',
      },
      body: encryptedBackup,
    }));

    expect(response.status).toBe(204);
    expect(fetcher.mock.calls[2][1]).toMatchObject({
      method: 'PUT',
      headers: expect.objectContaining({
        'x-upsert': 'true',
        'Content-Type': 'application/octet-stream',
      }),
    });
    expect(new Uint8Array(fetcher.mock.calls[2][1].body)).toEqual(encryptedBackup);

    fetcher.mockResolvedValueOnce(Response.json({ public: false }));
    fetcher.mockResolvedValueOnce(new Response(null, { status: 404 }));
    fetcher.mockRejectedValueOnce(new Error('private upstream details'));
    const unavailable = await handler(new Request('https://backup.test/state', {
      method: 'PUT',
      headers: {
        Authorization: 'Bearer backup-secret',
        'Content-Type': 'application/octet-stream',
      },
      body: encryptedBackup,
    }));
    expect(unavailable.status).toBe(502);
    expect(await unavailable.text()).not.toContain('private upstream details');
  });

  it('retains the previous private object before overwriting the current backup', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(Response.json({ public: false }))
      .mockResolvedValueOnce(new Response(encryptedBackup, { status: 200 }))
      .mockResolvedValue(new Response(null, { status: 200 }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state', {
      method: 'PUT',
      headers: {
        Authorization: 'Bearer backup-secret',
        'Content-Type': 'application/octet-stream',
      },
      body: encryptedBackup,
    }));

    expect(response.status).toBe(204);
    expect(fetcher.mock.calls[2][0]).toBe(
      'https://project.supabase.co/storage/v1/object/freeapi-db-backups/freellmapi.db.backup.previous',
    );
    expect(fetcher.mock.calls[2][1].method).toBe('PUT');
    expect(new Uint8Array(fetcher.mock.calls[2][1].body)).toEqual(encryptedBackup);
    expect(fetcher.mock.calls[3][0]).toBe(
      'https://project.supabase.co/storage/v1/object/freeapi-db-backups/freellmapi.db.backup',
    );
  });

  it('serves the previous object to an authenticated recovery GET', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(Response.json({ public: false }))
      .mockResolvedValueOnce(new Response(encryptedBackup, { status: 200 }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state?version=previous', {
      headers: { Authorization: 'Bearer backup-secret' },
    }));

    expect(response.status).toBe(200);
    expect(fetcher.mock.calls[1][0]).toBe(
      'https://project.supabase.co/storage/v1/object/freeapi-db-backups/freellmapi.db.backup.previous',
    );
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(encryptedBackup);
  });

  it('allows a restored previous backup to replace a malformed current object', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(Response.json({ public: false }))
      .mockResolvedValueOnce(new Response('malformed current object', { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state?version=previous', {
      method: 'PUT',
      headers: {
        Authorization: 'Bearer backup-secret',
        'Content-Type': 'application/octet-stream',
      },
      body: encryptedBackup,
    }));

    expect(response.status).toBe(204);
    expect(fetcher.mock.calls[2][0]).toBe(
      'https://project.supabase.co/storage/v1/object/freeapi-db-backups/freellmapi.db.backup',
    );
    expect(fetcher.mock.calls[2][1].method).toBe('PUT');
  });

  it('returns 404 when no private object exists', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(Response.json({ public: false }))
      .mockResolvedValueOnce(new Response(null, { status: 404 }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state', {
      headers: { Authorization: 'Bearer backup-secret' },
    }));
    expect(response.status).toBe(404);
  });

  it('refuses to access an object when the bucket is public', async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json({ public: true }));
    const handler = createBackupHandler(config, fetcher);
    const response = await handler(new Request('https://backup.test/state', {
      headers: { Authorization: 'Bearer backup-secret' },
    }));
    expect(response.status).toBe(503);
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
