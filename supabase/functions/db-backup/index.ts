import { createBackupHandler } from './handler.ts';

const deno = (globalThis as typeof globalThis & {
  Deno: {
    env: { get(name: string): string | undefined };
    serve(handler: (request: Request) => Promise<Response>): void;
  };
}).Deno;

deno.serve(createBackupHandler({
  supabaseUrl: deno.env.get('SUPABASE_URL') || '',
  serviceRoleKey: deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '',
  backupToken: deno.env.get('FREEAPI_DB_BACKUP_TOKEN') || '',
  bucket: deno.env.get('SUPABASE_BACKUP_BUCKET') || 'freeapi-db-backups',
  objectPath: deno.env.get('SUPABASE_BACKUP_OBJECT') || 'freellmapi.db.backup',
}));
