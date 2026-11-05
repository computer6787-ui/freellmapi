import { createBackupHandler } from './handler.ts';

Deno.serve(createBackupHandler({
  supabaseUrl: Deno.env.get('SUPABASE_URL') || '',
  serviceRoleKey: Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '',
  backupToken: Deno.env.get('FREEAPI_DB_BACKUP_TOKEN') || '',
  bucket: Deno.env.get('SUPABASE_BACKUP_BUCKET') || 'freeapi-db-backups',
  objectPath: Deno.env.get('SUPABASE_BACKUP_OBJECT') || 'freellmapi.db.backup',
}));
