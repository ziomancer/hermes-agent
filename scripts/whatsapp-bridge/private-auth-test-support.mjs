// Synthetic allocation issuer for SDK tests. Production authority is the private
// runtime's quota/transport owner; this helper is never loaded by the bridge.
import {lstat, writeFile} from 'node:fs/promises';
import {createHash, randomBytes} from 'node:crypto';
import path from 'node:path';
import {AUTH_BYTES, AUTH_ALLOCATION_BYTES} from './private_auth.mjs';

export async function allocate(directory, profile, owner_pid = process.pid) {
  const info = await lstat(directory);
  const raw = Buffer.from(JSON.stringify({v: 1, profile, generation: '2'.repeat(32), owner_pid,
    owner_start: 'synthetic-process-start', token: randomBytes(16).toString('hex'), directory,
    device: info.dev, inode: info.ino, account: '100:1@s.whatsapp.net',
    snapshot_bytes: AUTH_BYTES, allocation_bytes: AUTH_ALLOCATION_BYTES}));
  await writeFile(path.join(directory, 'allocation.json'), raw, {mode: 0o600});
  return createHash('sha256').update(raw).digest('hex');
}
