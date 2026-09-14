// Private inherited-pipe bootstrap. Never import the legacy bridge here: its
// module initialization opens ordinary caches and transports.
import {readFile} from 'node:fs/promises';
import {fstatSync, writeSync, closeSync} from 'node:fs';
import {PrivateController} from './private_controller.mjs';
import {PrivateWire, sha256} from './private_wire.mjs';
import {strictJSON} from './private_framing.mjs';

const FILES = ['private_controller_entry.mjs', 'private_controller.mjs', 'private_wire.mjs',
  'private_framing.mjs', 'bridge.js', 'bridge_helpers.js', 'private_admissions.mjs',
  'private_projection.mjs', 'private_native.mjs', 'private_socket.mjs', 'private_auth.mjs', 'private_baileys.mjs',
  'private_delivery.mjs', 'private_spool.mjs'];
let controller = null, ownerEnded = false, closing = null;
function closeOwner() {
  ownerEnded = true;
  if (!closing && controller) closing = controller.close().catch(() => { process.exitCode = 78; });
  return closing;
}
process.stdin.on('end', closeOwner);
process.stdin.on('error', closeOwner);
process.stdout.on('error', closeOwner);
process.on('SIGTERM', () => { process.stdin.destroy(); closeOwner(); });
process.on('SIGINT', () => { process.stdin.destroy(); closeOwner(); });

function bootstrap() {
  return new Promise((resolve, reject) => {
    const prefix = Buffer.alloc(4);
    let prefixCount = 0, body = null, bodyCount = 0, complete = false;
    const timer = setTimeout(() => reject(Error('bootstrap_timeout')), 5000);
    const stop = () => { clearTimeout(timer); if (!complete) reject(Error('owner_eof')); };
    process.stdin.once('end', stop);
    process.stdin.on('data', piece => {
      try {
        if (complete) throw Error('extra_bootstrap');
        let position = 0;
        if (prefixCount < 4) {
          const n = Math.min(4 - prefixCount, piece.length);
          piece.copy(prefix, prefixCount, 0, n); prefixCount += n; position += n;
          if (prefixCount === 4) {
            const length = prefix.readUInt32BE();
            if (!length || length > 1048576) throw Error('bootstrap_limit');
            body = Buffer.alloc(length);
          }
        }
        if (body) {
          if (piece.length - position > body.length - bodyCount) throw Error('extra_bootstrap');
          piece.copy(body, bodyCount, position); bodyCount += piece.length - position;
          if (bodyCount === body.length) {
            complete = true; clearTimeout(timer); resolve(strictJSON(body, 1048576));
          }
        }
      } catch {
        clearTimeout(timer); closeOwner(); reject(Error('bootstrap_invalid'));
      }
    });
  });
}

try {
  // SDK dependencies can bypass the supplied logger and write to stdout. The
  // parent discards both diagnostic streams at the OS level; this dedicated
  // inherited descriptor is the sole bootstrap reply channel.
  const fdText = process.env.PRIVATE_BOOTSTRAP_REPLY_FD;
  if (typeof fdText !== 'string' || !/^[0-9]{1,9}$/.test(fdText)) throw Error('bootstrap_invalid');
  const replyFd = Number(fdText);
  if (replyFd < 3 || !fstatSync(replyFd).isFIFO()) throw Error('bootstrap_invalid');
  delete process.env.PRIVATE_BOOTSTRAP_REPLY_FD;
  const value = await bootstrap();
  const keys = ['v', 'profile_id', 'generation', 'owner_start', 'contract_digest', 'schema_digest', 'schema_base64', 'bearers', 'source_hashes'];
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)) || value.v !== 1 ||
      typeof value.owner_start !== 'string' || !value.owner_start || Buffer.byteLength(value.owner_start) > 128) throw Error('bootstrap_invalid');
  if (Object.keys(value.source_hashes).sort().join() !== [...FILES].sort().join()) throw Error('source_mismatch');
  const hashes = {};
  for (const name of FILES) {
    hashes[name] = sha256(await readFile(new URL(name, import.meta.url)));
    if (hashes[name] !== value.source_hashes[name]) throw Error('source_mismatch');
  }
  const bytes = Buffer.from(value.schema_base64, 'base64');
  if (bytes.toString('base64') !== value.schema_base64) throw Error('bootstrap_invalid');
  const wire = new PrivateWire(bytes, value.schema_digest);
  if (ownerEnded) throw Error('owner_eof');
  // Missing native handlers deliberately make /activate unavailable. The real
  // bridge will install its owned native services here before support is enabled.
  controller = new PrivateController({wire, profile: value.profile_id, generation: value.generation,
    contractDigest: value.contract_digest, bearers: value.bearers, services: {runtimeState: () => 'READY'}});
  const endpoints = await controller.open();
  if (ownerEnded) { await controller.close(); throw Error('owner_eof'); }
  const reply = Buffer.from(JSON.stringify({v: 1, profile_id: value.profile_id, generation: value.generation,
    owner_start: value.owner_start, owner_pid: process.pid, state: 'SUSPENDED',
    schema_digest: wire.digest, contract_digest: value.contract_digest, source_hashes: hashes, endpoints}));
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(reply.length);
  const frame = Buffer.concat([prefix, reply]);
  let written = 0;
  while (written < frame.length) {
    const count = writeSync(replyFd, frame, written, frame.length - written);
    if (count <= 0) throw Error('owner_eof');
    written += count;
  }
  closeSync(replyFd);
} catch {
  await closeOwner();
  process.stdin.destroy();
  process.exitCode = 78;
}
