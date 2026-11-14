import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  HEADER_SIZE,
  scanFrames,
  segmentPath
} from '../lib/main.js';

export async function makeTempDir(prefix = 'audit-chain-') {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function cleanup(...directories) {
  await Promise.all(directories.map((directory) => fs.rm(directory, {
    recursive: true,
    force: true
  })));
}

export function makeRecord(seq, overrides = {}) {
  return {
    seq,
    timestamp: 1_700_000_000_000 + seq,
    source: `service-${seq % 3}`,
    data: Buffer.from(`原始字节-${seq}`),
    ...overrides
  };
}

export async function readSegment(directory, segmentIndex) {
  return fs.readFile(segmentPath(directory, segmentIndex));
}
export async function writeSegment(directory, segmentIndex, buffer) {
  await fs.writeFile(segmentPath(directory, segmentIndex), buffer);
}

export async function listRecordFrames(directory, segmentIndex) {
  const buffer = await readSegment(directory, segmentIndex);
  return scanFrames(buffer).filter((frame) => frame.type === 'record');
}

export function flipByte(buffer, offset) {
  buffer[offset] = buffer[offset] ^ 0xff;
}

export async function removeSegmentFile(directory, segmentIndex) {
  await fs.unlink(segmentPath(directory, segmentIndex));
}

export async function truncateSegment(directory, segmentIndex, length) {
  const handle = await fs.open(segmentPath(directory, segmentIndex), 'r+');
  await handle.truncate(length);
  await handle.close();
}

export { HEADER_SIZE };
