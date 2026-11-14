import { createHash } from 'node:crypto';

export const ZERO_HASH = '0'.repeat(64);

const TAG_LEAF = Buffer.from('audit-chain/leaf:');
const TAG_NODE = Buffer.from('audit-chain/node:');
const TAG_SEGMENT = Buffer.from('audit-chain/segment:');

export function sha256(...parts) {
  const hash = createHash('sha256');
  for (const part of parts) {
    hash.update(part);
  }
  return hash.digest('hex');
}

export function leafHash(payload) {
  return sha256(TAG_LEAF, payload);
}

function nodeHash(left, right) {
  return sha256(TAG_NODE, Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

export function merkleRoot(leafHashes) {
  if (leafHashes.length === 0) {
    return ZERO_HASH;
  }
  let level = leafHashes.slice();
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = index + 1 < level.length ? level[index + 1] : left;
      next.push(nodeHash(left, right));
    }
    level = next;
  }
  return level[0];
}

export function merkleProof(leafHashes, index) {
  if (index < 0 || index >= leafHashes.length) {
    throw new RangeError(`leaf index ${index} out of range (size=${leafHashes.length})`);
  }
  const proof = [];
  let level = leafHashes.slice();
  let cursor = index;
  while (level.length > 1) {
    const next = [];
    for (let position = 0; position < level.length; position += 2) {
      const left = level[position];
      const right = position + 1 < level.length ? level[position + 1] : left;
      next.push(nodeHash(left, right));
      if (position === cursor || position + 1 === cursor) {
        if (position === cursor) {
          proof.push({ side: 'right', hash: right });
        } else {
          proof.push({ side: 'left', hash: left });
        }
      }
    }
    level = next;
    cursor = Math.floor(cursor / 2);
  }
  return proof;
}

export function verifyMerkleProof(leaf, proof, expectedRoot) {
  if (!Array.isArray(proof)) {
    return false;
  }
  let digest = leaf;
  for (const step of proof) {
    if (!step || typeof step.hash !== 'string' || (step.side !== 'left' && step.side !== 'right')) {
      return false;
    }
    digest = step.side === 'left'
      ? nodeHash(step.hash, digest)
      : nodeHash(digest, step.hash);
  }
  return digest === expectedRoot;
}

export function segmentRoot({ index, prevRoot, count, merkle }) {
  const indexBuffer = Buffer.alloc(4);
  indexBuffer.writeUInt32BE(index, 0);
  const countBuffer = Buffer.alloc(4);
  countBuffer.writeUInt32BE(count, 0);
  return sha256(
    TAG_SEGMENT,
    indexBuffer,
    Buffer.from(prevRoot, 'hex'),
    countBuffer,
    Buffer.from(merkle, 'hex')
  );
}
