import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ZERO_HASH,
  leafHash,
  merkleProof,
  merkleRoot,
  segmentRoot,
  sha256,
  verifyMerkleProof,
  encodeRecordPayload
} from '../lib/main.js';
import { makeRecord } from './helpers.js';

test('空 Merkle 树返回全零根', () => {
  assert.equal(merkleRoot([]), ZERO_HASH);
});

test('奇数个叶子时最后一个节点与自身配对，proof 仍可验证', () => {
  const leaves = [0, 1, 2].map((seq) => leafHash(encodeRecordPayload(makeRecord(seq))));
  const root = merkleRoot(leaves);

  for (const index of [0, 1, 2]) {
    const proof = merkleProof(leaves, index);
    assert.equal(verifyMerkleProof(leaves[index], proof, root), true);
  }

  const wrongProof = merkleProof(leaves, 1);
  assert.equal(verifyMerkleProof(leaves[0], wrongProof, root), false);
});

test('proof 遇到非法兄弟节点结构时返回 false 而不是抛异常', () => {
  const leaves = [0, 1].map((seq) => leafHash(encodeRecordPayload(makeRecord(seq))));
  const root = merkleRoot(leaves);
  assert.equal(verifyMerkleProof(leaves[0], [{ side: 'middle', hash: leaves[1] }], root), false);
  assert.equal(verifyMerkleProof(leaves[0], [{ side: 'left', hash: 'bad' }], root), false);
  assert.equal(verifyMerkleProof(leaves[0], null, root), false);
});

test('segmentRoot 绑定段序号、前一根、记录数和 Merkle 根，任一输入变化都会改变结果', () => {
  const leaves = [0, 1].map((seq) => leafHash(encodeRecordPayload(makeRecord(seq))));
  const merkle = merkleRoot(leaves);
  const base = { index: 3, prevRoot: ZERO_HASH, count: 2, merkle };
  const root = segmentRoot(base);

  assert.notEqual(segmentRoot({ ...base, index: 4 }), root);
  assert.notEqual(segmentRoot({ ...base, count: 1 }), root);
  assert.notEqual(segmentRoot({ ...base, merkle: leaves[0] }), root);
  assert.notEqual(segmentRoot({ ...base, prevRoot: root }), root);
  assert.equal(segmentRoot(base), root);
});

test('叶子哈希与节点哈希使用不同域标签，不能互相伪造', () => {
  const payload = encodeRecordPayload(makeRecord(0));
  const leaf = leafHash(payload);
  assert.notEqual(leaf, sha256(payload));
  const root = merkleRoot([leaf, leafHash(encodeRecordPayload(makeRecord(1)))]);
  assert.notEqual(root, leaf);
});
