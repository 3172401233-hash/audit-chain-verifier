import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuditError,
  AuditWriter,
  ErrorCode,
  ZERO_HASH,
  encodeRecordPayload,
  leafHash,
  openIndex,
  segmentPath
} from '../lib/main.js';
import { cleanup, makeRecord, makeTempDir } from './helpers.js';

test('空日志可以打开，headRoot 是全零摘要且没有任何记录', async () => {
  const directory = await makeTempDir();
  try {
    const index = await openIndex(directory);
    assert.equal(index.isEmpty, true);
    assert.equal(index.recordCount, 0);
    assert.equal(index.segmentCount, 0);
    assert.equal(index.headRoot, ZERO_HASH);
    assert.deepEqual(index.list(), []);

    assert.throws(
      () => index.locate(0),
      (error) => error instanceof AuditError && error.code === ErrorCode.NOT_FOUND
    );
  } finally {
    await cleanup(directory);
  }
});

test('commit 之前的记录不能被索引为可验证记录', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(1));

    const indexBeforeCommit = await openIndex(directory);
    assert.equal(indexBeforeCommit.recordCount, 0);
    assert.equal(indexBeforeCommit.isEmpty, true);

    const checkpoint = await writer.commit();
    assert.equal(checkpoint.committed, true);
    assert.equal(checkpoint.count, 2);

    const indexAfterCommit = await openIndex(directory);
    assert.equal(indexAfterCommit.recordCount, 2);
    assert.equal(indexAfterCommit.segmentCount, 1);
    assert.equal(indexAfterCommit.headRoot, checkpoint.root);

    await writer.close();
  } finally {
    await cleanup(directory);
  }
});

test('单记录日志：Merkle 根即叶子哈希，proof 为空兄弟列表', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    const record = makeRecord(7, { source: 'billing', data: Buffer.from([0xde, 0xad]) });
    await writer.append(record);
    const checkpoint = await writer.commit();
    await writer.close();

    const index = await openIndex(directory);
    const proof = index.getProof(7);
    assert.equal(proof.segmentIndex, 0);
    assert.equal(proof.position, 0);
    assert.deepEqual(proof.merkleProof, []);
    assert.equal(proof.merkleRoot, leafHash(encodeRecordPayload(record)));
    assert.equal(proof.anchors.length, 1);
    assert.equal(proof.headRoot, checkpoint.root);
    assert.equal(index.verifyProof(proof), true);
    assert.equal(index.verifyProof(proof, { trustedRoot: checkpoint.root }), true);

    const located = index.locate(7);
    assert.equal(located.record.source, 'billing');
    assert.deepEqual(located.record.data, Buffer.from([0xde, 0xad]));
  } finally {
    await cleanup(directory);
  }
});

test('轮转边界：达到阈值自动封段，新段保存前一段的根摘要', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory, { maxRecordsPerSegment: 2 });
    const roots = [];
    for (let seq = 0; seq < 5; seq += 1) {
      await writer.append(makeRecord(seq));
      if (seq === 1 || seq === 3) {
        const checkpoint = await writer.commit();
        roots.push(checkpoint.root);
      }
    }
    const lastCheckpoint = await writer.commit();
    roots.push(lastCheckpoint.root);
    await writer.close();

    const index = await openIndex(directory);
    assert.equal(index.segmentCount, 3);
    assert.equal(index.recordCount, 5);
    assert.equal(index.headRoot, roots[2]);

    const files = [0, 1, 2].map((segmentIndex) => segmentPath(directory, segmentIndex));
    for (const file of files) {
      await assert.doesNotReject(fsStat(file));
    }

    const firstProof = index.getProof(0);
    assert.equal(firstProof.anchors.length, 3);
    assert.equal(firstProof.anchors[0].prevRoot, ZERO_HASH);
    assert.equal(firstProof.anchors[1].prevRoot, roots[0]);
    assert.equal(firstProof.anchors[2].prevRoot, roots[1]);
    assert.equal(index.verifyProof(firstProof, { trustedRoot: roots[2] }), true);

    const middleProof = index.getProof(2);
    assert.equal(middleProof.anchors.length, 2);
    assert.equal(middleProof.anchors[0].index, 1);
    assert.equal(index.verifyProof(middleProof), true);
  } finally {
    await cleanup(directory);
  }
});

test('append 触发隐式轮转：无需手动 commit 也会先封旧段', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory, { maxRecordsPerSegment: 2 });
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(1));
    await writer.append(makeRecord(2));
    assert.equal(writer.pendingCount, 1);
    assert.equal(writer.committedRecordCount, 2);

    const checkpoint = await writer.commit();
    assert.equal(checkpoint.committed, true);
    assert.equal(checkpoint.segmentIndex, 1);
    await writer.close();

    const index = await openIndex(directory);
    assert.equal(index.segmentCount, 2);
    assert.equal(index.recordCount, 3);
  } finally {
    await cleanup(directory);
  }
});

test('写入端拒绝重复序号和乱序序号', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(2));

    await assert.rejects(
      writer.append(makeRecord(2)),
      (error) => error instanceof AuditError && error.code === ErrorCode.SEQ_DUPLICATE
    );
    await assert.rejects(
      writer.append(makeRecord(1)),
      (error) => error instanceof AuditError && error.code === ErrorCode.SEQ_OUT_OF_ORDER
    );
    await writer.close();
  } finally {
    await cleanup(directory);
  }
});

async function fsStat(file) {
  const { stat } = await import('node:fs/promises');
  return stat(file);
}
