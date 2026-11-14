import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuditError,
  AuditWriter,
  ErrorCode,
  ZERO_HASH,
  auditLog,
  openIndex
} from '../lib/main.js';
import {
  cleanup,
  listRecordFrames,
  makeRecord,
  makeTempDir,
  readSegment,
  writeSegment,
  truncateSegment
} from './helpers.js';

async function buildTwoCommittedSegments(directory) {
  const writer = await AuditWriter.open(directory, { maxRecordsPerSegment: 2 });
  await writer.append(makeRecord(0));
  await writer.append(makeRecord(1));
  await writer.commit();
  await writer.append(makeRecord(2));
  await writer.simulateCrash();
  return writer;
}

test('写入中断：没有提交尾的尾段不会被索引，也不会被当作合法记录', async () => {
  const directory = await makeTempDir();
  try {
    await buildTwoCommittedSegments(directory);

    const index = await openIndex(directory);
    assert.equal(index.segmentCount, 1);
    assert.equal(index.recordCount, 2);
    assert.deepEqual(index.list().map((record) => record.seq), [0, 1]);
    assert.throws(
      () => index.locate(2),
      (error) => error instanceof AuditError && error.code === ErrorCode.NOT_FOUND
    );

    const report = await auditLog(directory);
    assert.equal(report.ok, true);
    assert.equal(report.hasUncommittedTail, true);
    assert.equal(report.recordCount, 2);
    assert.equal(report.warnings[0].code, 'UNCOMMITTED_TAIL');
  } finally {
    await cleanup(directory);
  }
});

test('崩溃后重新打开写入器会清理未提交尾段并从可信链续写', async () => {
  const directory = await makeTempDir();
  try {
    await buildTwoCommittedSegments(directory);

    const reopened = await AuditWriter.open(directory, { maxRecordsPerSegment: 2 });
    assert.equal(reopened.segmentCount, 1);
    assert.equal(reopened.pendingCount, 0);

    await reopened.append(makeRecord(2));
    await reopened.append(makeRecord(3));
    const checkpoint = await reopened.commit();
    assert.equal(checkpoint.segmentIndex, 1);
    assert.equal(checkpoint.count, 2);
    await reopened.close();

    const index = await openIndex(directory);
    assert.equal(index.segmentCount, 2);
    assert.deepEqual(index.list().map((record) => record.seq), [0, 1, 2, 3]);
    assert.equal(index.headRoot, checkpoint.root);
    const firstProof = index.getProof(0);
    const lastProof = index.getProof(3);
    assert.equal(lastProof.anchors[0].prevRoot, firstProof.anchors[0].root);
    assert.equal(lastProof.headRoot, index.headRoot);
  } finally {
    await cleanup(directory);
  }
});

test('崩溃后的写入器拒绝继续写入，避免半开状态污染数据', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.simulateCrash();

    await assert.rejects(
      writer.append(makeRecord(1)),
      (error) => error instanceof AuditError && error.code === ErrorCode.WRITER_CLOSED
    );
    await assert.rejects(
      writer.commit(),
      (error) => error instanceof AuditError && error.code === ErrorCode.WRITER_CLOSED
    );
  } finally {
    await cleanup(directory);
  }
});

test('提交尾被截断等同于写入中断，验证器按未提交尾处理', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(1));
    await writer.commit();
    await writer.append(makeRecord(2));
    await writer.simulateCrash();

    const fullTail = await readSegment(directory, 1);
    await truncateSegment(directory, 1, fullTail.length - 3);

    const index = await openIndex(directory);
    assert.equal(index.recordCount, 2);
    assert.equal(index.segmentCount, 1);

    const report = await auditLog(directory);
    assert.equal(report.ok, true);
    assert.equal(report.hasUncommittedTail, true);
  } finally {
    await cleanup(directory);
  }
});

test('已提交段帧结构损坏会报 CORRUPT_SEGMENT，而不是静默丢记录', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(1));
    await writer.commit();
    await writer.close();

    const frames = await listRecordFrames(directory, 0);
    const buffer = await readSegment(directory, 0);
    buffer[frames[0].offset + 6] = 0x77;
    await writeSegment(directory, 0, buffer);

    await assert.rejects(
      openIndex(directory),
      (error) => error instanceof AuditError && error.code === ErrorCode.CORRUPT_SEGMENT
    );

    const report = await auditLog(directory);
    assert.equal(report.ok, false);
    assert.equal(report.issues[0].code, ErrorCode.CORRUPT_SEGMENT);
    assert.equal(report.hasUncommittedTail, false);
  } finally {
    await cleanup(directory);
  }
});

test('已提交段连同提交尾一起被截断时，可信 root 能发现尾部删除', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(1));
    const checkpoint = await writer.commit();
    await writer.close();

    const buffer = await readSegment(directory, 0);
    await truncateSegment(directory, 0, buffer.length - 120);

    const index = await openIndex(directory);
    assert.equal(index.recordCount, 0);
    assert.notEqual(index.headRoot, checkpoint.root);

    const report = await auditLog(directory);
    assert.equal(report.hasUncommittedTail, true);
    assert.equal(report.headRoot, ZERO_HASH);
  } finally {
    await cleanup(directory);
  }
});

test('close(discardUncommitted) 会丢弃未提交尾段，之后索引完全干净', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.commit();
    await writer.append(makeRecord(1));
    await writer.close({ discardUncommitted: true });

    const index = await openIndex(directory);
    assert.equal(index.recordCount, 1);
    assert.deepEqual(index.list().map((record) => record.seq), [0]);

    const report = await auditLog(directory);
    assert.equal(report.ok, true);
    assert.equal(report.hasUncommittedTail, false);
  } finally {
    await cleanup(directory);
  }
});
