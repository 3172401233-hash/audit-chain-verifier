import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuditError,
  AuditWriter,
  ErrorCode,
  auditLog,
  openIndex
} from '../lib/main.js';
import { cleanup, makeRecord, makeTempDir } from './helpers.js';

test('帧写入失败会让写入器中毒，后续操作必须重新打开', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.commit();

    await writer.append(makeRecord(1));
    assert.notEqual(writer._handle, null);
    const failingHandle = writer._handle;
    failingHandle.write = async () => {
      throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
    };
    failingHandle.close = async () => {};

    await assert.rejects(
      writer.append(makeRecord(2)),
      (error) => error.code === 'ENOSPC'
    );
    assert.equal(writer.closed, true);
    await assert.rejects(
      writer.append(makeRecord(2)),
      (error) => error instanceof AuditError && error.code === ErrorCode.WRITER_CLOSED
    );
    await assert.rejects(
      writer.commit(),
      (error) => error instanceof AuditError && error.code === ErrorCode.WRITER_CLOSED
    );

    const indexAfterCrash = await openIndex(directory);
    assert.deepEqual(indexAfterCrash.list().map((record) => record.seq), [0]);

    const reopened = await AuditWriter.open(directory);
    assert.equal(reopened.pendingCount, 0);
    await reopened.append(makeRecord(1));
    await reopened.commit();
    await reopened.close();

    const index = await openIndex(directory);
    assert.deepEqual(index.list().map((record) => record.seq), [0, 1]);
  } finally {
    await cleanup(directory);
  }
});

test('序号缺口默认报 SEQ_GAP，allowGaps 时只保留严格递增检查', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory, { allowGaps: true });
    await writer.append(makeRecord(0));
    await writer.append(makeRecord(5));
    await writer.commit();
    await writer.close();

    await assert.rejects(
      openIndex(directory),
      (error) => error instanceof AuditError && error.code === ErrorCode.SEQ_GAP
    );

    const index = await openIndex(directory, { allowGaps: true });
    assert.deepEqual(index.list().map((record) => record.seq), [0, 5]);

    const report = await auditLog(directory, { allowGaps: true });
    assert.equal(report.ok, true);
  } finally {
    await cleanup(directory);
  }
});

test('目录中出现非段文件时拒绝猜测并报 UNEXPECTED_FILE', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await writer.append(makeRecord(0));
    await writer.commit();
    await writer.close();

    const { writeFile } = await import('node:fs/promises');
    await writeFile(`${directory}/notes.txt`, 'hello');

    await assert.rejects(
      openIndex(directory),
      (error) => error instanceof AuditError && error.code === ErrorCode.UNEXPECTED_FILE
    );
  } finally {
    await cleanup(directory);
  }
});

test('无效记录在写入前被拒绝，不会产生任何段文件副作用', async () => {
  const directory = await makeTempDir();
  try {
    const writer = await AuditWriter.open(directory);
    await assert.rejects(
      writer.append({ seq: 0, timestamp: 1, source: 'x', data: null }),
      (error) => error instanceof AuditError && error.code === ErrorCode.INVALID_RECORD
    );
    await assert.rejects(
      writer.append({ seq: -1, timestamp: 1, source: 'x', data: Buffer.from('a') }),
      (error) => error instanceof AuditError && error.code === ErrorCode.INVALID_RECORD
    );
    assert.equal(writer.pendingCount, 0);
    await writer.close({ discardUncommitted: true });

    const report = await auditLog(directory);
    assert.equal(report.ok, true);
    assert.equal(report.recordCount, 0);
  } finally {
    await cleanup(directory);
  }
});
