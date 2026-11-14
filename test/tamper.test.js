import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuditError,
  AuditWriter,
  ErrorCode,
  auditLog,
  encodeRecordFrame,
  openIndex,
  parseProof,
  scanFrames,
  serializeProof
} from '../lib/main.js';
import {
  HEADER_SIZE,
  cleanup,
  flipByte,
  listRecordFrames,
  makeRecord,
  makeTempDir,
  readSegment,
  removeSegmentFile,
  writeSegment
} from './helpers.js';

async function buildLog(directory, { maxRecordsPerSegment = 2 } = {}) {
  const writer = await AuditWriter.open(directory, { maxRecordsPerSegment });
  for (let seq = 0; seq < 6; seq += 1) {
    await writer.append(makeRecord(seq));
  }
  const checkpoint = await writer.commit();
  await writer.close();
  return checkpoint;
}

function assertRejectedWith(code) {
  return (error) => error instanceof AuditError && error.code === code;
}

test('尾部删除：移除最后一个段后，可信 root 不再匹配', async () => {
  const directory = await makeTempDir();
  try {
    const checkpoint = await buildLog(directory);
    await removeSegmentFile(directory, 2);

    const index = await openIndex(directory);
    assert.equal(index.segmentCount, 2);
    assert.equal(index.recordCount, 4);
    assert.notEqual(index.headRoot, checkpoint.root);

    const proof = index.getProof(0);
    assert.equal(index.verifyProof(proof), true);
    assert.throws(
      () => index.verifyProof(proof, { trustedRoot: checkpoint.root }),
      assertRejectedWith(ErrorCode.INVALID_PROOF)
    );

    const report = await auditLog(directory);
    assert.equal(report.ok, true);
    assert.equal(report.headRoot, index.headRoot);
  } finally {
    await cleanup(directory);
  }
});

test('缺段：删除中间段并把后续段改名会触发 MISSING_SEGMENT', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    await removeSegmentFile(directory, 1);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.MISSING_SEGMENT));
    const report = await auditLog(directory);
    assert.equal(report.ok, false);
    assert.equal(report.issues.some((issue) => issue.code === ErrorCode.MISSING_SEGMENT), true);
  } finally {
    await cleanup(directory);
  }
});

test('中间记录替换：改写 payload 字节后 Merkle 根不匹配', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const frames = await listRecordFrames(directory, 0);
    const buffer = await readSegment(directory, 0);
    const target = frames[0];
    const sourceLength = buffer.readUInt32BE(target.payloadOffset + 16);
    const dataOffset = target.payloadOffset + 20 + sourceLength;
    buffer[dataOffset] = buffer[dataOffset] ^ 0x01;
    await writeSegment(directory, 0, buffer);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.ROOT_MISMATCH));
    const report = await auditLog(directory);
    assert.equal(
      report.issues.some((issue) => issue.code === ErrorCode.ROOT_MISMATCH),
      true
    );
  } finally {
    await cleanup(directory);
  }
});

test('中间记录删除：删掉一帧后提交尾计数与帧数不一致', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const frames = await listRecordFrames(directory, 0);
    const buffer = await readSegment(directory, 0);
    const victim = frames[1];
    const rebuilt = Buffer.concat([
      buffer.subarray(0, victim.offset),
      buffer.subarray(victim.offset + victim.length)
    ]);
    await writeSegment(directory, 0, rebuilt);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.CORRUPT_SEGMENT));
    const report = await auditLog(directory);
    assert.equal(report.ok, false);
    assert.equal(report.issues[0].code, ErrorCode.CORRUPT_SEGMENT);
  } finally {
    await cleanup(directory);
  }
});

test('记录交换：同段内交换两帧会破坏 Merkle 根', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const frames = await listRecordFrames(directory, 0);
    const buffer = await readSegment(directory, 0);
    const first = frames[0];
    const second = frames[1];
    const rebuilt = Buffer.concat([
      buffer.subarray(0, HEADER_SIZE),
      buffer.subarray(second.offset, second.offset + second.length),
      buffer.subarray(first.offset, first.offset + first.length),
      buffer.subarray(second.offset + second.length)
    ]);
    await writeSegment(directory, 0, rebuilt);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.ROOT_MISMATCH));
  } finally {
    await cleanup(directory);
  }
});

test('跨段交换：把段 1 的记录插入段 0，两个段的根都会失效', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const segmentZero = await readSegment(directory, 0);
    const segmentOne = await readSegment(directory, 1);
    const framesOne = scanFrames(segmentOne).filter((frame) => frame.type === 'record');
    const injectedFrame = segmentOne.subarray(framesOne[0].offset, framesOne[0].offset + framesOne[0].length);

    const framesZero = scanFrames(segmentZero);
    const commitOffset = framesZero.find((frame) => frame.type === 'commit').offset;
    const tamperedZero = Buffer.concat([
      segmentZero.subarray(0, commitOffset),
      injectedFrame,
      segmentZero.subarray(commitOffset)
    ]);
    await writeSegment(directory, 0, tamperedZero);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.CORRUPT_SEGMENT));

    await writeSegment(directory, 0, segmentZero);
    const tamperedOne = Buffer.concat([
      segmentOne.subarray(0, framesOne[0].offset),
      segmentOne.subarray(framesOne[0].offset + framesOne[0].length)
    ]);
    await writeSegment(directory, 1, tamperedOne);
    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.CORRUPT_SEGMENT));
  } finally {
    await cleanup(directory);
  }
});

test('记录插入：在段内插入一个格式合法的新帧，计数校验直接失败', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const buffer = await readSegment(directory, 0);
    const frames = scanFrames(buffer);
    const commitOffset = frames.find((frame) => frame.type === 'commit').offset;
    const forgedFrame = encodeRecordFrame(makeRecord(99, { source: 'attacker' }));
    const tampered = Buffer.concat([
      buffer.subarray(0, commitOffset),
      forgedFrame,
      buffer.subarray(commitOffset)
    ]);
    await writeSegment(directory, 0, tampered);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.CORRUPT_SEGMENT));
  } finally {
    await cleanup(directory);
  }
});

test('伪造 proof：篡改记录内容、兄弟哈希和 headRoot 都会被拒绝', async () => {
  const directory = await makeTempDir();
  try {
    const checkpoint = await buildLog(directory);
    const index = await openIndex(directory);
    const proof = index.getProof(3);

    const contentForgery = structuredClone(proof);
    contentForgery.record.data = Buffer.from('伪造内容').toString('base64');
    assert.throws(
      () => index.verifyProof(contentForgery),
      assertRejectedWith(ErrorCode.INVALID_PROOF)
    );

    const siblingForgery = structuredClone(proof);
    siblingForgery.merkleRoot = flipDigest(siblingForgery.merkleRoot);
    assert.throws(
      () => index.verifyProof(siblingForgery),
      assertRejectedWith(ErrorCode.INVALID_PROOF)
    );

    const headForgery = structuredClone(proof);
    headForgery.headRoot = flipDigest(headForgery.headRoot);
    assert.throws(
      () => index.verifyProof(headForgery, { trustedRoot: checkpoint.root }),
      assertRejectedWith(ErrorCode.INVALID_PROOF)
    );

    const anchorForgery = structuredClone(proof);
    anchorForgery.anchors[0].root = flipDigest(anchorForgery.anchors[0].root);
    assert.throws(
      () => index.verifyProof(anchorForgery),
      assertRejectedWith(ErrorCode.INVALID_PROOF)
    );

    assert.equal(index.verifyProof(proof, { trustedRoot: checkpoint.root }), true);
  } finally {
    await cleanup(directory);
  }
});

test('proof 的 JSON 序列化往返后仍可离线验证', async () => {
  const directory = await makeTempDir();
  try {
    const checkpoint = await buildLog(directory);
    const index = await openIndex(directory);
    const proof = index.getProof(4);

    const text = serializeProof(proof);
    const restored = parseProof(text);
    assert.equal(index.verifyProof(restored, { trustedRoot: checkpoint.root }), true);
  } finally {
    await cleanup(directory);
  }
});

test('截断锚点链伪造旧 head 会在可信 root 锚定时暴露', async () => {
  const directory = await makeTempDir();
  try {
    const checkpoint = await buildLog(directory);
    const index = await openIndex(directory);
    const proof = index.getProof(0);

    const shortened = structuredClone(proof);
    shortened.anchors = shortened.anchors.slice(0, 1);
    shortened.anchorIndex = shortened.anchors[0].index;
    shortened.headRoot = shortened.anchors[0].root;

    assert.equal(index.verifyProof(shortened), true);
    assert.throws(
      () => index.verifyProof(shortened, { trustedRoot: checkpoint.root }),
      assertRejectedWith(ErrorCode.INVALID_PROOF)
    );
  } finally {
    await cleanup(directory);
  }
});

test('伪造提交尾：只翻转段根摘要字节会在重算段根时暴露', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const buffer = await readSegment(directory, 1);
    const frames = scanFrames(buffer);
    const commitOffset = frames.find((frame) => frame.type === 'commit').offset;
    flipByte(buffer, commitOffset + 80);
    await writeSegment(directory, 1, buffer);

    await assert.rejects(openIndex(directory), assertRejectedWith(ErrorCode.ROOT_MISMATCH));
  } finally {
    await cleanup(directory);
  }
});

test('验证途中遇到损坏段：audit 返回问题清单而不是只抛一个异常', async () => {
  const directory = await makeTempDir();
  try {
    await buildLog(directory);
    const buffer = await readSegment(directory, 1);
    const frames = await listRecordFrames(directory, 1);
    const sourceLength = buffer.readUInt32BE(frames[0].payloadOffset + 16);
    flipByte(buffer, frames[0].payloadOffset + 20 + sourceLength + 1);
    await writeSegment(directory, 1, buffer);

    const report = await auditLog(directory);
    assert.equal(report.ok, false);
    assert.equal(report.issues.length >= 1, true);
    assert.equal(report.issues[0].code, ErrorCode.ROOT_MISMATCH);
    assert.equal(report.segmentCount, 1);
  } finally {
    await cleanup(directory);
  }
});

test('整段替换：用合法结构的新段覆盖旧段，prevRoot 链接断裂', async () => {
  const directory = await makeTempDir();
  const other = await makeTempDir();
  try {
    await buildLog(directory);

    const attacker = await AuditWriter.open(other, { maxRecordsPerSegment: 2 });
    for (let seq = 100; seq < 104; seq += 1) {
      await attacker.append(makeRecord(seq));
    }
    await attacker.commit();
    await attacker.close();

    const forgedSegment = await readSegment(other, 0);
    const originalOne = await readSegment(directory, 1);
    const frames = scanFrames(originalOne);
    const commitOffset = frames.find((frame) => frame.type === 'commit').offset;
    const sameLengthForgery = Buffer.concat([
      forgedSegment.subarray(0, forgedSegment.length),
      originalOne.subarray(commitOffset)
    ]);
    await writeSegment(directory, 1, sameLengthForgery);

    await assert.rejects(openIndex(directory), (error) =>
      error instanceof AuditError &&
      (error.code === ErrorCode.CORRUPT_SEGMENT || error.code === ErrorCode.ROOT_MISMATCH)
    );
  } finally {
    await cleanup(directory, other);
  }
});

function flipDigest(digest) {
  const chars = digest.split('');
  chars[0] = chars[0] === '0' ? '1' : '0';
  return chars.join('');
}
