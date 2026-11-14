import path from 'node:path';
import { AuditError, ErrorCode } from './errors.js';

export const LOG_MAGIC = Buffer.from('AULG');
export const RECORD_MAGIC = Buffer.from('AULR');
export const COMMIT_MAGIC = Buffer.from('AULT');

export const FORMAT_VERSION = 1;
export const HEADER_SIZE = 9;
export const RECORD_HEADER_SIZE = 24;
export const COMMIT_SIZE = 112;

const SEGMENT_NAME_PATTERN = /^segment-(\d{10})\.log$/;

export function toBuffer(value, fieldName) {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  throw new AuditError(
    ErrorCode.INVALID_RECORD,
    `${fieldName} 必须是 Buffer 或 Uint8Array`,
    { field: fieldName }
  );
}

export function encodeRecordPayload(record) {
  const seq = Number(record.seq);
  const timestamp = Number(record.timestamp);
  if (!Number.isSafeInteger(seq) || seq < 0) {
    throw new AuditError(
      ErrorCode.INVALID_RECORD,
      'seq 必须是非负安全整数',
      { seq: record.seq }
    );
  }
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new AuditError(
      ErrorCode.INVALID_RECORD,
      'timestamp 必须是非负安全整数',
      { timestamp: record.timestamp }
    );
  }
  const sourceBuffer = Buffer.from(String(record.source ?? ''), 'utf8');
  const dataBuffer = toBuffer(record.data, 'data');
  if (sourceBuffer.length > 0xffffffff || dataBuffer.length > 0xffffffff) {
    throw new AuditError(
      ErrorCode.INVALID_RECORD,
      'source 或 data 超过 4GiB 长度上限'
    );
  }
  const payload = Buffer.alloc(20 + sourceBuffer.length + dataBuffer.length);
  payload.writeBigUInt64BE(BigInt(seq), 0);
  payload.writeBigUInt64BE(BigInt(timestamp), 8);
  payload.writeUInt32BE(sourceBuffer.length, 16);
  sourceBuffer.copy(payload, 20);
  dataBuffer.copy(payload, 20 + sourceBuffer.length);
  return payload;
}

export function decodeRecordPayload(payload) {
  if (payload.length < 20) {
    throw new AuditError(
      ErrorCode.CORRUPT_SEGMENT,
      `记录负载过短: ${payload.length} 字节`
    );
  }
  const seq = Number(payload.readBigUInt64BE(0));
  const timestamp = Number(payload.readBigUInt64BE(8));
  const sourceLength = payload.readUInt32BE(16);
  if (20 + sourceLength > payload.length) {
    throw new AuditError(
      ErrorCode.CORRUPT_SEGMENT,
      '记录 source 长度超出负载边界'
    );
  }
  const source = payload.subarray(20, 20 + sourceLength).toString('utf8');
  const data = Buffer.from(payload.subarray(20 + sourceLength));
  return { seq, timestamp, source, data };
}

export function encodeRecordFrame(record) {
  const payload = encodeRecordPayload(record);
  const frame = Buffer.alloc(RECORD_HEADER_SIZE + payload.length);
  RECORD_MAGIC.copy(frame, 0);
  frame.writeUInt32BE(payload.length, 4);
  frame.writeBigUInt64BE(BigInt(record.seq), 8);
  frame.writeBigUInt64BE(BigInt(record.timestamp), 16);
  payload.copy(frame, RECORD_HEADER_SIZE);
  return frame;
}

export function encodeHeader(segmentIndex) {
  const header = Buffer.alloc(HEADER_SIZE);
  LOG_MAGIC.copy(header, 0);
  header.writeUInt8(FORMAT_VERSION, 4);
  header.writeUInt32BE(segmentIndex, 5);
  return header;
}

export function encodeCommit({ segmentIndex, prevRoot, count, merkleRoot, segmentRoot }) {
  for (const digest of [prevRoot, merkleRoot, segmentRoot]) {
    if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
      throw new AuditError(ErrorCode.CORRUPT_SEGMENT, '提交摘要必须是 64 位十六进制字符串');
    }
  }
  const commit = Buffer.alloc(COMMIT_SIZE);
  COMMIT_MAGIC.copy(commit, 0);
  commit.writeUInt32BE(segmentIndex, 4);
  commit.writeUInt32BE(count, 8);
  Buffer.from(prevRoot, 'hex').copy(commit, 12);
  Buffer.from(merkleRoot, 'hex').copy(commit, 44);
  Buffer.from(segmentRoot, 'hex').copy(commit, 76);
  commit.writeUInt32BE((segmentIndex ^ 0xa5a5a5a5) >>> 0, 108);
  return commit;
}

function fail(message, details = {}) {
  throw new AuditError(ErrorCode.CORRUPT_SEGMENT, message, details);
}

export function scanFrames(buffer) {
  const frames = [];
  let offset = HEADER_SIZE;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) {
      fail('帧头被截断', { offset });
    }
    const magic = buffer.subarray(offset, offset + 4);
    if (magic.equals(COMMIT_MAGIC)) {
      frames.push({ type: 'commit', offset });
      offset += 4;
      break;
    }
    if (!magic.equals(RECORD_MAGIC)) {
      fail('出现无法识别的帧魔数', { offset });
    }
    if (offset + RECORD_HEADER_SIZE > buffer.length) {
      fail('记录帧头不完整', { offset });
    }
    const payloadLength = buffer.readUInt32BE(offset + 4);
    const payloadStart = offset + RECORD_HEADER_SIZE;
    const payloadEnd = payloadStart + payloadLength;
    if (payloadEnd > buffer.length) {
      fail('记录负载被截断', { offset, payloadLength });
    }
    frames.push({
      type: 'record',
      offset,
      length: RECORD_HEADER_SIZE + payloadLength,
      payloadOffset: payloadStart,
      payloadLength
    });
    offset = payloadEnd;
  }
  return frames;
}

export function parseSegment(buffer, { allowUncommitted = false } = {}) {
  if (buffer.length < HEADER_SIZE || !buffer.subarray(0, 4).equals(LOG_MAGIC)) {
    fail('段头缺失或魔数错误');
  }
  const version = buffer.readUInt8(4);
  if (version !== FORMAT_VERSION) {
    fail(`不支持的格式版本: ${version}`, { version });
  }
  const headerIndex = buffer.readUInt32BE(5);

  const frames = scanFrames(buffer);
  const commitFrame = frames.find((frame) => frame.type === 'commit');

  if (!commitFrame) {
    if (!allowUncommitted) {
      fail('段缺少提交尾，属于未提交或已截断的数据', { segmentIndex: headerIndex });
    }
    return {
      committed: false,
      index: headerIndex,
      records: [],
      rawRecords: []
    };
  }

  const commitOffset = commitFrame.offset;
  if (commitOffset + COMMIT_SIZE !== buffer.length) {
    fail('提交尾长度错误或其后存在多余字节', { commitOffset, fileLength: buffer.length });
  }

  const commitIndex = buffer.readUInt32BE(commitOffset + 4);
  const count = buffer.readUInt32BE(commitOffset + 8);
  const prevRoot = buffer.subarray(commitOffset + 12, commitOffset + 44).toString('hex');
  const merkle = buffer.subarray(commitOffset + 44, commitOffset + 76).toString('hex');
  const root = buffer.subarray(commitOffset + 76, commitOffset + 108).toString('hex');
  const check = buffer.readUInt32BE(commitOffset + 108);
  if (((commitIndex ^ 0xa5a5a5a5) >>> 0) !== check) {
    fail('提交尾校验字损坏', { segmentIndex: commitIndex });
  }
  if (commitIndex !== headerIndex) {
    fail('段头与提交尾的段序号不一致', { headerIndex, commitIndex });
  }

  const recordFrames = frames.filter((frame) => frame.type === 'record');
  if (recordFrames.length !== count) {
    fail('提交尾记录数与实际帧数不一致', {
      segmentIndex: commitIndex,
      declared: count,
      actual: recordFrames.length
    });
  }

  const records = [];
  const rawRecords = [];
  for (const frame of recordFrames) {
    const payload = buffer.subarray(frame.payloadOffset, frame.payloadOffset + frame.payloadLength);
    const record = decodeRecordPayload(payload);
    if (Number(record.seq) !== Number(buffer.readBigUInt64BE(frame.offset + 8))) {
      fail('帧头序号与负载序号不一致', { offset: frame.offset });
    }
    if (Number(record.timestamp) !== Number(buffer.readBigUInt64BE(frame.offset + 16))) {
      fail('帧头时间与负载时间不一致', { offset: frame.offset });
    }
    records.push(record);
    rawRecords.push(payload);
    frame.payload = payload;
  }

  return {
    committed: true,
    index: commitIndex,
    prevRoot,
    merkleRoot: merkle,
    root,
    count,
    records,
    rawRecords,
    frames: recordFrames
  };
}

export function segmentPath(directory, segmentIndex) {
  const name = `segment-${String(segmentIndex).padStart(10, '0')}.log`;
  return path.join(directory, name);
}

export function parseSegmentFilename(filename) {
  const match = SEGMENT_NAME_PATTERN.exec(filename);
  return match ? Number(match[1]) : null;
}
