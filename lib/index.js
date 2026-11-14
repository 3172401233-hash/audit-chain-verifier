import { promises as fs } from 'node:fs';
import {
  encodeRecordPayload,
  parseSegment
} from './codec.js';
export {
  COMMIT_MAGIC,
  HEADER_SIZE,
  decodeRecordPayload,
  scanFrames,
  segmentPath
} from './codec.js';
import {
  ZERO_HASH,
  leafHash,
  merkleProof,
  segmentRoot,
  verifyMerkleProof
} from './crypto.js';
import { AuditError, ErrorCode } from './errors.js';
import {
  checkSequenceOrder,
  listSegmentFiles,
  loadVerifiedSegments,
  parseTolerantTail,
  verifySegment
} from './store.js';

export class AuditIndex {
  constructor(directory, segments, headRoot) {
    this.directory = directory;
    this._segments = segments;
    this._headRoot = headRoot;
    this._bySeq = new Map();
    this._entries = [];

    for (const segment of segments) {
      for (let position = 0; position < segment.records.length; position += 1) {
        const record = segment.records[position];
        const entry = {
          record,
          segmentIndex: segment.index,
          position,
          frameOffset: segment.frames[position].offset,
          payloadOffset: segment.frames[position].payloadOffset,
          payloadLength: segment.frames[position].payloadLength,
          path: segment.path
        };
        this._bySeq.set(record.seq, entry);
        this._entries.push(entry);
      }
    }
  }

  get headRoot() {
    return this._headRoot;
  }

  get segmentCount() {
    return this._segments.length;
  }

  get recordCount() {
    return this._entries.length;
  }

  get isEmpty() {
    return this._entries.length === 0;
  }

  list() {
    return this._entries.map((entry) => ({ ...entry.record }));
  }

  locate(seq) {
    const entry = this._bySeq.get(Number(seq));
    if (!entry) {
      throw new AuditError(
        ErrorCode.NOT_FOUND,
        `序号 ${seq} 不在已提交的索引中`,
        { seq: Number(seq) }
      );
    }
    return entry;
  }

  getProof(seq) {
    const entry = this.locate(seq);
    const segment = this._segments.find((item) => item.index === entry.segmentIndex);
    const proof = merkleProof(segment.leafHashes, entry.position);
    const anchorIndex = this._segments.length - 1;

    return {
      version: 1,
      record: { ...entry.record },
      segmentIndex: segment.index,
      position: entry.position,
      merkleProof: proof,
      merkleRoot: segment.merkleRoot,
      anchors: this._segments.slice(segment.index).map((item) => ({
        index: item.index,
        prevRoot: item.prevRoot,
        count: item.count,
        merkleRoot: item.merkleRoot,
        root: item.root
      })),
      anchorIndex,
      headRoot: this._headRoot
    };
  }

  verifyProof(proof, options = {}) {
    return verifyProof(proof, options);
  }
}

function expect(condition, message, details) {
  if (!condition) {
    throw new AuditError(ErrorCode.INVALID_PROOF, message, details);
  }
}

export function serializeProof(proof) {
  return JSON.stringify(proof);
}

export function parseProof(text) {
  try {
    return JSON.parse(text);
  } catch (cause) {
    throw new AuditError(ErrorCode.INVALID_PROOF, 'proof 不是合法的 JSON', { cause });
  }
}

export function verifyProof(proof, { trustedRoot } = {}) {
  expect(proof && typeof proof === 'object', 'proof 必须是对象');
  expect(proof.version === 1, '仅支持 version=1 的证明', { version: proof.version });
  expect(Number.isInteger(proof.segmentIndex) && proof.segmentIndex >= 0, '缺少合法的 segmentIndex');
  expect(Number.isInteger(proof.position) && proof.position >= 0, '缺少合法的 position');
  expect(Array.isArray(proof.anchors) && proof.anchors.length > 0, 'proof 缺少锚点链');
  expect(proof.anchors[0].index === proof.segmentIndex, '锚点链起点与 segmentIndex 不一致');
  expect(Array.isArray(proof.merkleProof), 'merkleProof 必须是数组');
  expect(typeof proof.merkleRoot === 'string' && proof.merkleRoot.length === 64, '缺少合法的 merkleRoot');
  expect(typeof proof.headRoot === 'string' && proof.headRoot.length === 64, '缺少合法的 headRoot');

  let payload;
  try {
    payload = encodeRecordPayload(normalizeProofRecord(proof.record));
  } catch (cause) {
    throw new AuditError(ErrorCode.INVALID_PROOF, 'proof 中的记录无法编码', { cause });
  }

  const leaf = leafHash(payload);
  expect(
    verifyMerkleProof(leaf, proof.merkleProof, proof.merkleRoot),
    'Merkle 证明校验失败：记录内容与证明不匹配',
    { segmentIndex: proof.segmentIndex, position: proof.position }
  );

  let previousRoot;
  for (const anchor of proof.anchors) {
    expect(
      anchor && typeof anchor === 'object'
        && Number.isInteger(anchor.index) && anchor.index >= 0
        && Number.isInteger(anchor.count) && anchor.count >= 0
        && typeof anchor.prevRoot === 'string'
        && typeof anchor.merkleRoot === 'string'
        && typeof anchor.root === 'string',
      '锚点链中存在结构非法的锚点',
      { anchor }
    );
    const merkleForAnchor = anchor.index === proof.segmentIndex
      ? proof.merkleRoot
      : anchor.merkleRoot;
    const recomputed = segmentRoot({
      index: anchor.index,
      prevRoot: anchor.prevRoot,
      count: anchor.count,
      merkle: merkleForAnchor
    });
    expect(
      recomputed === anchor.root,
      `段 ${anchor.index} 的根摘要与锚点链不一致`,
      { segmentIndex: anchor.index, expected: anchor.root, actual: recomputed }
    );
    if (previousRoot !== undefined) {
      expect(
        anchor.prevRoot === previousRoot,
        `段 ${anchor.index} 的 prevRoot 没有接到前一段`,
        { segmentIndex: anchor.index }
      );
    }
    previousRoot = anchor.root;
  }

  expect(proof.headRoot === previousRoot, 'proof 的 headRoot 与锚点链末端不一致');

  if (trustedRoot !== undefined) {
    expect(
      trustedRoot === proof.headRoot,
      'headRoot 与外部可信 root 不一致，日志可能缺段或尾部被删除',
      { trustedRoot, actual: proof.headRoot }
    );
  }
  return true;
}

function normalizeProofRecord(record) {
  if (!record || typeof record !== 'object') {
    throw new AuditError(ErrorCode.INVALID_PROOF, 'proof.record 必须是对象');
  }
  let data = record.data;
  if (!Buffer.isBuffer(data)) {
    if (data && data.type === 'Buffer' && Array.isArray(data.data)) {
      data = Buffer.from(data.data);
    } else if (data instanceof Uint8Array) {
      data = Buffer.from(data);
    } else if (typeof data === 'string') {
      data = Buffer.from(data, 'base64');
    } else if (Array.isArray(data)) {
      data = Buffer.from(data);
    } else {
      throw new AuditError(ErrorCode.INVALID_PROOF, 'proof.record.data 不是可识别的字节表示');
    }
  }
  return { ...record, data };
}

export async function openIndex(directory, { allowGaps = false } = {}) {
  const { segments, headRoot } = await loadVerifiedSegments(directory);
  const issues = checkSequenceOrder(segments, { allowGaps });
  if (issues.length > 0) {
    throw new AuditError(
      issues[0].code,
      issues[0].message,
      { issues }
    );
  }
  return new AuditIndex(directory, segments, headRoot);
}

export async function auditLog(directory, { allowGaps = false } = {}) {
  const { files, gaps } = await listSegmentFiles(directory, { strict: false });
  const issues = [];
  const warnings = [];
  const segments = [];
  let prevRoot = ZERO_HASH;
  let uncommittedTail = false;

  for (const gap of gaps) {
    issues.push({
      code: ErrorCode.MISSING_SEGMENT,
      message: `缺少段序号 ${gap.missing}：段文件必须从 0 开始连续编号`,
      details: gap
    });
  }
  if (gaps.length > 0) {
    return finalizeAudit({ issues, warnings, segments, prevRoot, uncommittedTail });
  }

  for (let position = 0; position < files.length; position += 1) {
    const file = files[position];
    const isLast = position === files.length - 1;
    let buffer;
    try {
      buffer = await fs.readFile(file.path);
    } catch (cause) {
      issues.push({
        code: ErrorCode.CORRUPT_SEGMENT,
        message: `段文件无法读取: ${file.name}`,
        details: { segmentIndex: file.index, cause: cause.message }
      });
      continue;
    }

    let parsed;
    if (isLast) {
      try {
        const tolerant = parseTolerantTail(buffer, file.index);
        parsed = tolerant.parsed;
        if (tolerant.warning) {
          uncommittedTail = true;
          warnings.push(tolerant.warning);
        }
      } catch (error) {
        issues.push({
          code: error.code || ErrorCode.CORRUPT_SEGMENT,
          message: error.message,
          details: { ...error.details, segmentIndex: file.index }
        });
        break;
      }
    } else {
      try {
        parsed = parseSegment(buffer, { allowUncommitted: false });
      } catch (error) {
        issues.push({
          code: error.code || ErrorCode.CORRUPT_SEGMENT,
          message: error.message,
          details: { ...error.details, segmentIndex: file.index }
        });
        return finalizeAudit({ issues, warnings, segments, prevRoot, uncommittedTail });
      }
    }

    if (isLast && !parsed.committed) {
      break;
    }

    if (parsed.committed && parsed.index !== file.index) {
      issues.push({
        code: ErrorCode.CORRUPT_SEGMENT,
        message: '段文件序号与内部段头不一致',
        details: { filenameIndex: file.index, internalIndex: parsed.index }
      });
      continue;
    }

    try {
      const leafHashes = verifySegment(parsed, prevRoot);
      segments.push({ ...parsed, path: file.path, leafHashes });
      prevRoot = parsed.root;
    } catch (error) {
      issues.push({
        code: error.code || ErrorCode.CORRUPT_SEGMENT,
        message: error.message,
        details: { ...error.details, segmentIndex: file.index }
      });
      break;
    }
  }

  for (const issue of checkSequenceOrder(segments, { allowGaps })) {
    issues.push(issue);
  }

  return finalizeAudit({ issues, warnings, segments, prevRoot, uncommittedTail });
}

function finalizeAudit({ issues, warnings, segments, prevRoot, uncommittedTail }) {
  return {
    ok: issues.length === 0,
    headRoot: prevRoot,
    segmentCount: segments.length,
    recordCount: segments.reduce((total, segment) => total + segment.records.length, 0),
    hasUncommittedTail: uncommittedTail,
    issues,
    warnings
  };
}
