import { promises as fs } from 'node:fs';
import { COMMIT_MAGIC, COMMIT_SIZE, parseSegment, parseSegmentFilename, segmentPath } from './codec.js';
import { ZERO_HASH, leafHash, merkleRoot, segmentRoot } from './crypto.js';
import { AuditError, ErrorCode } from './errors.js';

export async function listSegmentFiles(directory, { strict = true } = {}) {
  await fs.mkdir(directory, { recursive: true });
  const names = await fs.readdir(directory);
  const files = [];
  for (const name of names) {
    const index = parseSegmentFilename(name);
    if (index === null) {
      throw new AuditError(
        ErrorCode.UNEXPECTED_FILE,
        `目录中存在无法识别的文件: ${name}`,
        { file: name }
      );
    }
    files.push({ index, name, path: segmentPath(directory, index) });
  }
  files.sort((a, b) => a.index - b.index);
  const gaps = [];
  for (const [position, file] of files.entries()) {
    if (file.index !== position) {
      gaps.push({ missing: position, found: file.index });
      if (strict) {
        throw new AuditError(
          ErrorCode.MISSING_SEGMENT,
          `缺少段序号 ${position}：段文件必须从 0 开始连续编号`,
          { missing: position, found: file.index }
        );
      }
    }
  }
  return { files, gaps };
}

export function verifySegment(parsed, expectedPrevRoot) {
  const leafHashes = parsed.rawRecords.map((payload) => leafHash(payload));
  const computedMerkle = merkleRoot(leafHashes);
  if (computedMerkle !== parsed.merkleRoot) {
    throw new AuditError(
      ErrorCode.ROOT_MISMATCH,
      'Merkle 根与段内记录不一致，记录可能被删除、插入或替换',
      {
        segmentIndex: parsed.index,
        expected: parsed.merkleRoot,
        actual: computedMerkle
      }
    );
  }
  if (parsed.prevRoot !== expectedPrevRoot) {
    throw new AuditError(
      ErrorCode.ROOT_MISMATCH,
      '段头保存的前一段根摘要与实际链不一致（缺段、乱序或整段替换）',
      {
        segmentIndex: parsed.index,
        expected: expectedPrevRoot,
        actual: parsed.prevRoot
      }
    );
  }
  const computedRoot = segmentRoot({
    index: parsed.index,
    prevRoot: parsed.prevRoot,
    count: parsed.count,
    merkle: computedMerkle
  });
  if (computedRoot !== parsed.root) {
    throw new AuditError(
      ErrorCode.ROOT_MISMATCH,
      '段根摘要校验失败，提交尾可能被伪造',
      {
        segmentIndex: parsed.index,
        expected: parsed.root,
        actual: computedRoot
      }
    );
  }
  return leafHashes;
}

export async function loadVerifiedSegments(directory) {
  const { files } = await listSegmentFiles(directory, { strict: true });
  const segments = [];
  let prevRoot = ZERO_HASH;

  for (const [position, file] of files.entries()) {
    const isLast = position === files.length - 1;
    const buffer = await fs.readFile(file.path);
    let parsed;
    if (isLast) {
      parsed = parseTolerantTail(buffer, file.index).parsed;
    } else {
      parsed = parseSegment(buffer, { allowUncommitted: false });
    }
    if (!parsed.committed) {
      break;
    }
    if (parsed.index !== file.index) {
      throw new AuditError(
        ErrorCode.CORRUPT_SEGMENT,
        '段文件序号与内部段头不一致，段文件可能被重命名或替换',
        { filenameIndex: file.index, internalIndex: parsed.index }
      );
    }
    const leafHashes = verifySegment(parsed, prevRoot);
    segments.push({ ...parsed, path: file.path, leafHashes });
    prevRoot = parsed.root;
  }

  return { segments, headRoot: prevRoot };
}

export function parseTolerantTail(buffer, segmentIndex) {
  try {
    const parsed = parseSegment(buffer, { allowUncommitted: true });
    if (parsed.committed) {
      return { parsed, warning: null };
    }
    return {
      parsed,
      warning: {
        code: 'UNCOMMITTED_TAIL',
        message: `尾段 ${segmentIndex} 尚未提交，其中的数据未纳入索引`,
        details: { segmentIndex }
      }
    };
  } catch (error) {
    const hadCommitMagic = hasCommitFrame(buffer);
    if (hadCommitMagic) {
      throw error;
    }
    if (error instanceof AuditError && error.code === ErrorCode.CORRUPT_SEGMENT) {
      return {
        parsed: { committed: false, index: segmentIndex, records: [], rawRecords: [] },
        warning: {
          code: 'UNCOMMITTED_TAIL',
          message: `尾段 ${segmentIndex} 在提交前被截断（写入中断），其中的数据未纳入索引`,
          details: { segmentIndex, cause: error.message }
        }
      };
    }
    throw error;
  }
}

function hasCommitFrame(buffer) {
  return buffer.length >= COMMIT_SIZE
    && buffer.subarray(buffer.length - COMMIT_SIZE, buffer.length - COMMIT_SIZE + 4)
      .equals(COMMIT_MAGIC);
}

export function checkSequenceOrder(segments, { allowGaps = false } = {}) {
  const issues = [];
  let previous = null;

  for (const segment of segments) {
    for (let position = 0; position < segment.records.length; position += 1) {
      const record = segment.records[position];
      if (previous !== null) {
        if (record.seq === previous) {
          issues.push({
            code: ErrorCode.SEQ_DUPLICATE,
            message: `检测到重复序号 ${record.seq}`,
            details: { seq: record.seq, segmentIndex: segment.index, position }
          });
        } else if (record.seq < previous) {
          issues.push({
            code: ErrorCode.SEQ_OUT_OF_ORDER,
            message: `序号乱序：${record.seq} 出现在 ${previous} 之后`,
            details: { seq: record.seq, previous, segmentIndex: segment.index, position }
          });
        } else if (!allowGaps && record.seq !== previous + 1) {
          issues.push({
            code: ErrorCode.SEQ_GAP,
            message: `序号不连续：${previous} 之后应为 ${previous + 1}，实际为 ${record.seq}`,
            details: { expected: previous + 1, actual: record.seq, segmentIndex: segment.index }
          });
        }
      }
      previous = record.seq;
    }
  }

  return issues;
}
