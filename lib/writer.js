import { promises as fs } from 'node:fs';
import {
  encodeCommit,
  encodeHeader,
  encodeRecordFrame,
  encodeRecordPayload,
  toBuffer,
  segmentPath
} from './codec.js';
import { ZERO_HASH, leafHash, merkleRoot, segmentRoot } from './crypto.js';
import { AuditError, ErrorCode } from './errors.js';
import { checkSequenceOrder, loadVerifiedSegments } from './store.js';

const DEFAULT_MAX_RECORDS = 1000;

export class AuditWriter {
  constructor(directory, { maxRecordsPerSegment = DEFAULT_MAX_RECORDS } = {}) {
    if (!Number.isInteger(maxRecordsPerSegment) || maxRecordsPerSegment <= 0) {
      throw new AuditError(
        ErrorCode.INVALID_RECORD,
        'maxRecordsPerSegment 必须是正整数',
        { maxRecordsPerSegment }
      );
    }
    this.directory = directory;
    this.maxRecordsPerSegment = maxRecordsPerSegment;
    this._closed = false;
    this._crashed = false;
    this._poisoned = false;
    this._handle = null;
    this._segmentIndex = 0;
    this._prevRoot = ZERO_HASH;
    this._pendingRecords = [];
    this._pendingHashes = [];
    this._committedCount = 0;
    this._lastSeq = null;
  }

  static async open(directory, options = {}) {
    await fs.mkdir(directory, { recursive: true });
    const writer = new AuditWriter(directory, options);
    const { segments, headRoot } = await loadVerifiedSegments(directory);

    const issues = checkSequenceOrder(segments, options);
    if (issues.length > 0) {
      throw new AuditError(issues[0].code, issues[0].message, { issues });
    }

    const tailPath = segmentPath(directory, segments.length);
    try {
      await fs.unlink(tailPath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    writer._prevRoot = headRoot;
    writer._segmentIndex = segments.length;
    if (segments.length > 0) {
      const lastSegment = segments[segments.length - 1];
      const lastRecord = lastSegment.records[lastSegment.records.length - 1];
      writer._lastSeq = lastRecord.seq;
    }
    return writer;
  }

  get headRoot() {
    return this._prevRoot;
  }

  get segmentCount() {
    return this._segmentIndex;
  }

  get recordCount() {
    return this._committedCount + this._pendingRecords.length;
  }

  get committedRecordCount() {
    return this._committedCount;
  }

  get pendingCount() {
    return this._pendingRecords.length;
  }

  get closed() {
    return this._closed;
  }

  async append(record) {
    if (this._closed) {
      throw new AuditError(
        ErrorCode.WRITER_CLOSED,
        this._crashed
          ? '写入器已因模拟崩溃而失效'
          : this._poisoned
            ? '写入器已因上一次写入失败而失效，请重新打开'
            : '写入器已经关闭'
      );
    }

    const normalized = normalizeRecord(record);
    const seq = normalized.seq;
    if (this._lastSeq !== null && seq <= this._lastSeq) {
      throw new AuditError(
        seq === this._lastSeq ? ErrorCode.SEQ_DUPLICATE : ErrorCode.SEQ_OUT_OF_ORDER,
        `序号 ${seq} 必须严格递增，当前最后一个序号为 ${this._lastSeq}`,
        { seq, lastSeq: this._lastSeq }
      );
    }

    if (this._pendingRecords.length >= this.maxRecordsPerSegment) {
      await this._sealSegment();
    }

    if (this._handle === null) {
      this._handle = await fs.open(
        segmentPath(this.directory, this._segmentIndex),
        'wx'
      );
      await this._handle.write(encodeHeader(this._segmentIndex));
    }

    const payload = encodeRecordPayload(normalized);
    const frame = encodeRecordFrame(normalized);
    try {
      await this._handle.write(frame);
    } catch (cause) {
      await this._poison(cause);
      throw cause;
    }

    this._pendingRecords.push(normalized);
    this._pendingHashes.push(leafHash(payload));
    this._lastSeq = seq;

    return {
      seq,
      committed: false,
      segmentIndex: this._segmentIndex,
      position: this._pendingRecords.length - 1
    };
  }

  async _poison(cause) {
    this._poisoned = true;
    this._closed = true;
    if (this._handle !== null) {
      try {
        await this._handle.close();
      } catch {
        // 关闭失败时底层描述符也不再可用，保持中毒状态即可
      }
      this._handle = null;
    }
    this._pendingRecords = [];
    this._pendingHashes = [];
    this._poisonCause = cause;
  }

  async _sealSegment() {
    if (this._handle === null || this._pendingRecords.length === 0) {
      return null;
    }

    const count = this._pendingRecords.length;
    const merkle = merkleRoot(this._pendingHashes);
    const root = segmentRoot({
      index: this._segmentIndex,
      prevRoot: this._prevRoot,
      count,
      merkle
    });
    const commit = encodeCommit({
      segmentIndex: this._segmentIndex,
      prevRoot: this._prevRoot,
      count,
      merkleRoot: merkle,
      segmentRoot: root
    });

    try {
      await this._handle.write(commit);
      await this._handle.sync();
      await this._handle.close();
    } catch (cause) {
      await this._poison(cause);
      throw cause;
    }
    this._handle = null;

    const sealed = {
      segmentIndex: this._segmentIndex,
      count,
      prevRoot: this._prevRoot,
      merkleRoot: merkle,
      root
    };

    this._prevRoot = root;
    this._segmentIndex += 1;
    this._committedCount += count;
    this._pendingRecords = [];
    this._pendingHashes = [];
    return sealed;
  }

  async commit() {
    if (this._closed) {
      throw new AuditError(ErrorCode.WRITER_CLOSED, '写入器已经关闭');
    }
    if (this._pendingRecords.length === 0) {
      return {
        committed: false,
        reason: 'NO_PENDING_RECORDS',
        headRoot: this._prevRoot,
        segmentIndex: this._segmentIndex,
        count: 0
      };
    }
    const sealed = await this._sealSegment();
    return {
      committed: true,
      segmentIndex: sealed.segmentIndex,
      count: sealed.count,
      merkleRoot: sealed.merkleRoot,
      prevRoot: sealed.prevRoot,
      root: sealed.root
    };
  }

  async simulateCrash() {
    if (this._handle !== null) {
      await this._handle.close();
      this._handle = null;
    }
    this._closed = true;
    this._crashed = true;
  }

  async close({ discardUncommitted = false } = {}) {
    if (this._closed) {
      return;
    }
    if (discardUncommitted && this._pendingRecords.length > 0) {
      if (this._handle !== null) {
        await this._handle.close();
        this._handle = null;
      }
      await fs.unlink(segmentPath(this.directory, this._segmentIndex));
    } else if (this._pendingRecords.length > 0) {
      await this._sealSegment();
    } else if (this._handle !== null) {
      await this._handle.close();
      this._handle = null;
    }
    this._closed = true;
  }
}

function normalizeRecord(record) {
  if (!record || typeof record !== 'object') {
    throw new AuditError(ErrorCode.INVALID_RECORD, '记录必须是对象');
  }
  const seq = Number(record.seq);
  const timestamp = Number(record.timestamp);
  if (!Number.isSafeInteger(seq) || seq < 0) {
    throw new AuditError(ErrorCode.INVALID_RECORD, 'seq 必须是非负安全整数', { seq: record.seq });
  }
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new AuditError(
      ErrorCode.INVALID_RECORD,
      'timestamp 必须是非负安全整数',
      { timestamp: record.timestamp }
    );
  }
  if (record.data === undefined || record.data === null) {
    throw new AuditError(ErrorCode.INVALID_RECORD, 'data 原始字节不能为空');
  }
  return {
    seq,
    timestamp,
    source: record.source === undefined || record.source === null ? '' : String(record.source),
    data: toBuffer(record.data, 'data')
  };
}
