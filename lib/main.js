export { AuditWriter } from './writer.js';
export {
  AuditIndex,
  auditLog,
  openIndex,
  parseProof,
  serializeProof,
  verifyProof
} from './index.js';
export { AuditError, ErrorCode } from './errors.js';
export {
  ZERO_HASH,
  leafHash,
  merkleProof,
  merkleRoot,
  sha256,
  segmentRoot,
  verifyMerkleProof
} from './crypto.js';
export {
  COMMIT_MAGIC,
  COMMIT_SIZE,
  HEADER_SIZE,
  RECORD_MAGIC,
  decodeRecordPayload,
  encodeRecordFrame,
  encodeRecordPayload,
  parseSegment,
  scanFrames,
  segmentPath
} from './codec.js';
