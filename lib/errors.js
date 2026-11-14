export const ErrorCode = Object.freeze({
  INVALID_RECORD: 'INVALID_RECORD',
  NOT_FOUND: 'NOT_FOUND',
  CORRUPT_SEGMENT: 'CORRUPT_SEGMENT',
  UNEXPECTED_FILE: 'UNEXPECTED_FILE',
  MISSING_SEGMENT: 'MISSING_SEGMENT',
  ROOT_MISMATCH: 'ROOT_MISMATCH',
  PROOF_MISMATCH: 'PROOF_MISMATCH',
  INVALID_PROOF: 'INVALID_PROOF',
  SEQ_DUPLICATE: 'SEQ_DUPLICATE',
  SEQ_OUT_OF_ORDER: 'SEQ_OUT_OF_ORDER',
  SEQ_GAP: 'SEQ_GAP',
  WRITER_CLOSED: 'WRITER_CLOSED'
});

export class AuditError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'AuditError';
    this.code = code;
    this.details = details;
  }
}
