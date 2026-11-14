"""Experimental paced byte transfer, without device access or authorization.

The caller pins the complete stream and device, owns the USB lock and durable
guard, and supplies the actual write callback. No chunk is retried or resumed
after an error. Successful writes prove host transport only, not a printout.
"""
import hashlib
import time

CHUNK_BYTES = 257
GAP_SECONDS = 0.05


def transmit(data, write_chunk, checkpoint, pause=time.sleep):
    if not isinstance(data, bytes) or not 0 < len(data) <= 16 * 1024 * 1024:
        raise ValueError('require one bounded immutable byte stream')
    count = 0
    for offset in range(0, len(data), CHUNK_BYTES):
        chunk = data[offset:offset + CHUNK_BYTES]
        record = {'offset': offset, 'requested_bytes': len(chunk),
                  'sha256': hashlib.sha256(chunk).hexdigest(),
                  'phase': 'write_attempt_started'}
        checkpoint(dict(record))
        try:
            rc, written = write_chunk(chunk)
        except Exception as error:
            record.update(phase='write_result_unknown', error=str(error))
            checkpoint(dict(record))
            raise
        record.update(rc=rc, written_bytes=written)
        if type(written) is not int or not 0 <= written <= len(chunk) or rc != 0 or written != len(chunk):
            record['phase'] = 'incomplete_no_retry'
            checkpoint(dict(record))
            raise RuntimeError('paced write incomplete; no retry or following chunk')
        record['phase'] = 'write_acknowledged'
        checkpoint(dict(record))
        count += written
        if offset + written < len(data):
            pause(GAP_SECONDS)
    return {'all_bytes_written': count == len(data), 'bytes': count,
            'stream_sha256': hashlib.sha256(data).hexdigest(),
            'chunk_bytes': CHUNK_BYTES, 'gap_seconds': GAP_SECONDS,
            'physical_printout_proven': False}
