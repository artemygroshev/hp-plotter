"""Experimental bounded reads with IN-only quiet phases after the final nonce.

No daemon or CLI. This preserves the fixed read-command whitelist and poisons
the session on incomplete writes. Separate complete 87-query LCD/status collections
passed with this policy; sustained reliability and arbitrary long text replies
remain unproved.
"""
import ctypes as C

from batch_usb import ReadSession
import probe_printer as probe


class QuietEndReadSession(ReadSession):
    def __init__(self, *args, **kwargs):
        if not {'command_payload', 'validate_reply'}.issubset(ReadSession.query.__code__.co_names):
            raise RuntimeError('quiet-end experiment requires matching transport hooks')
        if kwargs.pop('refresh_id_each_query', False) is not False:
            raise ValueError('this experiment uses identity only at session open')
        super().__init__(*args, refresh_id_each_query=False, **kwargs)

    def read_identity(self):
        for attempt in range(3):
            buf = C.create_string_buffer(1024)
            rc = self.control(self.handle, 0xa1, 0, 0, 1, buf, 1024, 5000)
            raw = buf.raw[:max(0, rc)]
            decoded = probe.parse_device_id(raw)
            self.controls.append({'operation': 'GET_DEVICE_ID', 'attempt': attempt,
                                  'rc': rc, 'decoded': decoded})
            if rc > 0 and decoded['hp_c7769b_identified']:
                return
            # Repeat empty control IN only. Reject foreign IDs and USB errors.
            if rc < 0 or any(raw):
                break
        raise RuntimeError('fresh HP identity not confirmed')

    def drain_payload(self, kind, response=b''):
        if self.queries:
            end = b'E' + self.queries[-1]['nonce'].encode('ascii') + b'\n'
            if response.endswith(end):
                # The parent still requires two actual quiet IN reads and
                # strict parsing; seeing an end marker alone is not success.
                return None
        return super().drain_payload(kind, response)
