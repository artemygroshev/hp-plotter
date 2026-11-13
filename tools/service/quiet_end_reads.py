"""Experimental bounded reads with IN-only quiet phases after the final nonce.

No daemon or CLI. This preserves the fixed read-command whitelist and poisons
the session on incomplete writes. Six scalar reads passed with this policy;
long-running reliability and complete LCD/status collection remain unproved.
"""
from batch_usb import ReadSession


class QuietEndReadSession(ReadSession):
    def __init__(self, *args, **kwargs):
        if not {'command_payload', 'validate_reply'}.issubset(ReadSession.query.__code__.co_names):
            raise RuntimeError('quiet-end experiment requires matching transport hooks')
        if kwargs.pop('refresh_id_each_query', False) is not False:
            raise ValueError('this experiment uses identity only at session open')
        super().__init__(*args, refresh_id_each_query=False, **kwargs)

    def drain_payload(self, kind, response=b''):
        if self.queries:
            end = b'E' + self.queries[-1]['nonce'].encode('ascii') + b'\n'
            if response.endswith(end):
                # The parent still requires two actual quiet IN reads and
                # strict parsing; seeing an end marker alone is not success.
                return None
        return super().drain_payload(kind, response)
