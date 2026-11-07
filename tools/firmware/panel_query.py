"""One bounded screen-read candidate using the A.04.02 TCLWARE path.

No arbitrary scripts, panel ownership, button simulation, printing, flash or
configuration commands. Default is preview. Transport success is not a frame.
"""
import argparse
import base64
import json
import re
import secrets
import probe_printer as probe


def make_query(nonce):
    if not re.fullmatch(r'[A-Za-z0-9]{8,64}', nonce):
        raise ValueError('nonce must be 8..64 ASCII alphanumeric characters')
    script = (
        'puts BTT_LCD_BEGIN_'+nonce+'\n'
        'if {[llength [info commands fpDumpDisplay]]} {fpDumpDisplay BMP} '
        'else {puts BTT_LCD_UNAVAILABLE_'+nonce+'}\n'
        'puts BTT_LCD_END_'+nonce+'\n'
        'flush stdout\n'
        'exit 0\n'
    ).encode('ascii')
    return (probe.UEL+b'@PJL ENTER LANGUAGE=TCLWARE\r\n'+script+probe.UEL), script


def frame_body(raw, nonce):
    begin=b'BTT_LCD_BEGIN_'+nonce.encode('ascii')
    end=b'BTT_LCD_END_'+nonce.encode('ascii')
    # Require standalone printed markers, not source lines echoed by a bridge.
    left=re.search(rb'(?:\A|[\r\n])'+re.escape(begin)+rb'\r?\n',raw)
    if not left: raise ValueError('begin marker missing')
    right=re.search(rb'(?:\A|[\r\n])('+re.escape(end)+rb')\r?\n',raw[left.end():])
    if not right: raise ValueError('end marker missing')
    # Preserve any boundary newline: it can be the final binary pixel byte.
    return raw[left.end():left.end()+right.start(1)]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--send',action='store_true')
    parser.add_argument('--panel-observed',choices=('ready','replace-ink-cartridges'))
    parser.add_argument('--prime-device-id',action='store_true',
                        help='read IEEE-1284 ID first, as the CUPS USB backend does')
    args=parser.parse_args()
    if args.send and not args.panel_observed:
        parser.error('observe the idle panel before sending')
    nonce=secrets.token_hex(8);payload,script=make_query(nonce)
    result={'query':'one_LCD_BMP_via_TCLWARE','nonce':nonce,
            'payload_bytes':len(payload),'payload_base64':base64.b64encode(payload).decode(),
            'sent':False,'reply_markers_verified':False,'screen_received':False}
    if args.send:
        result['panel_observation']=args.panel_observed
        try:
            bus,address=probe.discover()
            transport=probe.transact(payload,bus,address,concurrent_read=True,read_seconds=10,
                                     prime_device_id=args.prime_device_id)
            result['transport']=transport
            result['sent']=transport['written_bytes']>0
            result['transport_clean']=(transport['write_completed'] and transport['cleanup_verified']
                                       and not transport.get('error') and not transport.get('read_error'))
            raw=base64.b64decode(transport['received_base64'])
            try:
                body=frame_body(raw,nonce)
                result['reply_markers_verified']=True
                result['frame_body_base64']=base64.b64encode(body).decode()
            except ValueError as e:
                result['frame_error']=str(e)
            # Decoding/validation and physical freshness confirmation happen on PC20.
        except Exception as e:
            result['error']=str(e)
    print(json.dumps(result,indent=2))


if __name__=='__main__': main()
