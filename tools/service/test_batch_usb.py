"""Session ownership, old replies and failure containment without real USB."""
import ctypes as C
import datetime as dt
import re
import unittest
from batch_usb import ReadSession,payload_for,probe
from quiet_end_reads import QuietEndReadSession


class Function:
    def __init__(self,callback):self.callback=callback
    def __call__(self,*args):return self.callback(*args)


class Fake:
    def __init__(self,scenario='ok'):
        self.scenario=scenario;self.alt=0;self.pending=b'';self.events=[];self.primary=0
        names=('init','exit','open_device_with_vid_pid','close','get_device','get_bus_number',
               'get_device_address','kernel_driver_active','claim_interface','release_interface',
               'set_interface_alt_setting','control_transfer','bulk_transfer')
        for name in names:setattr(self,'libusb_'+name,Function(getattr(self,name)))
    def init(self,ctx):ctx._obj.value=1;self.events.append('init');return 0
    def exit(self,*args):self.events.append('exit')
    def open_device_with_vid_pid(self,*args):self.events.append('open');return None if self.scenario=='no_device' else 10
    def close(self,*args):self.events.append('close')
    def get_device(self,*args):return 20
    def get_bus_number(self,*args):return 5
    def get_device_address(self,*args):return 2
    def kernel_driver_active(self,*args):return 0
    def claim_interface(self,*args):self.events.append('claim');return 0
    def release_interface(self,*args):self.events.append('release');self.alt=0;return 0
    def set_interface_alt_setting(self,handle,interface,value):
        self.events.append(('alt',value));self.alt=value
        return -6 if self.scenario=='restore_failure' and value==0 else 0
    def control_transfer(self,handle,bm,request,value,index,data,length,timeout):
        if (bm,request)==(0x81,10):data._obj.value=self.alt;return 1
        if (bm,request)==(0xa1,0):
            self.events.append('device_id')
            text=b'MANUFACTURER:Hewlett-Packard;MODEL:DesignJet 500 (C7769B);'
            raw=(len(text)+2).to_bytes(2,'big')+text
            C.memmove(data,raw,len(raw));return len(raw)
        raise AssertionError('unexpected control request')
    def bulk_transfer(self,handle,endpoint,data,length,count,timeout):
        count._obj.value=0
        if endpoint==1:
            raw=C.string_at(data,length);self.events.append(('out',length));count._obj.value=length
            if b'LANGUAGE=TCLWARE' in raw:
                self.primary+=1
                if self.scenario=='partial_second' and self.primary==2:
                    count._obj.value=8;return -7
                nonce=re.search(rb'puts B([a-f0-9]{6})\n',raw)[1]
                if self.scenario=='old_reply':nonce=b'ffffff'
                tag=b'F' if b'sysGetFwRevision' in raw else b'R'
                value=b'A.04.02' if tag==b'F' else b'0'
                self.pending=b'B'+nonce+b'\n'+tag+nonce+b'_'+value+b'\nE'+nonce+b'\n'
            return 0
        self.events.append('in')
        if self.pending:
            raw=self.pending[:length];self.pending=self.pending[length:]
            C.memmove(data,raw,len(raw));count._obj.value=len(raw);return 0
        return -7


class Clock:
    def __init__(self,step=.1):self.value=0;self.step=step
    def __call__(self):self.value+=self.step;return self.value


class SessionChecks(unittest.TestCase):
    def session(self,fake,clock=None,cls=ReadSession):
        nonces=iter(('111aaa','222bbb','333ccc'))
        return cls(5,2,dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),
                           lib=fake,alt_observer=lambda:fake.alt,now=clock or Clock(),
                           sleep=lambda _:None,nonce_factory=lambda:next(nonces))
    def test_quiet_end_uses_no_more_OUT_after_complete_reply(self):
        fake=Fake();session=self.session(fake,cls=QuietEndReadSession)
        with session:
            for kind in ('fw_info_tagged','telemetry_diag_busy'):
                reply=session.query(kind)
                self.assertTrue(reply['stream_closed'])
                self.assertEqual(reply['out_attempts'],1)
                self.assertEqual(len(reply['phases']),3)
                self.assertTrue(all(p['waiting_without_OUT'] for p in reply['phases'][1:]))
                self.assertTrue(all(p['reads'] for p in reply['phases']))
        self.assertEqual(fake.events.count('device_id'),1)
        self.assertTrue(session.cleanup_verified)

    def test_quiet_end_still_rejects_stale_nonce_and_poisoned_session(self):
        fake=Fake('old_reply');session=self.session(fake,cls=QuietEndReadSession)
        with session:
            with self.assertRaises(RuntimeError):session.query('fw_info_tagged')
            before=len(fake.events)
            with self.assertRaises(RuntimeError):session.query('telemetry_diag_busy')
            self.assertEqual(len(fake.events),before)
        self.assertTrue(session.poisoned);self.assertTrue(session.cleanup_verified)

    def test_quiet_end_never_replays_a_partial_command(self):
        fake=Fake('partial_second');session=self.session(fake,cls=QuietEndReadSession)
        with session:
            session.query('fw_info_tagged')
            with self.assertRaisesRegex(RuntimeError,'incomplete OUT'):session.query('telemetry_diag_busy')
            before=fake.primary
            with self.assertRaises(RuntimeError):session.query('telemetry_diag_busy')
            self.assertEqual(fake.primary,before)
        self.assertFalse(session.stream_closed);self.assertTrue(session.cleanup_verified)
    def test_short_comment_profile_keeps_every_OUT_off_the_64_byte_boundary(self):
        fake=Fake();session=self.session(fake);session.comment_bytes=63
        with session:reply=session.query('fw_info_tagged')
        self.assertEqual([p['written_bytes'] for p in reply['phases']],[129,63,63])
        self.assertEqual(reply['comment_bytes'],63)
        self.assertTrue(reply['stream_closed']);self.assertTrue(session.cleanup_verified)
        self.assertEqual(bytes.fromhex(reply['phases'][1]['payload_hex']),probe.make_drain_comment(63))
        for value in (True,62,65,'63'):
            with self.assertRaises(ValueError):
                ReadSession(5,2,dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),lib=Fake(),comment_bytes=value)
    def test_multiple_reads_share_one_handle_ID_and_alt_transition(self):
        fake=Fake();session=self.session(fake)
        with session:
            for kind in ('fw_info_tagged','telemetry_diag_busy','telemetry_diag_printing'):
                reply=session.query(kind)
                self.assertTrue(reply['stream_closed']);self.assertEqual(fake.alt,1)
                self.assertFalse(session.cleanup_verified)
                self.assertNotIn('release',fake.events)
        self.assertTrue(session.cleanup_verified)
        for event in ('init','open','claim','device_id','release','close','exit'):
            self.assertEqual(fake.events.count(event),1,event)
        self.assertEqual([x for x in fake.events if isinstance(x,tuple) and x[0]=='alt'],[('alt',1),('alt',0)])
    def test_partial_write_blocks_every_following_query_and_still_closes_USB(self):
        fake=Fake('partial_second');session=self.session(fake)
        with session:
            session.query('fw_info_tagged')
            with self.assertRaisesRegex(RuntimeError,'incomplete OUT'):
                session.query('telemetry_diag_busy')
            attempts=len(fake.events)
            with self.assertRaisesRegex(RuntimeError,'uncertain prior'):
                session.query('telemetry_diag_printing')
            self.assertEqual(len(fake.events),attempts)
        self.assertTrue(session.cleanup_verified);self.assertFalse(session.stream_closed)
        self.assertEqual(session.queries[-1]['out_attempts'],1)

    def test_optional_ID_refresh_does_not_reclaim_or_change_alt_between_queries(self):
        fake=Fake();session=self.session(fake);session.refresh_id_each_query=True
        with session:
            for kind in ('fw_info_tagged','telemetry_diag_busy','telemetry_diag_printing'):
                self.assertTrue(session.query(kind)['identity_refreshed'])
        self.assertEqual(fake.events.count('device_id'),3)
        self.assertEqual(fake.events.count('claim'),1)
        self.assertEqual([x for x in fake.events if isinstance(x,tuple) and x[0]=='alt'],[('alt',1),('alt',0)])
    def test_old_nonce_is_not_accepted_and_cannot_start_another_query(self):
        fake=Fake('old_reply');session=self.session(fake)
        with session:
            with self.assertRaises(RuntimeError):session.query('fw_info_tagged')
            self.assertTrue(session.poisoned);self.assertFalse(session.stream_closed)
        self.assertTrue(session.cleanup_verified)
    def test_restore_failure_is_not_claimed_as_cleanup(self):
        fake=Fake('restore_failure');session=self.session(fake)
        with session:session.query('fw_info_tagged')
        self.assertFalse(session.cleanup_verified)
        self.assertIn('release',fake.events);self.assertIn('close',fake.events)
    def test_no_device_can_release_a_no_OUT_guard_after_postflight(self):
        fake=Fake('no_device');session=self.session(fake)
        with self.assertRaisesRegex(RuntimeError,'adapter open failed'):
            with session:pass
        self.assertTrue(session.cleanup_verified);self.assertTrue(session.stream_closed)
        self.assertFalse(session.queries)
    def test_a_skipped_IN_cannot_count_as_a_quiet_phase(self):
        fake=Fake();session=self.session(fake,Clock(step=2))
        with session:
            with self.assertRaisesRegex(RuntimeError,'did not perform'):
                session.query('fw_info_tagged')
        self.assertFalse(session.stream_closed)
        self.assertEqual(session.queries[0]['out_attempts'],1)
    def test_fixed_and_memory_payloads_preserve_the_existing_wire_format(self):
        for kind in ('fw_info_tagged','telemetry_serial','telemetry_diag_intervention'):
            self.assertEqual(payload_for(kind,'012abc'),probe.make_small_read_query(kind,'012abc',129))
        for memory in ((0xa017d468,96),(0xa0540d08,128)):
            command=('osMemDump 0x%08x %d'%memory).encode()
            previous=probe.SMALL_READ_COMMANDS.get('runtime_mem')
            try:
                probe.SMALL_READ_COMMANDS['runtime_mem']=command
                self.assertEqual(payload_for('runtime_mem','012abc',memory),probe.make_small_read_query('runtime_mem','012abc',129))
            finally:
                if previous is None:probe.SMALL_READ_COMMANDS.pop('runtime_mem')
                else:probe.SMALL_READ_COMMANDS['runtime_mem']=previous
        for kind,memory in (('lcd_direct',None),('runtime_mem',(0,128)),('runtime_mem',(0xa0001000,129))):
            with self.assertRaises(ValueError):payload_for(kind,'012abc',memory)

    def test_invalid_wait_policy_stops_before_any_bulk_write(self):
        for limit,tick in ((2,None),(241,None),(True,None),('9',None),
                           (9,b'short'),(9,'x'*64)):
            with self.subTest(limit=limit,tick=tick):
                fake=Fake();session=self.session(fake)
                session.phase_limit=lambda kind:limit
                if tick is not None:session.drain_payload=lambda kind,response=b'':tick
                with session:
                    with self.assertRaises(ValueError):session.query('fw_info_tagged')
                self.assertFalse(any(isinstance(e,tuple) and e[0]=='out'
                                     for e in fake.events))
                self.assertTrue(session.cleanup_verified)


if __name__=='__main__':unittest.main()
