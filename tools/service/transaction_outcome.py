"""Decide whether a completed report permits a later independent query.

Zero attempted Bulk OUT plus verified restoration is different from a partial
or failed write. Neither condition authorizes replay of that failed write.
"""


def safely_closed(report,kind=None):
    if report.get('no_usb_started') is True:return 'transport' not in report
    if (report.get('no_query_started') is True and report.get('no_bulk_out_attempted') is True
            and report.get('idle_preparation',{}).get('idle_verified') is True):return 'transport' not in report
    transport=report.get('transport',{})
    if (report.get('cleanup',{}).get('usb_restored',report.get('cleanup',{}).get('verified')) is not True
            or transport.get('cleanup_verified') is not True):return False
    if type(transport.get('write_attempts')) is int and transport['write_attempts']==0:
        return type(transport.get('written_bytes')) is int and transport['written_bytes']==0
    return (transport.get('write_completed') is True
            and (transport.get('small_stopped_after_end_and_two_quiet_phases') is True
                 or (kind=='echo' and report.get('fresh_echo_received') is True)))
