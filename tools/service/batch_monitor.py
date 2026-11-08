"""Bounded monitor using one USB session per complete collection."""
import functools
import json
from pathlib import Path
import sys
import monitor
from batch_read import collect


def main():
    # Keep the existing settings/deadline/priority loop, with an explicit new
    # run/release identifier in the installation settings for this experiment.
    if len(sys.argv)!=3 or sys.argv[1]!='--settings':
        raise ValueError('use --settings /private/batch-monitor.json')
    settings=json.loads(Path(sys.argv[2]).read_text())
    extra=settings.get('include_diagnostics',False)
    if type(extra) is not bool:raise ValueError('include_diagnostics must be boolean')
    refresh=settings.get('refresh_id_each_query',False)
    if type(refresh) is not bool:raise ValueError('refresh_id_each_query must be boolean')
    comment=settings.get('comment_bytes',64)
    if type(comment) is not int or comment not in (63,64):raise ValueError('comment length must explicitly be 63 or 64')
    def batch_collect(cutoff):
        try:return collect(cutoff,'all',include_diagnostics=extra,refresh_id_each_query=refresh,comment_bytes=comment)
        except Exception as error:
            raise monitor.CycleFailure(getattr(error,'client',None),error) from error
    monitor.collect=batch_collect
    monitor.public_snapshot=functools.partial(monitor.public_snapshot,include_diagnostics=extra)
    monitor.main()


if __name__=='__main__':main()
