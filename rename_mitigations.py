#!/usr/bin/env python
import argparse
import re
import sys

from peakflow_misc import PeakflowAPI

def main():
    parser = argparse.ArgumentParser(description='rename auto-mitigations to a better name')
    parser.add_argument('host')
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('api_key')
    parser.add_argument('--limit', '-n', type=int, help='limit of queried mitigations', default=10)
    args = parser.parse_args()

    api = PeakflowAPI(args.host, args.username, args.password, args.api_key)
    r = api.post('/mitigations/status', filter='auto-mitigation', limit=args.limit)

    for m in r.json():
        if 'alert_id' not in m.keys() or 'managed_object_name' not in m.keys():
            continue
        if re.match(r'^Alert \d+ Auto-Mitigation$', m['name']) is None:
            continue
        mo_match = re.match(r'^(.+) \(\d+\)$', m['managed_object_name'])
        mo_name = mo_match.group(1)
        command = 'services sp mitigation tms rename "%s" "%s (%s)"' % (m['name'], mo_name, m['alert_id'])
        result = api.cli_run(command)
        if result != 'OK':
            print >>sys.stderr, 'arbor says:', result
            return 1

if __name__ == '__main__':
    sys.exit(main())
