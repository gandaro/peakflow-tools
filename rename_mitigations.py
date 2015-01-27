#!/usr/bin/env python
import argparse
import re
import sys

from peakflow_misc import PeakflowAPI

RENAME_COMMAND = 'services sp mitigation tms rename "%s" "%s"'

def rename_mitigation(api, old_name, new_name):
    sanitize = lambda s: s.replace('"', '').replace('\\', '\\\\')
    old_name = sanitize(old_name)
    new_name = sanitize(new_name)

    cmd = RENAME_COMMAND % (old_name, new_name)
    return api.cli_run(cmd)

def main():
    parser = argparse.ArgumentParser(description='rename auto-mitigations')
    parser.add_argument('host')
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('api_key')
    parser.add_argument('--limit', '-n', type=int,
            help='limit of queried mitigations', default=10)
    args = parser.parse_args()

    api = PeakflowAPI(args.host, args.username, args.password, args.api_key)
    r = api.post(
        '/mitigations/status',
        filter='auto-mitigation',
        limit=args.limit
    )
    for mitigation in r.json():
        if 'alert_id' not in mitigation.keys() or \
                'managed_object_name' not in mitigation.keys():
            continue

        old_name = mitigation['name']
        if re.match(r'^Alert \d+ Auto-Mitigation$', old_name) is None:
            continue

        alert_id = mitigation['alert_id']
        managed_object_name = mitigation['managed_object_name']
        managed_object_match = re.match(r'^(.+) \(\d+\)$', managed_object_name)
        managed_object_name = managed_object_match.group(1)

        new_name = '%s (%s)' % (managed_object_name, alert_id)
        result = rename_mitigation(api, old_name, new_name)
        if result != 'OK':
            print >>sys.stderr, 'CLI failed:', result
            return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
