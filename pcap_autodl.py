#!/usr/bin/env python
import argparse
import os
import sys

from peakflow_misc import PeakflowAPI

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcapdir', help='directory to store .pcap files in')
    parser.add_argument('host', help='Arbor hostname')
    parser.add_argument('username', help='username for downloading .pcap')
    parser.add_argument('password', help='password for downloading .pcap')
    parser.add_argument('apikey', help='Web API key')
    # /arborws/admin/tms
    parser.add_argument('tmsip', help='TMS IP address')
    args = parser.parse_args()

    api = PeakflowAPI(args.host, args.username, args.password, args.apikey, args.tmsip)
    r = api.post('/mitigations/status', filter='ongoing')

    for m in r.json():
        if 'alert_id' not in m.keys():
            continue
        alert = int(m['alert_id'])
        path = os.path.join(args.pcapdir, '%d.pcap' % alert)
        if os.path.exists(path):
            continue
        try:
            api.download_pcap(int(m['id']), path)
        except Exception as e:
            print >>sys.stderr, 'failed downloading %d.pcap: ' % alert, e

if __name__ == '__main__':
    main()
