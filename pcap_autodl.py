#!/usr/bin/env python
# Copyright (c) 2015 Jakob Kramer

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
    parser.add_argument('tmsip', help='TMS IP address')
    args = parser.parse_args()

    api = PeakflowAPI(args.host, args.username, args.password, args.apikey,
                      args.tmsip)
    r = api.post('/mitigations/status', filter='ongoing')

    for mitigation in r.json():
        # some mitigations don't have alert_ids
        if 'alert_id' not in mitigation.keys():
            continue
        alert = int(mitigation['alert_id'])
        path = os.path.join(args.pcapdir, '{}.pcap'.format(alert))
        # only download pcap if we don't have one already
        if os.path.exists(path):
            continue
        try:
            api.download_pcap(int(mitigation['id']), path)
        except Exception as e:
            print >>sys.stderr, 'failed downloading {}.pcap:'.format(alert), e

if __name__ == '__main__':
    main()
