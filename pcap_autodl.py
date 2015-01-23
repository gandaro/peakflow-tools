#!/usr/bin/env python
import argparse
import os
import sys

import requests

from pfpcap import PeakflowBrowser

ARBORWS = 'https://%s/arborws'

def download_pcap(host, username, password, tms_ip, mitigation_id, filename):
    pb = PeakflowBrowser(host, username, password)
    try:
        if not pb.start_flowcapture(mitigation_id, tms_ip):
            print >>sys.stderr, "error: Unable to start flow capture"
        while not pb.is_flowcapture_finished(mitigation_id, tms_ip):
            print "Flow capture not done...."
        print "Flow capture complete, downloading pcap..."
        pb.download_pcap(mitigation_id, tms_ip, filename)
    finally:
        pb.logout()

def arbor_post(url, hostname, api_key, **parameters):
    data = {
        'api_key': api_key
    }
    data.update(parameters)
    # XXX: SSL certificate should be checked
    return requests.post(ARBORWS % hostname + url, verify=False, data=data)

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

    r = arbor_post('/mitigations/status', args.host, args.apikey, filter='ongoing')

    for m in r.json():
        if 'alert_id' not in m.keys():
            continue
        alert = int(m['alert_id'])
        path = os.path.join(args.pcapdir, '%d.pcap' % alert)
        if os.path.exists(path):
            continue
        try:
            download_pcap(args.host, args.username, args.password,
                    args.tmsip, int(m['id']), path)
        except Exception as e:
            print >>sys.stderr, 'failed downloading %d.pcap: ' % alert, e

if __name__ == '__main__':
    main()
