#!/usr/bin/env python
import argparse
import base64
import os
import re
import sys
import urllib2

import requests

from suds.client import Client
from suds.transport.https import HttpAuthenticated

class PeakflowApi(object):
    def __init__(self, host, username, password):
        soap_url = 'https://%s/soap/sp' % host
        wsdl_url = 'file://%s/PeakflowSP.wsdl' % os.path.dirname(os.path.abspath(__file__))

        t = HttpAuthenticated(username=username, password=password)
        t.handler = urllib2.HTTPDigestAuthHandler(t.pm)
        t.urlopener = urllib2.build_opener(t.handler)
        self.client = Client(url=wsdl_url, location=soap_url, transport=t)

        self._timeout = 10

    def cli_run(self, command):
        """ Run a command
        """
        command = base64.b64encode(command)
        result = self.client.service.cliRun(command=command, timeout=self._timeout)
        return base64.b64decode(result)

def arbor_post(url, hostname, api_key, **parameters):
    data = {
        'api_key': api_key
    }
    data.update(parameters)
    return requests.post('https://%s/arborws%s' % (hostname, url),
            verify=False, data=data)

def main():
    parser = argparse.ArgumentParser(description='rename auto-mitigations to a better name')
    parser.add_argument('host')
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('api_key')
    parser.add_argument('--limit', '-n', type=int, help='limit of queried mitigations', default=10)
    args = parser.parse_args()

    api = PeakflowApi(args.host, args.username, args.password)

    r = arbor_post('/mitigations/status', args.host, args.api_key,
            filter='auto-mitigation', limit=args.limit)

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
