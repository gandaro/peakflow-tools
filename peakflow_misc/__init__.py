# coding: utf-8

import base64
import sys
import urllib2

import pkg_resources
import requests

from pfpcap import PeakflowBrowser
from suds.client import Client
from suds.transport.https import HttpAuthenticated

ARBORWS = 'https://%s/arborws'

class PeakflowAPI(object):
    def __init__(self, host, username=None, password=None, api_key=None,
                 tms_ip=None):
        soap_url = 'https://%s/soap/sp' % host
        wsdl_url = 'file://%s' % pkg_resources.resource_filename(
            __name__, 'PeakflowSP.wsdl'
        )

        if username is None or password is None:
            self.client = None
        else:
            t = HttpAuthenticated(username=username, password=password)
            t.handler = urllib2.HTTPDigestAuthHandler(t.pm)
            t.urlopener = urllib2.build_opener(t.handler)
            self.client = Client(url=wsdl_url, location=soap_url, transport=t)

        self.host = host
        self.username = username
        self.password = password
        self.api_key = api_key
        self.tms_ip = tms_ip

        self._timeout = 10

    def cli_run(self, command):
        command = base64.b64encode(command)
        result = self.client.service.cliRun(command=command,
                                            timeout=self._timeout)
        return base64.b64decode(result)

    def download_pcap(self, mitigation_id, filename):
        pb = PeakflowBrowser(self.host, self.username, self.password)
        try:
            if not pb.start_flowcapture(mitigation_id, self.tms_ip):
                print >>sys.stderr, "error: Unable to start flow capture"
            while not pb.is_flowcapture_finished(mitigation_id, self.tms_ip):
                print "Flow capture not done...."
            print "Flow capture complete, downloading pcap..."
            pb.download_pcap(mitigation_id, self.tms_ip, filename)
        finally:
            pb.logout()

    def post(self, url, **parameters):
        data = {
            'api_key': self.api_key
        }
        data.update(parameters)
        # XXX: SSL certificate should be checked
        return requests.post(ARBORWS % self.host + url, verify=False,
                             data=data)
