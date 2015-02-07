"""
    peakflow_misc
    ~~~~~~~~~~~~~

    Provides a class for easy programmatic access to Peakflow.

    :copyright: (c) 2015 by the developers
    :license: MIT, see LICENSE for more details.
"""

import base64
import sys
import time
import urllib2

import pkg_resources
import requests

from pfpcap import PeakflowBrowser
from suds.client import Client
from suds.transport.https import HttpAuthenticated

ARBORWS = 'https://{}/arborws/{}'

class PeakflowAPI(object):
    """Python interface to several Arbor APIs.

    This class can be used to run CLI commands using
    the SOAP API, to capture packets for a mitigation,
    and to send requests to the Web Services API.
    """

    def __init__(self, host, username=None, password=None, api_key=None,
                 tms_ip=None):
        """Inits PeakflowAPI with API credentials and hostname.

        Args:
            host: The hostname of the Arbor instance, for example
                'arbor.example.com'.
            username: (Optional) Username for SOAP API and accessing
                the web interface for .pcap download.  This is needed
                for the download_pcap and cli_run methods.
            password: (Optional) Password for this username.
            api_key: (Optional) API key for Web Services API.  This is
                needed for calls to the post method.
            tms_ip: (Optional) Hostname of the TMS that shall capture
                the packets.  Needed for download_pcap.
        """
        soap_url = 'https://{}/soap/sp'.format(host)
        wsdl_url = 'file://{}'.format(
            pkg_resources.resource_filename(__name__, 'PeakflowSP.wsdl')
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
        """Run a command on the Arbor CLI.

        Args:
            command: The command to be run.

        Returns:
            The string that is being returned by the SOAP API.

        Example:
            >>> api.cli_run('foo bar baz')
            'OK'
        """
        if self.client is None:
            raise RunTimeError('credentials for SOAP API are missing')
        command = base64.b64encode(command)
        result = self.client.service.cliRun(command=command,
                                            timeout=self._timeout)
        return base64.b64decode(result)

    def download_pcap(self, mitigation_id, filename):
        """Capture packets and download them to a .pcap file.

        Args:
            mitigation_id: The ID of the mitigation that you want to
                capture packets from.
            filename: The name of the file you want to download the
                .pcap file to.

        Example:
            >>> api.download_pcap(1234, 'foo.pcap')
        """
        if self.username is None or self.password is None:
            raise RunTimeError('credentials for pcap downloading are missing')
        pb = PeakflowBrowser(self.host, self.username, self.password)
        try:
            pb.start_flowcapture(mitigation_id, self.tms_ip)
            while not pb.is_flowcapture_finished(mitigation_id, self.tms_ip):
                time.sleep(0.5)
            return pb.download_pcap(mitigation_id, self.tms_ip, filename)
        finally:
            pb.logout()

    def post(self, url, **parameters):
        """Send an HTTP POST request to the Arbor Web Services API.

        Args:
            url: The part of the API url after the /arborws.
            **parameters: Any parameters that the API accepts are
                also accepted as keyword arguments.

        Returns:
            A requests.Response object for the POST request.

        Example:
            >>> api.post('/mitigations/status', filter='ongoing', limit=10)
        """
        if self.api_key is None:
            raise RunTimeError('API key is missing')
        data = {
            'api_key': self.api_key
        }
        data.update(parameters)
        # XXX: SSL certificate should be checked
        return requests.post(ARBORWS.format(self.host, url), verify=False,
                             data=data)
