from setuptools import setup, find_packages

setup(
    name='peakflow-tools',
    version='0.1',
    package_data={
        '': ['PeakflowSP.wsdl']
    },
    scripts=['pcap_autodl.py', 'rename_mitigations.py'],
    install_requires=['suds>=0.4', 'requests>=2.5.1', 'pfpcap>=0.1'],
    dependency_links=[
        'https://github.com/gandaro/peakflow-pcap.git'
    ]
)
