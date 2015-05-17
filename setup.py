from setuptools import setup

setup(
    name='peakflow-tools',
    version='0.1.2',
    include_package_data=True,
    scripts=['pcap_autodl.py', 'rename_mitigations.py'],
    packages=['peakflow_misc'],
    install_requires=['suds>=0.4', 'requests>=2.5.1', 'pfpcap>=0.1'],
    dependency_links=[
        'git+https://github.com/gandaro/peakflow-pcap.git@master#egg=pfpcap-0.1'
    ],
    author='Jakob Kramer',
    autor_email='jakob.kramer@gmx.de',
    license='MIT'
)
