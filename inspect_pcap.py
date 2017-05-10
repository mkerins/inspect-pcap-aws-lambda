from __future__ import print_function
import os
import urllib2

import boto3
from scapy.all import rdpcap, Ether  


def handler(event, context):  
    # Create a temporary file
    pcap_file = open('/tmp/temp.pcap', 'wb')

    # Download the PCAP from S3
    s3 = boto3.resource('s3')
    s3.Object('uploaded-pcaps', 'wget_google.pcap').download_file(
        pcap_file.name)
    pcap_file.close()

    # Load PCAP file
    pcap = rdpcap(pcap_file.name)

    mac_addresses = set()

    # Iterate over each packet in the PCAP file
    for pkt in pcap:
        # Get the source and destination MAC addresses
        src_mac = pkt.getlayer(Ether).src
        dst_mac = pkt.getlayer(Ether).dst
        # Add them to the set of MAC addresses
        mac_addresses.add(src_mac)
        mac_addresses.add(dst_mac)

    print('Found {} MAC addresses'.format(len(mac_addresses)))

    # Iterate over the set() of MAC addresses
    for mac in mac_addresses:
        # Attempt to look up the manufacturer
        try:
            resp = urllib2.urlopen('http://api.macvendors.com/{}'.format(mac))
            if resp.getcode() == 200:
                vendor_str = resp.readline()
                print('{} is a {} network interface'.format(mac, vendor_str))
        # Handle not found queries
        except urllib2.HTTPError:
            print('The manufacturer for {} was not found'.format(mac))
            continue

    # Delete the temporary file
    os.remove(pcap_file.name)

if __name__ == '__main__':  
    handler(event=None, context=None)
