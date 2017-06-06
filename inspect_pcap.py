from __future__ import print_function
import json
import os
import urllib
import urllib2

import boto3
from botocore.exceptions import ClientError
from scapy.all import rdpcap, Ether  
from scapy.error import Scapy_Exception

TEMP_FILE = '/tmp/temp.pcap'
MAX_SIZE = 1024**2


def handler(event, context):
    # Check to see an event of type dict was received
    if event is None or type(event) is not dict:
        print('No event received or event is improperly formatted')
        raise TypeError
    # Log the event
    print('Received event: {}'.format(json.dumps(event)))

    # Extract the bucket and key (from AWS 's3-get-object-python' example)
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key'].encode('utf8'))
    size = event['Records'][0]['s3']['object']['size']

    if size > MAX_SIZE:
        print('PCAP file {} is too big ({} > {})'.format(key, size, MAX_SIZE))
        raise Exception

    try:
        # Create a temporary file
        pcap_file = open(TEMP_FILE, 'wb')
        # Download the PCAP from S3
        s3 = boto3.resource('s3')
        s3.Object(bucket, key).download_file(
            pcap_file.name)
        pcap_file.close()
    except ClientError:
        print('Error getting object {} from the {} bucket'.format(key, bucket))
        os.remove(TEMP_FILE)
        raise

    # Load PCAP file
    try:
        pcap = rdpcap(pcap_file.name)
    except Scapy_Exception:
        print('{} is not a valid PCAP file'.format(key))
        os.remove(TEMP_FILE)
        raise

    mac_addresses = set()

    # Iterate over each packet in the PCAP file
    for pkt in pcap:
        try:
            # Get the source and destination MAC addresses
            src_mac = pkt.getlayer(Ether).src
            dst_mac = pkt.getlayer(Ether).dst
            # Add them to the set of MAC addresses
            mac_addresses.add(src_mac)
            mac_addresses.add(dst_mac)
        except:
            print('Could not extract MAC addresses')
            continue

    print('Found {} MAC addresses'.format(len(mac_addresses)))

    known_ouis = {}

    # Iterate over the set() of MAC addresses
    for mac in mac_addresses:
        # Get the first 24 bits (aka the OUI) of the mac address
        oui = mac[0:8]
        # Check if we've already looked up this OUI
        if oui in known_ouis:
            print('{} -> {}*'.format(mac, known_ouis[oui]))
            continue
        # Attempt to look up the manufacturer
        try:
            resp = urllib2.urlopen('http://api.macvendors.com/{}'.format(mac))
            if resp.getcode() == 200:
                vendor_str = resp.readline()
                # Add this to our dict of known OUIs
                known_ouis[oui] = vendor_str
                print('{} -> {}'.format(mac, vendor_str))
        # Handle not found queries
        except urllib2.HTTPError:
            # Add the 'Unknown' OUI
            known_ouis[oui] = 'Unknown'
            print('{} -> {}'.format(mac, known_ouis[oui]))
