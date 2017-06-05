import unittest
import boto3
from botocore.exceptions import ClientError
from scapy.error import Scapy_Exception

from inspect_pcap import handler

S3_PUT = {
    "Records": [{
        "eventVersion": "2.0",
        "eventTime": "1970-01-01T00:00:00.000Z",
        "requestParameters": {
            "sourceIPAddress": "127.0.0.1"
        },
        "s3": {
            "configurationId": "testConfigRule",
            "object": {
                "eTag": "0123456789abcdef0123456789abcdef",
                "sequencer": "0A1B2C3D4E5F678901",
                "key": "file.pcap",
                "size": 0
            },
            "bucket": {
                "arn": "arn:aws:s3:::mybucket",
                "name": "uploaded-pcaps",
                "ownerIdentity": {
                    "principalId": "EXAMPLE"
                }
            },
            "s3SchemaVersion": "1.0"
        },
        "responseElements": {
            "x-amz-id-2": "EXAMPLE123/5678abcdefghijklambdaisawesome/mnopqrstuvwxyzABCDEFGH",
            "x-amz-request-id": "EXAMPLE123456789"
        },
        "awsRegion": "us-east-1",
        "eventName": "ObjectCreated:Put",
        "userIdentity": {
            "principalId": "EXAMPLE"
        },
        "eventSource": "aws:s3"
    }]
}


class TestInspectPcap(unittest.TestCase):        

    def test_no_event(self):
        with self.assertRaises(TypeError):
            handler(event=None, context=None)

    def test_bad_event(self):
        with self.assertRaises(TypeError):
            handler(event='filename.pcap', context=None)

    def test_good_pcap(self):
        good_pcap = S3_PUT
        good_pcap['Records'][0]['s3']['object']['key'] = 'wget_google.pcap'
        handler(event=good_pcap, context=None)

    def test_nonexistant_pcap(self):
        nonexistant_pcap = S3_PUT
        nonexistant_pcap['Records'][0]['s3']['object']['key'] = 'nonexistant.pcap'
        with self.assertRaises(ClientError):
            handler(event=nonexistant_pcap, context=None)

    def test_not_pcap(self):
        not_pcap = S3_PUT
        not_pcap['Records'][0]['s3']['object']['key'] = 'firefox.exe'
        with self.assertRaises(Scapy_Exception):
            handler(event=not_pcap, context=None)

    def test_problem_mac_addresses(self):
        problem_macs = S3_PUT
        problem_macs['Records'][0]['s3']['object']['key'] = 'problem_mac_addresses.pcap'
        handler(event=problem_macs, context=None)


if __name__ == '__main__':
    unittest.main()
