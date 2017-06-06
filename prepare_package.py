#!/usr/bin/env python
from __future__ import print_function
import argparse
import os

parser = argparse.ArgumentParser(description='Prepares .ZIP archive for upload to AWS Lambda')

parser.add_argument('-r', action='store', dest='req_file',
    help='requirements.txt file', required=True)
parser.add_argument('-f', action='store', dest='func_file',
    help='function file', required=True)

args = parser.parse_args()
req_file = args.req_file
func_file = args.func_file
py_path = os.environ['VIRTUAL_ENV'] + '/lib/python2.7/site-packages/'
base_path = os.environ['PWD']
zip_filename = func_file.split('.')[0] + '.zip'
zip_file = base_path + '/' + zip_filename

print('Opening {}'.format(req_file))

modules = []

with open(req_file) as f:
    for line in f:
        module_name = line.strip('\n').split('==')[0]
        modules.append(module_name)
        print('Adding {} to the list of modules'.format(module_name))

os.chdir(py_path)

for module in modules:
    print('Adding {} to {}'.format(module, zip_file))
    os.system('zip -q -x "*.pyc" -r {} {}'.format(zip_file, module))

os.chdir(base_path)
print('Adding function file {} to {}'.format(func_file, zip_file))
os.system('zip -q -u {} {}'.format(zip_file, func_file))
