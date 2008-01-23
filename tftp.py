#!/usr/bin/env python

# Author:     Maxime Petazzoni
#             maxime.petazzoni@bulix.org
#
# This file is part of pTFTPd.
#
# pTFTPd is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pTFTPd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pTFTPd.  If not, see <http://www.gnu.org/licenses/>.


"""Simple TFTP client.

This is a very simple TFTP client that supports pull/push files from a
TFTP server. Support for the TFTP Option Extension protocol is
currently a work in progress.
"""

import errno
import getopt
import os
import re
import socket
import stat
import sys

from proto import *

_PTFTP_DEFAULT_PORT = 6969
_PTFTP_DEFAULT_HOST = 'localhost'

_port = _PTFTP_DEFAULT_PORT
_host = _PTFTP_DEFAULT_HOST
_tftp_exts = True


class TFTPClient:
    def __init__(self, peer):
        self.peer = peer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.serve = True
        self.mode = 'netascii'

        self.packetsize = TFTP_DEFAULT_PACKET_SIZE

    def serve_forever(self):
        print "Connected to %s:%d." % (self.peer[0], self.peer[1])

        while self.serve:
            command = raw_input('tftp> ')
            if not command:
                continue

            cmd_parts = command.split(' ')
            if cmd_parts[0] in ('?', 'help'):
                self.usage()
            elif cmd_parts[0] == 'get':
                self.get(cmd_parts[1:])
            elif cmd_parts[0] == 'put':
                self.put(cmd_parts[1:])
            elif cmd_parts[0] in ('q', 'quit'):
                self.serve = False
            else:
                print 'Unrecognized command. Try help.'

    def usage(self):
        print 'Available commands:'
        print
        print '?  help             Display help'
        print '   get <filename>   Get <filename> from server'
        print '   put <filename>   Push <filename> to the server'
        print 'q  quit             Quit the TFTP client'
        print

    def receive(self, localfile):
        transfered = 0

        while True:
            err = self.receive_packet()
            if not err:
                print 'Error receiving packet'
                return -1

            opcode, packet = err

            if opcode == OP_DATA:
                num, data = TFTPHelper.parseDATA(packet)

                # Convert CRLF to LF if needed
                if self.mode == 'netascii':
                    data = re.sub('\r\n', '\n', data)

                # Save the data chunk and ACK the data packet
                localfile.write(data)
                transfered += len(data)

                response = TFTPHelper.createACK(num)
                self.sock.sendto(response, self.peer)

                if len(data) < self.packetsize:
                    return transfered

            elif opcode == OP_ERROR:
                errno, errmsg = TFTPHelper.parseERROR(packet)
                print "Error code %d: %s" % (errno, errmsg)
                return -1
            else:
                # Unexpected packet op-code
                print "Unexpected %s packet during transfer! Ignored." % TFTP_OPS[opcode]
                pass

    def receive_packet(self):
        data, addr = self.sock.recvfrom(8192)

        print [ord(i) for i in data]
        opcode = TFTPHelper.getOP(data)
        if not opcode:
            print "Can't find packet opcode!"
            return False
        if not TFTP_OPS.has_key(opcode):
            print "Unknown or unsupported operation %d!" % opcode
            self.send_error(ERROR_ILLEGAL_OP)
            return False

        print opcode

        return opcode, data[2:]

    def send_error(self, errno):
        packet = TFTPHelper.createERROR(errno)
        self.sock.sendto(packet, self.peer)

    def get(self, args):
        if len(args) != 1:
            print 'Usage: get <filename>'
            return False

        filepath = args[0]
        filename = filepath.split('/')
        filename = filename[len(filename)-1]

        # First, check we're not going to overwrite an existing file
        try:
            open(filename)
            print "Error: local file %s already exists!" % filename
            return False
        except IOError:
            pass

        # Then, before sending anything to the server, open the file
        # for writing
        try:
            localfile = open(filename, "w")
        except IOError, e:
            print "Error: %s" % errno.errorcodes[e.errno]
            print "Can't open local file %s for writing!" % filename
            return False

        packet = TFTPHelper.createRRQ(filepath, self.mode, {})

        self.sock.sendto(packet, self.peer)
        size = self.receive(localfile)

        if size < 0:
            try:
                # Close and remove file
                localfile.close()
                os.remove(filename)
                print "Transfer failed, please retry."
            except OSError:
                print "Error while removing file %s!" % filename
                print "Consider removing it manually."

            return False

        print "Transfer done (%d bytes)." % size
        return True

    def put(self, args):
        if len(args) != 1:
            print 'Usage: put <filename>'
            return

        print "PUT %s" % args[0]


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hd:p:r', ['help', 'host=', 'port=', 'rfc1350'])
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    for opt, val in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(0)
        if opt in ('-d', '--host'):
            _host = val
        if opt in ('-p', '--port'):
            try:
                _port = int(val)
            except ValueError:
                print 'Port must be a number!'
                sys.exit(2)
        if opt in ('-r', '--rfc1350'):
            _tftp_exts = False

    try:
        client = TFTPClient((_host, _port))
        client.serve_forever()
        print 'Goodbye.'
    except KeyboardInterrupt:
        print 'Got ^C. Exiting'
