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
import socket
import stat
import sys
import time

from proto import *

_PTFTP_DEFAULT_PORT = 6969
_PTFTP_DEFAULT_HOST = 'localhost'
_PTFTP_DEFAULT_MODE = 'octet'

class TFTPClient:
    """
    A small and simple TFTP client to pull/push files from a TFTP server.
    """

    def __init__(self, peer, exts, mode):
        """
        Initializes the TFTP client.

        Args:
          peer (tuple): a (host, port) tuple describing the server to connect to.
          exts (boolean): trigger the use of the TFTP options extensions.
          mode (string): the transfer mode to use by default, must be one of
            TFTP_MODES.
        """

        self.peer = peer
        self.exts = exts
        self.transfer_mode = mode

        # TODO: handle TFTP extensions
        self.packetsize = TFTP_DEFAULT_PACKET_SIZE

    def serve_forever(self):
        """
        Serve the client prompt until the user exits the program.

        Args:
          None.
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print "Connected to %s:%d." % (self.peer[0], self.peer[1])

        while True:
            print
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
                break
            elif cmd_parts[0] in ('m', 'mode'):
                self.mode(cmd_parts[1:])
            else:
                print 'Unrecognized command. Try help.'

        self.sock.close()

    def usage(self):
        """
        Display the client help to the user.

        Args:
          None.
        """

        print 'Available commands:'
        print
        print '?  help             Display help'
        print '   get <filename>   Get <filename> from server'
        print '   put <filename>   Push <filename> to the server'
        print 'q  quit             Quit the TFTP client'
        print 'm  mode [newmode]   Display or change transfer mode'
        print

    def __receive_packet(self):
        """
        Receive a single UDP packet from the server.

        Args:
          None.
        Returns:
          A tuple (opcode, packet data) if the packet was received succesfully
          and valid, False otherwise.
        """

        data = self.sock.recv(UDP_TRANSFER_SIZE)
        if not len(data):
            data = self.sock.recv(UDP_TRANSFER_SIZE)

        if not len(data):
            print 'No data received.'
            self.__send_error(ERROR_UNDEF, 'No data received by client.')
            return False

        # Validate the packet
        opcode = TFTPHelper.getOP(data)
        if not opcode:
            print "Can't find packet opcode!"
            return False

        if not TFTP_OPS.has_key(opcode):
            print "Unknown or unsupported operation %d!" % opcode
            self.__send_error(ERROR_ILLEGAL_OP)
            return False

        return opcode, data[2:]

    def __send_error(self, errno, errmsg=None):
        """
        Creates and sends an error packet for the given error code.

        Args:
          errno (integer): the desired error code.
          errmsg (string): if the error code is 0, a specific error message
            can be attached to the error packet.
        """

        packet = TFTPHelper.createERROR(errno, errmsg)
        self.sock.sendto(packet, self.peer)

    def __receive(self, localfile):
        transfered = 0

        while True:
            ret = self.__receive_packet()
            if not ret:
                return False, 'Error receiving packet'

            opcode, packet = ret
            last = False

            if opcode == OP_DATA:
                num, data = TFTPHelper.parseDATA(packet)

                if len(data) < self.packetsize:
                    last = True

                # Convert CRLF to LF if needed
                if self.transfer_mode == 'netascii':
                    data = NETASCII_TO_OCTET.sub('\n', data)

                # Save the data chunk and ACK the data packet
                localfile.write(data)
                transfered += len(data)

                response = TFTPHelper.createACK(num)
                self.sock.sendto(response, self.peer)

                if last:
                    return True, transfered

            elif opcode == OP_ERROR:
                errno, errmsg = TFTPHelper.parseERROR(packet)
                return False, errmsg
            else:
                # Unexpected packet op-code
                print "Unexpected %s packet during transfer! Ignored." % TFTP_OPS[opcode]
                pass

    def get(self, args):
        """
        Implements the GET command to retrieve a file from the server.

        Args:
          args (list): the list of arguments passed to the command.
        Returns:
          True or False depending on the success of the operation.
        """

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

        packet = TFTPHelper.createRRQ(filepath, self.transfer_mode, {})

        self.sock.sendto(packet, self.peer)
        ret, info = self.__receive(localfile)

        if not ret:
            try:
                # Close and remove file
                localfile.close()
                os.remove(filename)
                print 'Transfer failed. Local file removed.'
            except OSError:
                print "Error while removing file %s!" % filename
                print 'Consider removing it manually.'

            return False

        print "  <  DATA: Transfer complete (%d bytes)." % info
        return True

    def put(self, args):
        """
        Implements the PUT command to push a file to the server.

        Args:
          args (list): the list of arguments passed to the command.
        Returns:
          True or False depending on the success of the operation.
        """

        if len(args) != 1:
            print 'Usage: put <filename>'
            return

        print "PUT %s" % args[0]

    def mode(self, args):
        if len(args) > 1:
            print 'Usage: mode [newmode]'
            return

        if not len(args):
            print "Current transfer mode: %s." % self.transfer_mode
            return

        if args[0].lower() in TFTP_MODES:
            self.transfer_mode = args[0].lower()
            print "Mode set to %s." % self.transfer_mode
        else:
            print 'Unknown transfer mode, use one of:', ', '.join(TFTP_MODES)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hd:p:r', ['help', 'host=', 'port=', 'rfc1350'])
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    host = _PTFTP_DEFAULT_HOST
    port = _PTFTP_DEFAULT_PORT
    exts = True

    for opt, val in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(0)
        if opt in ('-d', '--host'):
            host = val
        if opt in ('-p', '--port'):
            try:
                port = int(val)
            except ValueError:
                print 'Port must be a number!'
                sys.exit(2)
        if opt in ('-r', '--rfc1350'):
            exts = False

    try:
        client = TFTPClient((host, port), exts, _PTFTP_DEFAULT_MODE)
        client.serve_forever()
        print 'Goodbye.'
    except KeyboardInterrupt:
        print 'Got ^C. Exiting'
        sys.exit(0)
