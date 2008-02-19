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

"""TFTP Server.

pTFTPd is a simple TFTP daemon written in Python. It fully supports
the TFTP specification as defined in RFC1350. It also supports the
TFTP Option Extension protocol (per RFC2347), although the specific
options themselves are not yet supported (RFC2348 and RFC2349).
"""

from datetime import datetime
from datetime import timedelta
import errno
import getopt
import os
import stat
import struct
import sys
import SocketServer
import threading
import time

from proto import *
from state import *

_PTFTPD_SERVER_NAME = 'pFTPd'
_PTFTPD_DEFAULT_PORT = 6969
_PTFTPD_DEFAULT_PATH = '/tftpboot'

_port = _PTFTPD_DEFAULT_PORT
_path = _PTFTPD_DEFAULT_PATH

class TFTPServerHandler(SocketServer.DatagramRequestHandler):
    """
    The SocketServer UDP datagram handler for the TFTP protocol.
    """

    def handle(self):
        """
        Handles an incoming request by unpacking the TFTP opcode and
        dispatching to one of the serve* method of this class.
        """

        request = self.rfile.read()
        response = None

        # Get the packet opcode and dispatch
        try:
            opn = struct.unpack('!h', request[:2])[0]
            op = TFTP_OPS[opn]
            response = getattr(self, "serve%s" % op)(opn, request[2:])
        except KeyError:
            print "Unknown operation %d!" % opn
            response = TFTPHelper.createERROR(ERROR_ILLEGAL_OP)
        except AttributeError:
            print "Unsupported operation %s!" % op
            response = TFTPHelper.createERROR(ERROR_UNDEF,
                                              'Operation not supported by server.')

        if response:
            self.wfile.write(response)
            self.wfile.flush()

    def serveRRQ(self, op, request):
        """
        Serves RRQ packets (GET requests).

        Args:
          op: the TFTP opcode (int).
          request: the TFTP packet without its opcode (string).
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            filename, mode, opts = TFTPHelper.parseRRQ(request)
        except SyntaxError:
            # Ignore malformed RRQ requests
            return None

        peer_state = TFTPState(self.client_address, op, filename, mode, opts)

        try:
            peer_state.file = open(os.path.join(_path, filename))
            peer_state.packetnum = 0
            peer_state.state = 'send'
        except IOError, e:
            peer_state.state = 'error'

            if e.errno == errno.ENOENT:
                peer_state.error = ERROR_FILE_NOT_FOUND
            elif e.errno == errno.EACCES or e.errno == errno.EPERM:
                peer_state.error = ERROR_ACCESS_VIOLATION
            else:
                peer_state.error = ERROR_UNDEF

        PTFTPD_STATE[self.client_address] = peer_state
        return peer_state.next()

    def serveWRQ(self, op, request):
        """
        Serves WRQ packets (PUT requests).

        Args:
          op: the TFTP opcode (int).
          request: the TFTP packet without its opcode (string).
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            filename, mode, opts = TFTPHelper.parseWRQ(request)
        except SyntaxError:
            # Ignore malfored WRQ requests
            return None

        peer_state = TFTPState(self.client_address, op, filename, mode, opts)

        path = os.path.join(_path, filename)
        try:
            # Try to open the file. If it succeeds, it means the file
            # already exists and report the error
            peer_state.file = open(path)
            peer_state.state = 'error'
            peer_state.error = ERROR_FILE_ALREADY_EXISTS
        except IOError, e:
            # Otherwise, if the open failed because the file did not
            # exist, create it and start receiving data
            if e.errno == errno.ENOENT:
                try:
                    peer_state.file = open(path, 'w')
                    peer_state.packetnum = 0
                    peer_state.state = 'recv'
                except IOError:
                    peer_state.state = 'error'
                    peer_state.error = ERROR_ACCESS_VIOLATION
            else:
                peer_state.state = 'error'
                peer_state.error = ERROR_ACCESS_VIOLATION

        PTFTPD_STATE[self.client_address] = peer_state
        return peer_state.next()

    def serveACK(self, op, request):
        """
		Serves ACK packets.

        Args:
          op: the TFTP opcode (int).
          request: the TFTP packet without its opcode (string).
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            num = TFTPHelper.parseACK(request)
        except SyntaxError:
            # Ignore malfored ACK packets
            return None

        try:
            peer_state = PTFTPD_STATE[self.client_address]
        except KeyError:
            peer_state = TFTPState(self.client_address, op, None, None, None)
            peer_state.state = 'error'
            peer_state.error = ERROR_UNKNOWN_ID

            PTFTPD_STATE[self.client_address] = peer_state
            return peer_state.next()

        if peer_state.state == 'send':
            if peer_state.packetnum != num:
                print 'Got ACK with incoherent data packet number. Aborting transfer.'
                peer_state.state = 'error'
                peer_state.error = ERROR_ILLEGAL_OP

            return peer_state.next()
        elif peer_state.state == 'error':
            print 'Error ACKed. Terminating transfer.'
        elif peer_state.state == 'last':
            peer_state.file.close()
        else:
            print 'ERROR: Unexpected ACK!'

        PTFTPD_STATE.pop(self.client_address)
        return None

    def serveDATA(self, op, request):
        """
        Serves DATA packets.

        Args:
          op: the TFTP opcode (int).
          request: the TFTP packet without its opcode (string).
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            num, data = TFTPHelper.parseDATA(request)
        except SyntaxError:
            # Ignore malformed DATA packets
            return None

        try:
            peer_state = PTFTPD_STATE[self.client_address]
        except KeyError:
            peer_state = TFTPState(self.client_address, op, None, None, None)
            peer_state.state = 'error'
            peer_state.error = ERROR_UNKNOWN_ID

            PTFTPD_STATE[self.client_address] = peer_state
            return peer_state.next()

        if num != peer_state.packetnum:
            peer_state.state = 'error'
            peer_state.error = ERROR_ILLEGAL_OP
        else:
            peer_state.data = data

        return peer_state.next()

    def serveERROR(self, op, request):
        """
        Serves ERROR packets.

        Args:
          op: the TFTP opcode (int).
          request: the TFTP packet without its opcode (string).
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            errno, errmsg = TFTPHelper.parseERROR(request)
        except SyntaxError:
            # Ignore malformed ERROR packets
            return None

        # An error packet immediately terminates a connection
        if PTFTPD_STATE.has_key(self.client_address):
            PTFTPD_STATE.pop(self.client_address)

        return None


class TFTPServerTimeouter(threading.Thread):
    """
    A timeouter thread to cleanup the server's state of timeouted
    clients.
    """

    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.start()

    def run(self):
        while True:
            toremove = []

            for peer, state in PTFTPD_STATE.iteritems():
                delta = datetime.today() - state.last_seen
                if delta > timedelta(seconds=30):
                    toremove.append(peer)

            for peer in toremove:
                del PTFTPD_STATE[peer]

            # Go to sleep
            time.sleep(10)


def checkBasePath(path):
    try:
        mode = os.stat(path)[stat.ST_MODE]
        if stat.S_ISDIR(mode):
            return True
    except OSError:
        print "Path %s not found or unavailable." % path

    return False

def usage():
    print "usage: %s [options]" % sys.argv[0]
    print
    print "  -h    --help      Get help"
    print "  -p    --port      Set TFTP listen port (default: %d)" % _PTFTPD_DEFAULT_PORT
    print "  -b    --basepath  Set TFTP root path (default: %s)" % _PTFTPD_DEFAULT_PATH
    print
    pass

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hp:b:',
                                   ['help', 'port=', 'basepath='])
    except getopt.GetoptError:
        # Print usage and exit
        usage()
        sys.exit(1)

    for opt, val in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(0)
        if opt in ('-p', '--port'):
            try:
                _port = int(val)
            except ValueError:
                print 'Port must be a number!'
                sys.exit(2)
        if opt in ('-b', '--basepath'):
            _path = val

    if checkBasePath(_path):
        try:
            server = SocketServer.UDPServer(('', _port), TFTPServerHandler)
            timeouter = TFTPServerTimeouter()

            print ("%s serving %s on port %d..." %
                   (_PTFTPD_SERVER_NAME, _path, _port))

            server.serve_forever()
        except KeyboardInterrupt:
            print 'Got ^C. Exiting'
            sys.exit(0)
