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
TFTP Option Extension protocol (per RFC2347), the block size option as
defined in RFC2348 and the transfer size option from RFC2349.

Note that this program currently does *not* support the timeout
interval option from RFC2349.
"""

from datetime import datetime
from datetime import timedelta
import errno
import getopt
import os
import SocketServer
import stat
import struct
import sys
import threading
import time

import proto
import state

_PTFTPD_SERVER_NAME = 'pFTPd'
_PTFTPD_DEFAULT_PORT = 6969
_PTFTPD_DEFAULT_PATH = '/tftpboot'

# The global state registry
PTFTPD_STATE = {}

_port = _PTFTPD_DEFAULT_PORT
_path = _PTFTPD_DEFAULT_PATH
_rfc1350 = False

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
        opcode = proto.TFTPHelper.getOP(request)

        if not opcode:
            print "Can't find packet opcode. Packet ignored!"
            return

        if not proto.TFTP_OPS.has_key(opcode):
            print "Unknown operation %d!" % opn
            response = proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)

        try:
            handler = getattr(self, "serve%s" % proto.TFTP_OPS[opcode])
        except AttributeError:
            print "Unsupported operation %s!" % op
            response = proto.TFTPHelper.createERROR(proto.ERROR_UNDEF,
                                                    'Operation not supported by server.')

        response = handler(opcode, request[2:])
        if response:
            self.wfile.write(response)
            self.wfile.flush()

    def serveRRQ(self, op, request):
        """
        Serves RRQ packets (GET requests).

        Args:
          op (integer): the TFTP opcode.
          request (string): the TFTP packet without its opcode.
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            filename, mode, opts = proto.TFTPHelper.parseRRQ(request)
        except SyntaxError:
            # Ignore malformed RRQ requests
            return None

        path = os.path.join(_path, filename)
        peer_state = state.TFTPState(self.client_address, op, path, mode)

        try:
            peer_state.file = open(path)
            peer_state.filesize = os.stat(path)[stat.ST_SIZE]
            peer_state.packetnum = 0
            peer_state.state = state.STATE_SEND

            # Only set options if not running in RFC1350 compliance mode
            # and when option were received.
            if not _rfc1350 and len(opts):
                opts = proto.TFTPHelper.parse_options(opts)
                if opts:
                    # HOOK: this is where we should check that we accept
                    # the options requested by the client.

                    peer_state.state = state.STATE_SEND_OACK
                    peer_state.set_opts(opts)
                else:
                    peer_state.file.close()
                    peer_state.state = state.STATE_ERROR
                    peer_state.error = proto.ERROR_OPTION_NEGOCIATION

        except IOError, e:
            peer_state.state = state.STATE_ERROR

            if e.errno == errno.ENOENT:
                peer_state.error = proto.ERROR_FILE_NOT_FOUND
            elif e.errno == errno.EACCES or e.errno == errno.EPERM:
                peer_state.error = proto.ERROR_ACCESS_VIOLATION
            else:
                peer_state.error = proto.ERROR_UNDEF


        PTFTPD_STATE[self.client_address] = peer_state
        return peer_state.next()

    def serveWRQ(self, op, request):
        """
        Serves WRQ packets (PUT requests).

        Args:
          op (integer): the TFTP opcode.
          request (string): the TFTP packet without its opcode.
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            filename, mode, opts = proto.TFTPHelper.parseWRQ(request)
        except SyntaxError:
            # Ignore malfored WRQ requests
            return None

        path = os.path.join(_path, filename)
        peer_state = state.TFTPState(self.client_address, op, path, mode)

        try:
            # Try to open the file. If it succeeds, it means the file
            # already exists and report the error
            peer_state.file = open(path)
            peer_state.state = state.STATE_ERROR
            peer_state.error = proto.ERROR_FILE_ALREADY_EXISTS

            # Only set options if not running in RFC1350 compliance mode
            if not _rfc1350 and len(opts):
                opts = proto.TFTPHelper.parse_options(opts)
                if opts:
                    # HOOK: this is where we should check that we accept
                    # the options requested by the client.

                    peer_state.packetnum = 1
                    peer_state.state = state.STATE_SEND_OACK
                    peer_state.set_opts(opts)
                else:
                    peer_state.state = state.STATE_ERROR
                    peer_state.error = proto.ERROR_OPTION_NEGOCIATION

        except IOError, e:
            # Otherwise, if the open failed because the file did not
            # exist, create it and go on
            if e.errno == errno.ENOENT:
                try:
                    peer_state.file = open(path, 'w')
                    peer_state.packetnum = 0
                    peer_state.state = state.STATE_RECV
                except IOError:
                    peer_state.state = state.STATE_ERROR
                    peer_state.error = proto.ERROR_ACCESS_VIOLATION
            else:
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ACCESS_VIOLATION

        PTFTPD_STATE[self.client_address] = peer_state
        return peer_state.next()

    def serveACK(self, op, request):
        """
		Serves ACK packets.

        Args:
          op (integer): the TFTP opcode.
          request (string): the TFTP packet without its opcode.
        Returns:
          A response packet (as a string) or None if the request is
          ignored or completed.
        """

        try:
            num = proto.TFTPHelper.parseACK(request)
        except SyntaxError:
            # Ignore malfored ACK packets
            return None

        try:
            peer_state = PTFTPD_STATE[self.client_address]
        except KeyError:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        if peer_state.state == state.STATE_SEND_OACK:
            if num != 0:
                print 'Client did not reply correctly to the OACK packet. Aborting transmission.'
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ILLEGAL_OP
            else:
                peer_state.state = state.STATE_SEND

            return peer_state.next()

        elif peer_state.state == state.STATE_SEND:
            if peer_state.packetnum != num:
                print 'Got ACK with incoherent data packet number. Aborting transfer.'
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ILLEGAL_OP

            return peer_state.next()

        elif peer_state.state == state.STATE_RECV and num == 0:
            return peer_state.next()

        elif peer_state.state == state.STATE_ERROR:
            print 'Error ACKed. Terminating transfer.'
            return None

        elif peer_state.state == state.STATE_SEND_LAST:
            print "  >  DATA: %d data packet(s) sent." % peer_state.packetnum
            print "  <   ACK: Transfer complete, %d byte(s)." % peer_state.filesize
            del PTFTPD_STATE[self.client_address]
            return None

        print 'ERROR: Unexpected ACK!'

        if peer_state.op == proto.OP_WRQ:
            peer_state.purge()
        del PTFTPD_STATE[self.client_address]
        return proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)

    def serveDATA(self, op, request):
        """
        Serves DATA packets.

        Args:
          op (integer): the TFTP opcode.
          request (string): the TFTP packet without its opcode.
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            num, data = proto.TFTPHelper.parseDATA(request)
        except SyntaxError:
            # Ignore malformed DATA packets
            return None

        try:
            peer_state = PTFTPD_STATE[self.client_address]
        except KeyError:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        if len(data) > peer_state.opts[proto.TFTP_OPTION_BLKSIZE]:
            return proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)

        if peer_state.state == state.STATE_RECV:
            if num != peer_state.packetnum:
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ILLEGAL_OP
            else:
                peer_state.data = data

            next = peer_state.next()

            if peer_state.done:
                print "  <  DATA: %d packet(s) recevied." % peer_state.packetnum
                print "  >   ACK: Transfer complete, %d byte(s)." % peer_state.filesize
                del PTFTPD_STATE[self.client_address]

            return next

        print 'ERROR: Unexpected DATA!'

        if peer_state.op == proto.OP_WRQ:
            peer_state.purge()
        del PTFTPD_STATE[self.client_address]
        return proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)

    def serveERROR(self, op, request):
        """
        Serves ERROR packets.

        Args:
          op (integer): the TFTP opcode.
          request (string): the TFTP packet without its opcode.
        Returns:
          A response packet (as a string) or None if the request is
          ignored for some reason.
        """

        try:
            errno, errmsg = proto.TFTPHelper.parseERROR(request)
        except SyntaxError:
            # Ignore malformed ERROR packets
            return None

        # An error packet immediately terminates a connection
        if PTFTPD_STATE.has_key(self.client_address):
            peer_state = PTFTPD_STATE[self.client_address]

            if peer_state.op == proto.OP_WRQ:
                peer_state.purge()
            del PTFTPD_STATE[self.client_address]

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

            for peer, peer_state in PTFTPD_STATE.iteritems():
                delta = datetime.today() - peer_state.last_seen
                if delta > timedelta(seconds=state.STATE_TIMEOUT_SECS):
                    print "  #  T-OUT: peer %s:%d timeouted." % peer
                    toremove.append(peer)

            for peer in toremove:
                if PTFTPD_STATE[peer].op == proto.OP_WRQ:
                    PTFTPD_STATE[peer].purge()
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
    print "To disable the use of TFTP extensions:"
    print "  -r    --rfc1350   Strictly comply to the RFC1350 only (no extensions)"
    print

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], '?p:b:r',
                                   ['help', 'port=', 'basepath=', 'rfc1350'])
    except getopt.GetoptError:
        # Print usage and exit
        usage()
        sys.exit(1)

    for opt, val in opts:
        if opt in ('-?', '--help'):
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
        if opt in ('-r', '--rfc1350'):
            _rfc1350 = True

    if checkBasePath(_path):
        try:
            server = SocketServer.UDPServer(('', _port), TFTPServerHandler)

            # Override the UDP read packet size to accomodate TFTP
            # block sizes larger than 8192.
            server.max_packet_size = proto.TFTP_BLKSIZE_MAX + 4

            # Increase TFTP protocol packet creation/parsing
            # verbosity.
            proto.verbose = 1

            timeouter = TFTPServerTimeouter()

            if _rfc1350:
                print 'Running in RFC1350 compliance mode.'
            print ("%s serving %s on port %d..." %
                   (_PTFTPD_SERVER_NAME, _path, _port))

            server.serve_forever()
        except KeyboardInterrupt:
            print 'Got ^C. Exiting'
            sys.exit(0)
