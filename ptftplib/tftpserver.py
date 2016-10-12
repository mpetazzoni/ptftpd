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
import logging
import netifaces
import os
import socket
import SocketServer
import stat
import sys
import threading
import time

from . import notify
from . import proto
from . import state

l = notify.getLogger('tftpd')

_PTFTPD_SERVER_NAME = 'pFTPd'
_PTFTPD_DEFAULT_PORT = 69
_PTFTPD_DEFAULT_PATH = '/tftpboot'


def get_ip_config_for_iface(iface):
    """Retrieve and return the IP address/netmask and MAC address of the
    given interface."""

    if iface not in netifaces.interfaces():
        raise TFTPServerConfigurationError(
                'Unknown network interface {}'.format(iface))

    details = netifaces.ifaddresses(iface)
    inet = details[netifaces.AF_INET][0]
    link = details[netifaces.AF_LINK][0]

    return inet['addr'], inet['netmask'], link['addr']


class TFTPServerConfigurationError(Exception):
    """The configuration of the pTFTPd is incorrect."""


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
            l.error("Can't find packet opcode, packet ignored")
            return

        if opcode not in proto.TFTP_OPS:
            l.error("Unknown operation %d" % opcode)
            response = proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)
            self.wfile.write(response)
            self.wfile.flush()
            return

        try:
            handler = getattr(self, "serve%s" % proto.TFTP_OPS[opcode])
        except AttributeError:
            l.error("Unsupported operation %s" % opcode)
            response = proto.TFTPHelper.createERROR(
                    proto.ERROR_UNDEF,
                    'Operation not supported by server.')

        response = handler(opcode, request[2:])
        if response:
            self.wfile.write(response)
            self.wfile.flush()

    def finish_state(self, peer_state):
        self.server.clients[self.client_address] = peer_state
        return peer_state.next()

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

        peer_state = state.TFTPState(self.client_address, op,
                                     self.server.root, filename, mode,
                                     not self.server.strict_rfc1350)

        if not peer_state.filepath.startswith(self.server.root):
            peer_state.state = state.STATE_ERROR
            peer_state.error = proto.ERROR_ACCESS_VIOLATION

            l.warning('Out-of-jail path requested: %s!' % filename,
                      extra=peer_state.extra(notify.TRANSFER_FAILED))
            return self.finish_state(peer_state)

        try:
            peer_state.file = open(peer_state.filepath, 'rb')
            peer_state.filesize = os.stat(peer_state.filepath)[stat.ST_SIZE]
            peer_state.packetnum = 0
            peer_state.state = state.STATE_SEND

            l.info('Serving file %s to host %s...' %
                   (filename, self.client_address[0]),
                   extra=peer_state.extra(notify.TRANSFER_STARTED))

            # Only set options if not running in RFC1350 compliance mode
            # and when option were received.
            if not self.server.strict_rfc1350 and len(opts):
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
                l.warning('Client requested non-existent file %s' % filename,
                          extra=peer_state.extra(notify.TRANSFER_FAILED))
            elif e.errno == errno.EACCES or e.errno == errno.EPERM:
                peer_state.error = proto.ERROR_ACCESS_VIOLATION
                l.error('Client requested inaccessible file %s' % filename,
                        extra=peer_state.extra(notify.TRANSFER_FAILED))
            else:
                peer_state.error = proto.ERROR_UNDEF
                l.error('Unknown error while accessing file %s' % filename,
                        extra=peer_state.extra(notify.TRANSFER_FAILED))

        return self.finish_state(peer_state)

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

        peer_state = state.TFTPState(self.client_address, op,
                                     self.server.root, filename, mode,
                                     not self.server.strict_rfc1350)

        if not peer_state.filepath.startswith(self.server.root):
            peer_state.state = state.STATE_ERROR
            peer_state.error = proto.ERROR_ACCESS_VIOLATION

            l.warning('Out-of-jail path requested: %s!' % filename,
                      extra=peer_state.extra(notify.TRANSFER_FAILED))
            return self.finish_state(peer_state)

        try:
            # Try to open the file. If it succeeds, it means the file
            # already exists and report the error
            peer_state.file = open(peer_state.filepath)
            peer_state.state = state.STATE_ERROR
            peer_state.error = proto.ERROR_FILE_ALREADY_EXISTS

            l.warning('Client attempted to overwrite file %s!' % filename,
                      extra=peer_state.extra(notify.TRANSFER_FAILED))
            return self.finish_state(peer_state)

        except IOError, e:
            # Otherwise, if the open failed because the file did not
            # exist, create it and go on
            if e.errno == errno.ENOENT:
                try:
                    peer_state.file = open(peer_state.filepath, 'wb')
                    peer_state.packetnum = 0
                    peer_state.state = state.STATE_RECV_ACK
                    l.info('Upload of %s began.' % filename,
                           extra=peer_state.extra(notify.TRANSFER_STARTED))
                except IOError:
                    peer_state.state = state.STATE_ERROR
                    peer_state.error = proto.ERROR_ACCESS_VIOLATION
                    l.warning('Error creating file %s for upload!' % filename,
                              extra=peer_state.extra(notify.TRANSFER_FAILED))
            else:
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ACCESS_VIOLATION
                l.warning('Error creating file %s for upload!' % filename,
                          extra=peer_state.extra(notify.TRANSFER_FAILED))

        # Only set options if not running in RFC1350 compliance mode
        if not self.server.strict_rfc1350 and len(opts):
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

        return self.finish_state(peer_state)

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
            peer_state = self.server.clients[self.client_address]
        except KeyError:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        if peer_state.state == state.STATE_SEND_OACK:
            if num != 0:
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ILLEGAL_OP
                l.error('Client did not reply correctly to the OACK packet. '
                        'Aborting transmission.',
                        extra=peer_state.extra(notify.TRANSFER_FAILED))
            else:
                peer_state.state = state.STATE_SEND

            return peer_state.next()

        elif peer_state.state == state.STATE_SEND:
            if peer_state.packetnum == num + 1:
                # Ignore duplicate N-1 ACK packets
                l.debug('Got duplicate ACK packet #%d. Ignoring.' % num)
                pass
            elif peer_state.packetnum != num:
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ILLEGAL_OP
                l.error('Got ACK with incoherent data packet number. '
                        'Aborting transfer.',
                        extra=peer_state.extra(notify.TRANSFER_FAILED))

            if not self.server.strict_rfc1350 and \
                    num == proto.TFTP_PACKETNUM_MAX - 1:
                l.debug('Packet number wraparound.')

            return peer_state.next()

        elif peer_state.state == state.STATE_RECV and num == 0:
            return peer_state.next()

        elif peer_state.state == state.STATE_ERROR:
            l.debug('Error ACKed. Terminating transfer.',
                    extra=peer_state.extra(notify.TRANSFER_FAILED))
            return None

        elif peer_state.state == state.STATE_SEND_LAST:
            l.debug("  >  DATA: %d data packet(s) sent."
                    % peer_state.total_packets)
            l.debug("  <   ACK: Transfer complete, %d byte(s)."
                    % peer_state.filesize)
            l.info('Transfer of file %s completed.' % peer_state.filename,
                   extra=peer_state.extra(notify.TRANSFER_COMPLETED))
            del self.server.clients[self.client_address]
            return None

        l.error('Unexpected ACK!',
                extra=peer_state.extra(notify.TRANSFER_FAILED))

        if peer_state.op == proto.OP_WRQ:
            peer_state.purge()
        del self.server.clients[self.client_address]
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
            peer_state = self.server.clients[self.client_address]
        except KeyError:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        if len(data) > peer_state.opts[proto.TFTP_OPTION_BLKSIZE]:
            l.warning('Illegal TFTP option received.',
                      extra=peer_state.extra(notify.TRANSFER_FAILED))
            return proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)

        if peer_state.state == state.STATE_RECV:
            if num != peer_state.packetnum:
                peer_state.state = state.STATE_ERROR
                peer_state.error = proto.ERROR_ILLEGAL_OP
            else:
                peer_state.data = data

            next = peer_state.next()

            if peer_state.done:
                l.debug("  <  DATA: %d packet(s) received."
                        % peer_state.total_packets)
                l.debug("  >   ACK: Transfer complete, %d byte(s)."
                        % peer_state.filesize)
                l.info('Transfer of file %s completed.' % peer_state.filename,
                       extra=peer_state.extra(notify.TRANSFER_COMPLETED))
                del self.server.clients[self.client_address]

            elif (not self.server.strict_rfc1350 and
                  num == proto.TFTP_PACKETNUM_MAX-1):
                l.debug('Packet number wraparound.')

            return next

        l.error('Unexpected DATA!',
                extra=peer_state.extra(notify.TRANSFER_FAILED))

        if peer_state.op == proto.OP_WRQ:
            peer_state.purge()
        del self.server.clients[self.client_address]
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

        if self.client_address not in self.server.clients:
            return None

        # An error packet immediately terminates a connection
        peer_state = self.server.clients[self.client_address]

        l.warning('Error packet received!',
                  extra=peer_state.extra(notify.TRANSFER_FAILED))
        if peer_state.op == proto.OP_WRQ:
            peer_state.purge()
        del self.server.clients[self.client_address]


class TFTPServerGarbageCollector(threading.Thread):
    """
    A gc thread to clean up the server's state of timed out clients.
    """

    def __init__(self, clients):
        threading.Thread.__init__(self)
        self.clients = clients
        self.setDaemon(True)

    def run(self):
        while True:
            # Sleep a little before doing a cycle.
            time.sleep(10)

            toremove = []

            for peer, peer_state in self.clients.iteritems():
                delta = datetime.today() - peer_state.last_seen
                if delta > timedelta(seconds=state.STATE_TIMEOUT_SECS):
                    if peer_state.state != state.STATE_ERROR:
                        l.debug("Peer %s:%d timed out." % peer,
                                extra=peer_state.extra(notify.TRANSFER_FAILED))
                    toremove.append(peer)

            for peer in toremove:
                if self.clients[peer].op == proto.OP_WRQ:
                    self.clients[peer].purge()
                l.debug('Removed stale peer %s:%d.' % peer)
                del self.clients[peer]


class TFTPServer(object):
    def __init__(self, iface, root, port=_PTFTPD_DEFAULT_PORT,
                 strict_rfc1350=False, notification_callbacks={}):
        self.iface, self.root, self.port, self.strict_rfc1350 = \
                iface, root, port, strict_rfc1350
        self.client_registry = {}

        if not os.path.isdir(self.root):
            raise TFTPServerConfigurationError(
                "The specified TFTP root does not exist")

        self.ip, self.netmask, self.mac = get_ip_config_for_iface(self.iface)
        self.server = SocketServer.UDPServer((self.ip, port),
                                             TFTPServerHandler)
        self.server.root = self.root
        self.server.strict_rfc1350 = self.strict_rfc1350
        self.server.clients = self.client_registry
        self.cleanup_thread = TFTPServerGarbageCollector(self.client_registry)

        # Add callback notifications
        notify.CallbackEngine.install(l, notification_callbacks)

    def serve_forever(self):
        l.info("Serving TFTP requests on %s:%d in %s" %
               (self.iface, self.port, self.root))
        self.cleanup_thread.start()
        self.server.serve_forever()


def main():
    import optparse

    usage = "Usage: %prog [options] <iface> <TFTP root>"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-r", "--rfc1350", dest="strict_rfc1350",
                      action="store_true", default=False,
                      help="Run in strict RFC1350 compliance mode, "
                      "with no extensions")
    parser.add_option("-p", "--port", dest="port", action="store", type="int",
                      default=_PTFTPD_DEFAULT_PORT, metavar="PORT",
                      help="Listen for TFTP requests on PORT")
    parser.add_option("-v", "--verbose", dest="loglevel", action="store_const",
                      const=logging.INFO, help="Output information messages",
                      default=logging.WARNING)
    parser.add_option("-D", "--debug", dest="loglevel", action="store_const",
                      const=logging.DEBUG, help="Output debugging information")

    (options, args) = parser.parse_args()
    if len(args) != 2:
        parser.print_help()
        return 1

    iface = args[0]
    root = os.path.abspath(args[1])

    # Setup notification logging
    notify.StreamEngine.install(l, stream=sys.stdout,
                                loglevel=options.loglevel,
                                format='%(levelname)s(%(name)s): %(message)s')

    try:
        server = TFTPServer(iface, root, options.port, options.strict_rfc1350)
        server.serve_forever()
    except TFTPServerConfigurationError, e:
        sys.stderr.write('TFTP server configuration error: %s!' %
                         e.message)
        return 1
    except socket.error, e:
        sys.stderr.write('Error creating a listening socket on port %d: '
                         '%s (%s).\n' % (options.port, e[1],
                                         errno.errorcode[e[0]]))
        return 1

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
