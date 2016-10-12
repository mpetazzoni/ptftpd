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
TFTP server. It fully supports the TFTP specification as defined in
RFC1350. It also supports the TFTP Option Extension protocol (per
RFC2347), the block size option as defined in RFC2348 and the transfer
size option from RFC2349.

Note that this program currently does *not* support the timeout
interval option from RFC2349.
"""

from datetime import datetime
import os
import shutil
import socket
import stat
import sys
import tempfile

from . import notify
from . import proto
from . import state

l = notify.getLogger('tftp')

# UDP datagram size
_UDP_TRANSFER_SIZE = 8192

_PTFTP_DEFAULT_PORT = 69
_PTFTP_DEFAULT_HOST = 'localhost'
_PTFTP_DEFAULT_MODE = 'octet'

_PTFTP_DEFAULT_OPTS = {
    proto.TFTP_OPTION_BLKSIZE: proto.TFTP_LAN_PACKET_SIZE,
}

_PTFTP_RFC1350_OPTS = {
    proto.TFTP_OPTION_BLKSIZE: proto.TFTP_DEFAULT_PACKET_SIZE,
}


class TFTPClient:
    """
    A small and simple TFTP client to pull/push files from a TFTP server.
    """

    PTFTP_STATE = None

    def __init__(self, peer, opts=None, mode='octet', rfc1350=False,
                 notification_callbacks={}):
        """
        Initializes the TFTP client.

        Args:
            peer (tuple): a (host, port) tuple describing the server to connect
                to.
            opts (dict): a dictionnary of TFTP option values to use,
                or None to disable them (defaults to None).
            mode (string): the transfer mode to use by default, must be one of
                TFTP_MODES (defaults to octet).
            notification_callbacks (dict): a dictionary of notification
                callbacks to use for the callback notification engine.
        """

        self.peer = peer
        self.transfer_mode = mode
        self.error = False
        self.rfc1350 = rfc1350

        self.opts = opts

        if rfc1350:
            self.opts = _PTFTP_RFC1350_OPTS
            print('Running in RFC1350 compliance mode.')
        else:
            if not self.opts:
                self.opts = _PTFTP_DEFAULT_OPTS

            # This one is mandatory
            if proto.TFTP_OPTION_BLKSIZE not in self.opts:
                self.opts[proto.TFTP_OPTION_BLKSIZE] = \
                        _PTFTP_DEFAULT_OPTS[proto.TFTP_OPTION_BLKSIZE]

        # Finally, install the provided callbacks
        notify.CallbackEngine.install(l, notification_callbacks)

    def connect(self):
        """
        Connects the sock to the remote host. Because TFTP is an UDP
        protocol, this has barely no effect.

        Args:
          None.
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(state.STATE_TIMEOUT_SECS)
        print('Connected to {}:{}.'.format(self.peer[0], self.peer[1]))

    def finish(self):
        """
        Closes the connection with the server.

        Args:
          None.
        """

        self.sock.close()

    def serve_forever(self):
        """
        Serve the client prompt until the user exits the program.

        Args:
          None.
        """

        self.connect()

        while True:
            print
            try:
                command = raw_input('tftp> ')
            except EOFError:
                print
                break

            if not command:
                continue

            cmd_parts = command.split(' ')
            if cmd_parts[0] in ('?', 'help'):
                self.usage()
            elif cmd_parts[0] in ('g', 'get'):
                self.get(cmd_parts[1:])
            elif cmd_parts[0] in ('p', 'put'):
                self.put(cmd_parts[1:])
            elif cmd_parts[0] in ('q', 'quit'):
                break
            elif cmd_parts[0] in ('m', 'mode'):
                self.mode(cmd_parts[1:])
            elif cmd_parts[0] in ('b', 'blksize'):
                self.blksize(cmd_parts[1:])
            else:
                print('Unrecognized command. Try help.')

        self.finish()

    def usage(self):
        """
        Display the client help to the user.

        Args:
          None.
        """

        print 'Available commands:'
        print
        print '?  help                  Display help'
        print 'q  quit                  Quit the TFTP client'
        print 'm  mode [newmode]        Display or change transfer mode'
        print 'b  blksize [newsize]     Display or change the transfer block size'
        print
        print 'g  get [-f] <filename>   Get <filename> from server.'
        print '                         (use -f to overwrite local file)'
        print 'p  put <filename>        Push <filename> to the server'
        print

    def handle(self):
        """
        Handle an incoming TFTP packet and dispatch it to one of the
        serve<op> methods below.

        Args:
          None.
        """

        if not self.PTFTP_STATE:
            self.error = (True, 'Connection state error.')
            return

        # Reset the error flag
        self.error = False

        # UDP recv size is _UDP_TRANSFER_SIZE or more if required by
        # the used block size.
        recvsize = _UDP_TRANSFER_SIZE
        if self.opts[proto.TFTP_OPTION_BLKSIZE] > recvsize:
            recvsize = self.opts[proto.TFTP_OPTION_BLKSIZE] + 4

        # Process incoming packet until the state is cleared by the
        # end of a succesfull transmission or an error
        while not self.PTFTP_STATE.done and not self.error:
            try:
                (request, (raddress, rport)) = self.sock.recvfrom(recvsize)
                if not len(request):
                    (request, (raddress, rport)) = self.sock.recvfrom(recvsize)

                # Still nothing?
                if not len(request):
                    self.error = (True, 'Communication error.')
                    return
            except socket.timeout:
                self.error = (True, 'Connection timed out.')
                return

            if not self.PTFTP_STATE.tid:
                self.PTFTP_STATE.tid = rport
                print('Communicating with {}:{}.'
                      .format(self.peer[0], self.PTFTP_STATE.tid))

            if self.PTFTP_STATE.tid != rport:
                l.debug(
                    'Ignoring packet from {}:{}, we are connected to {}:{}.'
                    .format(raddress, rport, raddress, self.peer[0],
                            self.PTFTP_STATE.tid))
                continue

            # Reset the response packet
            response = None

            # Get the packet opcode and dispatch
            opcode = proto.TFTPHelper.getOP(request)
            if not opcode:
                self.error = (True, None)
                response = proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)
            elif opcode not in proto.TFTP_OPS:
                self.error = (True,
                              "Unknown or unsupported operation %d!" % opcode)
                response = proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)
                return
            else:
                try:
                    handler = getattr(self, "serve%s" % proto.TFTP_OPS[opcode])
                except AttributeError:
                    self.error = (True, 'Operation not supported.')
                    response = proto.TFTPHelper.createERROR(
                            proto.ERROR_UNDEF, 'Operation not supported.')

                if not response:
                    response = handler(opcode, request[2:])

            # Finally, send the response if we have one
            if response:
                self.sock.sendto(response,
                                 (self.peer[0], self.PTFTP_STATE.tid))

    def serveOACK(self, op, request):
        """
        Serves OACK packets.

        Args:
          op (integer): the TFTP opcode.
          request (string): the TFTP packet without its opcode.
        Returns:
          A response packet (as a string) or None if the request is
          ignored or completed.
        """

        try:
            opts = proto.TFTPHelper.parseOACK(request)
        except SyntaxError:
            # Ignore malfored OACK packets
            return None

        if not self.PTFTP_STATE:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        # Analyze received options
        opts = proto.TFTPHelper.parse_options(opts)
        if opts:
            # HOOK: this is where we should check that we accept the
            # options provided by the server (tsize/timeout/...).

            self.PTFTP_STATE.set_opts(opts)
        else:
            self.error = (True, 'Transfer options parsing failed.')
            self.PTFTP_STATE.state = state.STATE_ERROR
            self.PTFTP_STATE.error = proto.ERROR_OPTION_NEGOCIATION

        if self.PTFTP_STATE.state == state.STATE_RECV:
            self.PTFTP_STATE.state = state.STATE_RECV_ACK

        return self.PTFTP_STATE.next()

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

        if not self.PTFTP_STATE:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        if self.PTFTP_STATE.state == state.STATE_SEND:
            if self.PTFTP_STATE.packetnum != num:
                self.error = (True,
                              'Got ACK with incoherent data packet number.')
                self.PTFTP_STATE.state = state.STATE_ERROR
                self.PTFTP_STATE.error = proto.ERROR_ILLEGAL_OP

            if not self.rfc1350 and num >= proto.TFTP_PACKETNUM_MAX-1:
                print('Packet number wraparound.')

            return self.PTFTP_STATE.next()

        elif self.PTFTP_STATE.state == state.STATE_SEND_LAST:
            self.PTFTP_STATE.done = True
            return None

        print('ERROR: Unexpected ACK!')
        self.error = (True, None)
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

        if not self.PTFTP_STATE:
            return proto.TFTPHelper.createERROR(proto.ERROR_UNKNOWN_ID)

        if len(data) > self.PTFTP_STATE.opts[proto.TFTP_OPTION_BLKSIZE]:
            self.error = (True, None)
            return proto.TFTPHelper.createERROR(proto.ERROR_ILLEGAL_OP)

        if self.PTFTP_STATE.state == state.STATE_RECV:
            if num != self.PTFTP_STATE.packetnum:
                self.error = (True, 'Got DATA with incoherent packet number.')
                self.PTFTP_STATE.state = state.STATE_ERROR
                self.PTFTP_STATE.error = proto.ERROR_ILLEGAL_OP
            else:
                self.PTFTP_STATE.data = data

            if not self.PTFTP_STATE.done and not self.rfc1350 and \
                    num >= proto.TFTP_PACKETNUM_MAX - 1:
                print('Packet number wraparound.')

            return self.PTFTP_STATE.next()

        print('ERROR: Unexpected DATA!')
        self.error = (True, None)
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

        # Clearing state
        if self.PTFTP_STATE.op == proto.OP_RRQ:
            self.PTFTP_STATE.purge()

        self.error = (True, errmsg)
        return None

    def get(self, args):
        """
        Implements the GET command to retrieve a file from the server.

        Args:
          args (list): the list of arguments passed to the command.
        Returns:
          True or False depending on the success of the operation.
        """

        if len(args) < 1 or len(args) > 2:
            print('Usage: get [-f] <filename>')
            return False

        filepath = args[0]
        overwrite = False

        if len(args) == 2:
            filepath = args[1]
            if args[0] == '-f':
                overwrite = True

        (_, filename) = os.path.split(filepath)

        # First, check we're not going to overwrite an existing file
        if not overwrite:
            try:
                open(filename)
                print('Error: local file {} already exists!'.format(filename))
                print('Use get -f to overwrite the local file.')
                return False
            except IOError:
                pass

        self.PTFTP_STATE = state.TFTPState(self.peer, proto.OP_RRQ,
                                           '', filepath, self.transfer_mode,
                                           not self.rfc1350)

        # Then, before sending anything to the server, open the file
        # for writing
        try:
            # We don't want tempfile to automatically delete the temporary
            # file on close() as we have to copy its content to the destination
            # file first. We'll handle it's deletion on our own.
            self.PTFTP_STATE.file = tempfile.NamedTemporaryFile(delete=False)
            self.PTFTP_STATE.packetnum = 1
            self.PTFTP_STATE.state = state.STATE_RECV
        except IOError, e:
            print('Error: {}'.format(os.strerror(e.errno)))
            print('Can\'t write to temporary file {}!'
                  .format(self.PTFTP_STATE.file.name))
            return False

        opts = dict(self.opts)

        # When not running in RFC1350 compliance mode, append tsize: 0
        # to the list of options in the request to get the requested
        # file size back in the OACK.
        if not self.rfc1350:
            opts[proto.TFTP_OPTION_TSIZE] = 0

        # Everything's OK, let's go
        print "Retrieving '%s' from the remote host..." % filename

        packet = proto.TFTPHelper.createRRQ(filepath, self.transfer_mode, opts)

        transfer_start = datetime.today()
        self.sock.sendto(packet, self.peer)
        self.handle()
        transfer_time = datetime.today() - transfer_start

        if self.error:
            error, errmsg = self.error
            if error and errmsg:
                print('Error: {}'.format(errmsg))
            # Remove the temporary file on error. The destionation file,
            # if it already existed, is left untouched.
            self.PTFTP_STATE.file.close()
            os.remove(self.PTFTP_STATE.file.name)
            return False

        # Copy the temporary file to its final destination
        try:
            shutil.copy(self.PTFTP_STATE.file.name, filename)
        except IOError, e:
            print('Error: {}'.format(os.strerror(e.errno)))
            print('Can\'t copy temporary file to local file {}!'
                  .format(filename))
            return False

        print('Transfer complete, {} bytes ({:.2f} kB/s)'
              .format(self.PTFTP_STATE.filesize,
                      self.__get_speed(self.PTFTP_STATE.filesize,
                                       transfer_time)))
        self.PTFTP_STATE.file.close()
        os.remove(self.PTFTP_STATE.file.name)
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
            print('Usage: put <filename>')
            return

        filepath = args[0]

        self.PTFTP_STATE = state.TFTPState(self.peer, proto.OP_WRQ,
                                           '', filepath, self.transfer_mode,
                                           not self.rfc1350)

        try:
            self.PTFTP_STATE.file = open(filepath, 'rb')
            self.PTFTP_STATE.filesize = os.stat(filepath)[stat.ST_SIZE]
            self.PTFTP_STATE.packetnum = 0
            self.PTFTP_STATE.state = state.STATE_SEND
        except IOError, e:
            print('Error: {}'.format(os.strerror(e.errno)))
            print('Can\'t read from local file {}!'.format(filepath))
            return False

        opts = dict(self.opts)

        # When not running in RFC1350 compliance mode, append the
        # tsize option to the request options to specify the
        # transfered file size to the server.
        if not self.rfc1350:
            opts[proto.TFTP_OPTION_TSIZE] = self.PTFTP_STATE.filesize

        # Everything's OK, let's go
        print "Pushing '%s' to the remote host..." % filepath

        packet = proto.TFTPHelper.createWRQ(filepath, self.transfer_mode, opts)

        transfer_start = datetime.today()
        self.sock.sendto(packet, self.peer)
        self.handle()
        transfer_time = datetime.today() - transfer_start

        if self.error:
            error, errmsg = self.error
            if error and errmsg:
                print('Error: {}'.format(errmsg))
            return False

        print('Transfer complete, {} bytes ({:.2f} kB/s)'
              .format(self.PTFTP_STATE.filesize,
                      self.__get_speed(self.PTFTP_STATE.filesize,
                                       transfer_time)))
        return True

    def mode(self, args):
        if len(args) > 1:
            print('Usage: mode [newmode]')
            return

        if not len(args):
            print('Current transfer mode: {}.'.format(self.transfer_mode))
            print('Available transfer modes: {}'
                  .format(', '.join(proto.TFTP_MODES)))
            return

        if args[0].lower() in proto.TFTP_MODES:
            self.transfer_mode = args[0].lower()
            print('Mode set to {}.'.format(self.transfer_mode))
        else:
            print('Unknown transfer mode, use one of: {}'
                  .format(', '.join(proto.TFTP_MODES)))

    def blksize(self, args):
        if len(args) > 1:
            print('Usage: blksize [newsize]')
            return

        if not len(args):
            print('Current block size: {} byte(s).'
                  .format(self.opts[proto.TFTP_OPTION_BLKSIZE]))
            return

        try:
            self.opts[proto.TFTP_OPTION_BLKSIZE] = int(args[0])
            print('Block size set to {} byte(s).'
                  .format(self.opts[proto.TFTP_OPTION_BLKSIZE]))
        except ValueError:
            print('Block size must be a number!')

    def __get_speed(self, filesize, time):
        return (filesize / 1024.0 /
                (time.seconds + time.microseconds / 1000000.0))


def usage():
    print "usage: %s [options]" % sys.argv[0]
    print
    print "  -?    --help         Get help"
    print "  -h    --host <host>  Set TFTP server (default: %s)" % _PTFTP_DEFAULT_HOST
    print "  -p    --port <port>  Define the port to connect to (default: %d)" % _PTFTP_DEFAULT_PORT
    print "  -m    --mode <mode>  Set transfer mode (default: %s)" % _PTFTP_DEFAULT_MODE
    print "                       Must be one of:", ', '.join(proto.TFTP_MODES)
    print
    print "Available extra options (using the TFTP option extension protocol):"
    print "  -b    --blksize <n>  Set transfer block size (default: %d bytes)" % proto.TFTP_LAN_PACKET_SIZE
    print
    print "To disable the use of TFTP extensions:"
    print "  -r    --rfc1350      Strictly comply to the RFC1350 only (no extensions)"
    print "                       This will discard other TFTP option values."
    print


def main():
    # TODO: convert to optparse
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], '?h:p:b:m:r',
                                   ['help', 'host=',
                                    'port=', 'blksize=',
                                    'mode=', 'rfc1350'])
    except getopt.GetoptError:
        usage()
        return 1

    host = _PTFTP_DEFAULT_HOST
    port = _PTFTP_DEFAULT_PORT
    mode = _PTFTP_DEFAULT_MODE
    exts = {}
    rfc1350 = False

    for opt, val in opts:
        if opt in ('-?', '--help'):
            usage()
            return 0
        if opt in ('-h', '--host'):
            host = val
        if opt in ('-p', '--port'):
            try:
                port = int(val)
            except ValueError:
                print('Port must be a number!')
                return 2
        if opt in ('-b', '--blksize'):
            try:
                exts[proto.TFTP_OPTION_BLKSIZE] = int(val)
            except ValueError:
                print('Block size must be a number!')
                return 2
        if opt in ('-m', '--mode'):
            if val in proto.TFTP_MODES:
                mode = val
            else:
                print('Transfer mode must be one of: {}'
                      .format(', '.join(proto.TFTP_MODES)))
                return 2
        if opt in ('-r', '--rfc1350'):
            rfc1350 = True

    client = TFTPClient((host, port), exts, mode, rfc1350)
    client.serve_forever()
    print('Goodbye.')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
