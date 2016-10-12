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

from datetime import datetime
import errno
import os

from . import proto

STATE_SEND = 1
STATE_SEND_OACK = 2
STATE_SEND_LAST = 4
STATE_RECV = 8
STATE_RECV_ACK = 16
STATE_ERROR = 32

STATE_TIMEOUT_SECS = 10


class TFTPState:
    """
    This class represents a peer's state. Because SocketServer is not
    stateful, we use a global state registry of TFTPState objects to
    keep track of each request's state through the life of a connexion
    with a client.
    """

    def __init__(self, peer, op, path, filename, mode, loop_packet=True):
        """
        Initializes a new TFTP state for the given peer.

        Args:
          peer (tuple): a tuple (ip, port) describing the peer.
          op (integer): the operation this state refers to.
          path (string): the server root path.
          filename (string): the relative path of the used file.
          mode (string): the transfer mode requested.
          loop_packet (boolean): activate packet number wraparound.
        Returns:
          A new, initialized TFTPState object with the options parsed.
        """

        (self.peer, self.op, self.path, self.filename, self.mode) = \
            (peer, op, path, filename, mode)
        self.filepath = os.path.abspath(os.path.join(self.path, self.filename))

        self.tid = None                     # Transfer ID
        self.file = None                    # File object to read from or
                                            # write to
        self.filesize = 0                   # File size in bytes
        self.state = None                   # Current transaction state
                                            # (send/recv/last/error)
        self.done = False                   # Transaction complete flag

        # Option defaults
        self.opts = {
            proto.TFTP_OPTION_BLKSIZE: proto.TFTP_DEFAULT_PACKET_SIZE
        }

        self.last_seen = datetime.today()

        self.packetnum = None               # Current data packet number
        self.loop_packetnum = loop_packet   # Packet number wraparound toggle
        self.total_packets = 0              # Total number of data packets sent
                                            # or received
        self.error = None                   # TFTP error code to send
                                            # (if state == error)
        self.data = None
        self.tosend = ""

    def extra(self, state):
        """Build an extra information dictionnary we can pass to logging
        functions when necessary.

        Args:
            state (notify state): a transfer state (see notify module).

        Returns a dictionnary containing the host, port, file and state
        mappings.
        """
        return {'host': self.peer[0],
                'port': self.peer[1],
                'tid': self.tid,
                'file': self.filename,
                'state': state}

    def __del__(self):
        if not self.file:
            return

        try:
            self.file.close()
        except AttributeError:
            pass

    def __str__(self):
        s = "TFTPState/%s for %s<%s>\n" % (proto.TFTP_OPS[self.op],
                                           self.peer,
                                           self.tid)
        s += "  filepath: %s\n" % self.filepath
        s += "  mode : %s\n" % self.mode
        s += "  state: %s\n" % self.state
        s += "  opts : %s\n" % self.opts

        return s

    def __repr__(self):
        return self.__str__()

    def purge(self):
        """
        Remove the used file on demand.
        """

        if self.filepath and self.file:
            try:
                os.remove(self.filepath)
                return True
            except OSError:
                return False

    def ping(self):
        """
        Update the last seen value to restart the watchdog.
        """

        self.last_seen = datetime.today()

    def set_opts(self, opts):
        """
        Set this state options.

        Args:
          opts (dict): a dictionnary of validated options.
        """

        if not opts:
            return

        if opts.get(proto.TFTP_OPTION_TSIZE) == 0:
            opts[proto.TFTP_OPTION_TSIZE] = self.filesize

        self.opts = opts

    def next(self):
        """
        Returns the next packet to be sent depending on this state.

        Args:
          None.
        Returns:
          The next packet to be sent, as a string (built through TFTPHelper)
          or None if no action is required.
        """

        self.ping()

        if self.state == STATE_SEND:
            return self.__next_send()
        elif self.state == STATE_SEND_OACK:
            return self.__next_send_oack()
        elif self.state == STATE_RECV:
            return self.__next_recv()
        elif self.state == STATE_RECV_ACK:
            return self.__next_recv_ack()
        elif self.state == STATE_ERROR:
            return self.__next_error()

        return None

    def __next_send(self):
        blksize = self.opts[proto.TFTP_OPTION_BLKSIZE]
        fromfile = self.file.read(blksize - len(self.tosend))

        # Convert LF to CRLF if needed
        if self.mode == 'netascii':
            fromfile = proto.OCTET_TO_NETASCII.sub('\r\n', fromfile)

        self.data = self.tosend + fromfile
        self.tosend = ""

        self.packetnum += 1
        self.total_packets += 1

        # Packet number wraparound
        if self.packetnum == proto.TFTP_PACKETNUM_MAX and self.loop_packetnum:
            self.packetnum = proto.TFTP_PACKETNUM_RESET

        data_len = len(self.data)
        if data_len > blksize:
            self.tosend = self.data[blksize:]
            self.data = self.data[:blksize]
        elif data_len < blksize:
            self.file.close()
            self.state = STATE_SEND_LAST

        return proto.TFTPHelper.createDATA(self.packetnum, self.data)

    def __next_send_oack(self):
        self.state = STATE_SEND if self.op == proto.OP_RRQ else STATE_RECV
        return proto.TFTPHelper.createOACK(self.opts)

    def __next_recv_ack(self):
        self.state = STATE_RECV
        return proto.TFTPHelper.createACK(0)

    def __next_recv(self):
        # Convert CRLF to LF if needed
        if self.mode == 'netascii':
            self.data = proto.NETASCII_TO_OCTET.sub('\n', self.data)

        data_len = len(self.data)
        if data_len < self.opts[proto.TFTP_OPTION_BLKSIZE]:
            self.done = True

        try:
            self.filesize += len(self.data)
            self.file.write(self.data)
        except IOError, e:
            self.file.close()
            if e.errno == errno.ENOSPC:
                return proto.TFTPHelper.createERROR(proto.ERROR_DISK_FULL)
            else:
                print('Undefined error occured: {}!'
                      .format(errno.errorcode[e.errno]))
                return proto.TFTPHelper.createERROR(proto.ERROR_UNDEF)

        if self.done:
            self.file.close()

        ack = proto.TFTPHelper.createACK(self.packetnum)

        if not self.done:
            self.packetnum += 1
            self.total_packets += 1

        # Packet number wraparound
        if self.packetnum == proto.TFTP_PACKETNUM_MAX and self.loop_packetnum:
            self.packetnum = proto.TFTP_PACKETNUM_RESET

        return ack

    def __next_error(self):
        return proto.TFTPHelper.createERROR(self.error)
