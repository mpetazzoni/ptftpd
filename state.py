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

from datetime import datetime
import os
import re
import stat

import proto

STATE_SEND = 1
STATE_SEND_OACK = 2
STATE_SEND_LAST = 4
STATE_RECV = 8
STATE_RECV_OACK = 16
STATE_ERROR = 32

STATE_TIMEOUT_SECS = 30

class TFTPState:
    """
    This class represents a peer's state. Because SocketServer is not
    stateful, we use a global state registry of TFTPState objects to
    keep track of each request's state through the life of a connexion
    with a client.
    """

    def __init__(self, peer, op, filepath, mode):
        """
        Initializes a new TFTP state for the given peer.

        Args:
          peer (tuple): a tuple (ip, port) describing the peer.
          op (integer): the operation this state refers to.
          filepath (string): the full path of the used file.
          mode (string): the transfer mode requested.
        Returns:
          A new, initialized TFTPState object with the options parsed.
        """

        self.peer = peer
        self.op = op
        self.filepath = filepath
        self.mode = mode

        self.file = None               # File object to read from or write to
        self.filesize = 0              # File size in bytes
        self.state = None              # Current transaction state (send/recv/last/error)
        self.done = False

        # Option defaults
        self.opts = {
            proto.TFTP_OPTION_BLKSIZE: proto.TFTP_DEFAULT_PACKET_SIZE,
            }

        self.last_seen = datetime.today()

        self.packetnum = None          # Current data packet number
        self.error = None              # TFTP error code to send (if state == error)
        self.data = None
        self.tosend = ""

    def __del__(self):
        if not self.file:
            return

        try:
            self.file.close()
        except AttributeError:
            pass

    def purge(self):
        """
        Remove the used file on demand.
        """

        if self.op == proto.OP_WRQ and self.filepath and self.file:
            try:
                os.remove(self.filepath)
            except OSError:
                pass

    def parse_options(self, opts):
        """
        Parse the given validated options.

        Args:
          opts (dict): a dictionnary of validated TFTP options to use.
        Returns:
          A list of the options parsed.
        """

        # Parse options
        if not opts:
            return

        used = []

        if opts.has_key(proto.TFTP_OPTION_BLKSIZE):
            self.opts[proto.TFTP_OPTION_BLKSIZE] = int(opts[proto.TFTP_OPTION_BLKSIZE])
            used.append(proto.TFTP_OPTION_BLKSIZE)

        return used

    def __str__(self):
        s = "TFTPState/%s for %s\n" % (proto.TFTP_OPS[self.op], self.peer)
        s += "  filepath: %s\n" % self.filepath
        s += "  mode : %s\n" % self.mode
        s += "  state: %s\n" % self.state
        s += "  opts : %s\n" % self.opts

        return s

    def __repr__(self):
        return self.__str__()

    def ping(self):
        """
        Update the last seen value to restart the watchdog.
        """

        self.last_seen = datetime.today()

    def next(self):
        """
        Returns the next packet to be sent depending on this state.

        Args:
          none
        Returns:
          The next packet to be sent, as a string (built through TFTPHelper)
          or None if no action is required.
        """

        self.ping()

        if self.state == STATE_SEND_OACK:
            if self.op == proto.OP_RRQ:
                self.state = STATE_SEND
            else:
                self.state = STATE_RECV

            return proto.TFTPHelper.createOACK(self.opts)

        elif self.state == STATE_RECV_OACK:
            self.state = STATE_RECV
            return proto.TFTPHelper.createACK(0)

        elif self.state == STATE_SEND:
            blksize = self.opts[proto.TFTP_OPTION_BLKSIZE]
            fromfile = self.file.read(blksize - len(self.tosend))

            # Convert LF to CRLF if needed
            if self.mode == 'netascii':
                fromfile = OCTET_TO_NETASCII.sub('\r\n', fromfile)

            self.data = self.tosend + fromfile
            self.tosend = ""

            self.packetnum += 1

            if len(self.data) > blksize:
                self.tosend = self.data[blksize:]
                self.data = self.data[:blksize]
            elif len(self.data) < blksize:
                self.file.close()
                self.state = STATE_SEND_LAST

            return proto.TFTPHelper.createDATA(self.packetnum, self.data)

        elif self.state == STATE_RECV:
            if self.data or self.data == '':
                if len(self.data) < self.opts[proto.TFTP_OPTION_BLKSIZE]:
                    self.done = True

                # Convert CRLF to LF if needed
                if self.mode == 'netascii':
                    self.data = re.sub('\r\n', '\n', self.data)

                try:
                    self.filesize += len(self.data)
                    self.file.write(self.data)
                except IOError, e:
                    self.file.close()
                    if e.errno == errno.ENOSPC:
                        return proto.TFTPHelper.createERROR(ERROR_DISK_FULL)
                    else:
                        return proto.TFTPHelper.createERROR(ERROR_UNDEF)

                if self.done:
                    self.file.close()

            ack = proto.TFTPHelper.createACK(self.packetnum)

            if not self.done:
                self.packetnum += 1

            return ack

        elif self.state == STATE_ERROR:
            return proto.TFTPHelper.createERROR(self.error)

        return None
