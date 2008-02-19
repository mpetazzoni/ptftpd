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
import re

from proto import *

# The global state registry
PTFTPD_STATE = {}

class TFTPState:
    """
    This class represents a peer's state. Because SocketServer is not
    stateful, we use a global state registry of TFTPState objects to
    keep track of each request's state through the life of a connexion
    with a client.
    """

    def __init__(self, peer, op, filename, mode, opts):
        """
        Initializes a new TFTP state for the given peer.

        Args:
          peer: a tuple (ip, port) describing the peer.
          op: the operation this state refers to.
          filename: the filename this state refers to.
          mode: the transfer mode requested.
          opts: a dictionnary of TFTP transfer options.
        Returns:
          A new, initialized TFTPState object.
        """

        self.peer = peer
        self.op = op
        self.filename = filename
        self.mode = mode
        self.opts = opts

        self.file = None               # File object to read from or write to
        self.packetnum = None          # Current data packet number
        self.state = None              # Current transaction state (send/recv/last/error)
        self.error = None              # TFTP error code (if state == error)

        # Set the transfer block size
        self.packetsize = TFTP_DEFAULT_PACKET_SIZE
        if self.opts.has_key(TFTP_OPTION_BLKSIZE):
            self.packetsize = self.opts[TFTP_OPTION_BLKSIZE]

        self.last_seen = datetime.today()

        self.data = ""
        self.tosend = ""

    def __str__(self):
        s = "TFTPState/%s for %s\n" % (TFTP_OPS[self.op], self.peer)
        s += "  filename: %s\n" % self.filename
        s += "  mode : %s\n" % self.mode
        s += "  state: %s\n" % self.state
        s += "  opts : %s\n" % self.opts

        return s

    def __repr__(self):
        return self.__str__()

    def next(self):
        """
        Returns the next packet to be sent depending on this state.

        Args:
          none
        Returns:
          The next packet to be sent, as a string (built through TFTPHelper)
          or None if no action is required.
        """

        # Update the last seen bit
        self.last_seen = datetime.today()

        if self.state == 'send':
            fromfile = self.file.read(self.packetsize - len(self.tosend))

            # Convert LF to CRLF if needed
            if self.mode == 'netascii':
                fromfile = OCTET_TO_NETASCII.sub('\r\n', fromfile)

            self.data = self.tosend + fromfile
            self.tosend = ""

            self.packetnum += 1

            if len(self.data) > 512:
                self.tosend = self.data[512:]
                self.data = self.data[:512]
            elif len(self.data) < 512:
                self.state = 'last'

            return TFTPHelper.createDATA(self.packetnum, self.data)
        elif self.state == 'recv':
            if self.data:
                # Convert CRLF to LF if needed
                if self.mode == 'netascii':
                    self.data = re.sub('\r\n', '\n', self.data)

                try:
                    self.file.write(self.data)
                except IOError, e:
                    if e.errno == errno.ENOSPC:
                        return TFTPHelper.createERROR(ERROR_DISK_FULL)
                    else:
                        return TFTPHelper.createERROR(ERROR_UNDEF)

                if len(self.data) < 512:
                    self.file.close()

            self.packetnum += 1
            return TFTPHelper.createACK(self.packetnum - 1)
        elif self.state == 'error':
            return TFTPHelper.createERROR(self.error)
        else:
            return None
