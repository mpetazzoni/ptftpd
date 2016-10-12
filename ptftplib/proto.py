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

import re
import struct

from . import notify

l = notify.getLogger('tftp-proto')
notify.NullEngine.install(l)

# Uncomment these lines to enable full protocol dump.
# import sys
# import logging
#
# notify.StreamEngine.install(l, sys.stderr, logging.DEBUG)

# The following values are defined in the following RFC documents:
#   - RFC1350 - The TFTP Protocol (revision 2)
#   - RFC2347 - TFTP Option Extension
#   - RFC2348 - TFTP Blocksize option
#   - RFC2349 - TFTP Timeout interval and Transfer size options

# TFTP data packet size. A data packet with a length less than this
# size is considered as being the last packet of the transmission.
TFTP_DEFAULT_PACKET_SIZE = 512

# Enhanced data packet size for LAN networks
TFTP_LAN_PACKET_SIZE = 1400

# Maximum packet number (2^16). When reached, we may want to wraparound and
# reset to TFTP_PACKETNUM_RESET to continue transfer (some clients may not
# support it).
# The wraparound can be disabled with --rfc1350.
TFTP_PACKETNUM_MAX = 65536

# Packet number value for reset (see above)
TFTP_PACKETNUM_RESET = 0

# TFTP opcodes
TFTP_OPCODE_LEN = 2

OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5
OP_OACK = 6

TFTP_OPS = {
    OP_RRQ: 'RRQ',
    OP_WRQ: 'WRQ',
    OP_DATA: 'DATA',
    OP_ACK: 'ACK',
    OP_ERROR: 'ERROR',
    OP_OACK: 'OACK',
}

# TFTP error codes
ERROR_UNDEF = 0
ERROR_FILE_NOT_FOUND = 1
ERROR_ACCESS_VIOLATION = 2
ERROR_DISK_FULL = 3
ERROR_ILLEGAL_OP = 4
ERROR_UNKNOWN_ID = 5
ERROR_FILE_ALREADY_EXISTS = 6
ERROR_NO_SUCH_USER = 7
ERROR_OPTION_NEGOCIATION = 8

TFTP_ERRORS = {
    ERROR_UNDEF: 'Not defined, see error message (if any).',
    ERROR_FILE_NOT_FOUND: 'File not found.',
    ERROR_ACCESS_VIOLATION: 'Access violation.',
    ERROR_DISK_FULL: 'Disk full or allocation exceeded.',
    ERROR_ILLEGAL_OP: 'Illegal TFTP operation.',
    ERROR_UNKNOWN_ID: 'Unknown transfer ID.',
    ERROR_FILE_ALREADY_EXISTS: 'File already exists.',
    ERROR_NO_SUCH_USER: 'No such user.',
    ERROR_OPTION_NEGOCIATION: 'Option negociation failed',
}

# TFTP transfer modes (mail is deprecated as of RFC1350)
TFTP_MODES = ['netascii', 'octet']
NETASCII_TO_OCTET = re.compile('\r\n')
OCTET_TO_NETASCII = re.compile('\r?\n')

# TFTP option names, as defined in RFC2348 and RFC2349
TFTP_OPTION_BLKSIZE = 'blksize'
TFTP_OPTION_TIMEOUT = 'timeout'
TFTP_OPTION_TSIZE = 'tsize'

TFTP_OPTIONS = [TFTP_OPTION_BLKSIZE, TFTP_OPTION_TIMEOUT, TFTP_OPTION_TSIZE]

TFTP_BLKSIZE_MIN = 8
TFTP_BLKSIZE_MAX = 65464

TFTP_TIMEOUT_MIN = 1
TFTP_TIMEOUT_MAX = 255


class TFTPHelper:
    """
    Static helper methods for the TFTP protocol.
    """

    def createRRQ(filename, mode, opts):
        """
        Creates a packed TFTP RRQ packet.

        Args:
          filename: the name of the requested file.
          mode: the transfer mode (must be one from TFTP_MODES).
          opts: a dictionnary of TFTP options.
        Returns:
          The request packet as a string.
        """

        l.debug("  >   %s: %s (mode: %s, opts: %s)" %
                (TFTP_OPS[OP_RRQ], filename, mode, opts))

        packet = struct.pack('!H%dsc%dsc' % (len(filename), len(mode)),
                             OP_RRQ, filename, '\0', mode, '\0')

        for opt, val in opts.iteritems():
            packet += struct.pack('!%dsc%dsc' % (len(opt), len(str(val))),
                                  opt, '\0', str(val), '\0')

        return packet

    def createWRQ(filename, mode, opts):
        """
        Creates a packed TFTP WRQ packet.

        Args:
          filename: the name of the requested file.
          mode: the transfer mode (must be one from TFTP_MODES).
          opts: a dictionnary of TFTP options.
        Returns:
          The request packet as a string.
        """

        l.debug("  >   %s: %s (mode: %s, opts: %s)" %
                (TFTP_OPS[OP_WRQ], filename, mode, opts))

        packet = struct.pack('!H%dsc%dsc' % (len(filename), len(mode)),
                             OP_WRQ, filename, '\0', mode, '\0')

        for opt, val in opts.iteritems():
            packet += struct.pack('!%dsc%dsc' % (len(opt), len(str(val))),
                                  opt, '\0', str(val), '\0')

        return packet

    def createACK(num):
        """
        Creates a packed TFTP ACK packet.

        Args:
          num (integer): the data packet number to ack.
        Returns:
          The ack packet as a string.
        """

        if num > 0:
            l.debug("  >   %s: #%d" % (TFTP_OPS[OP_ACK], num))
        elif num == 0:
            l.debug("  >   %s: Acknowledging transfer." % TFTP_OPS[OP_ACK])

        return struct.pack('!HH', OP_ACK, num)

    def createERROR(errno, errmsg=None):
        """
        Creates a packed TFTP error packet.

        Args:
          errno (integer): the TFTP error code.
          errmsg (string): when using error code ERROR_UNDEF, a specific
            error message can be attached to the error packet via this
            parameter.
        Returns:
          The error packet as a string.
        """

        error = TFTP_ERRORS[errno]
        if errno == ERROR_UNDEF and errmsg:
            error = errmsg

        l.debug("  > %s: %d %s" % (TFTP_OPS[OP_ERROR], errno, error))
        return struct.pack('!HH%dsc' % len(error),
                           OP_ERROR, errno, error, '\0')

    def createDATA(num, data):
        """
        Creates a packed TFTP data packet.

        Args:
          num: the data packet number (int).
          data: the data to be sent (string).
        Returns:
          The data packet as a string.
        """

        data_len = len(data)
        l.debug("  >  %s: #%d (%d bytes)" % (TFTP_OPS[OP_DATA], num, data_len))
        return struct.pack('!HH%ds' % data_len, OP_DATA, num, data)

    def createOACK(opts):
        """
        Creates an OACK TFTP packet for the given options.

        Args:
          opts (dict): a dictionnary of TFTP options.
        Returns:
          The OACK packet as a string.
        """

        l.debug("  >  %s: %s" % (TFTP_OPS[OP_OACK], opts))

        opts_str = ""
        for opt, val in opts.iteritems():
            opts_str += "%s%c%s%c" % (opt, '\0', val, '\0')

        return struct.pack('!H%ds' % len(opts_str), OP_OACK, opts_str)

    def parseRRQ(request):
        """
        Parses a RRQ packet to extract the requested mode and filename.

        Args:
          request: the RRQ packet without the TFTP opcode (string).
        Returns:
          The filename, mode and options of the request.
        Throws:
          If the parsing failed, a SyntaxError is raised.
        """

        packet = request.split('\0')[:-1]

        # If the length of the parsed list is not even, the packet is
        # malformed and thus parsing should fail.
        if len(packet) % 2 != 0:
            raise SyntaxError

        filename = packet[0]
        mode = packet[1].lower()

        opts = {}
        for i in xrange(2, len(packet)-1, 2):
            opt = packet[i].lower()
            val = packet[i+1]

            if opt in TFTP_OPTIONS:
                opts[opt] = val

        try:
            TFTP_MODES.index(mode)
            if filename != '':
                l.debug("  <   %s: %s (mode: %s, opts: %s)" %
                        (TFTP_OPS[OP_RRQ], filename, mode, opts))
                return filename, mode, opts
        except ValueError:
            raise SyntaxError()

    def parseWRQ(request):
        """
        Parses a WRQ packet to extract the requested mode and filename.

        Args:
          request: the WRQ packet without the TFTP opcode (string).
        Returns:
          The filename, mode and options of the request.
        Throws:
          If the parsing failed, a SyntaxError is raised.
        """

        packet = request.split('\0')[:-1]

        # If the length of the parsed list is not even, the packet is
        # malformed and thus parsing should fail.
        if len(packet) % 2 != 0:
            raise SyntaxError()

        filename = packet[0]
        mode = packet[1].lower()

        opts = {}
        for i in xrange(2, len(packet)-1, 2):
            opt = packet[i].lower()
            val = packet[i+1]

            if opt in TFTP_OPTIONS:
                opts[opt] = val

        try:
            TFTP_MODES.index(mode)
            if filename != '':
                l.debug("  <   %s: %s (mode: %s, opts: %s)" %
                        (TFTP_OPS[OP_WRQ], filename, mode, opts))
                return filename, mode, opts
        except ValueError:
            raise SyntaxError()

    def parseACK(request):
        """
        Parses a ACK packet to extract the data packet number acked.

        Args:
          request: the ACK packet without the TFTP opcode (string).
        Returns:
          The number of the ACKed packet.
        Throws:
          If the parsing failed, a SyntaxError is raised.
        """

        try:
            packet = struct.unpack('!H', request)
            num = packet[0]

            if num > 0:
                l.debug("  <   %s: #%d" % (TFTP_OPS[OP_ACK], num))
            elif num == 0:
                l.debug("  <   %s: Transfer acknowledged." % TFTP_OPS[OP_ACK])

            return num
        except struct.error:
            raise SyntaxError()

    def parseDATA(request):
        """
        Parses a DATA packet to extract the data packet number acked.

        Args:
          request: the DATA packet without the TFTP opcode (string).
        Returns:
          A (num, data) tuple containing the number of the data packet
          and the data itself.
        Throws:
          If the parsing failed, a SyntaxError is raised.
        """

        try:
            packet = struct.unpack('!H', request[:2])
            num = packet[0]
            data = request[2:]

            l.debug("  <  %s: #%d (%d bytes)" %
                    (TFTP_OPS[OP_DATA], num, len(data)))
            return num, data
        except struct.error:
            raise SyntaxError()

    def parseERROR(request):
        """
        Parses an ERROR packet to extract the data packet number acked.

        Args:
          request: the ERROR packet without the TFTP opcode (string).
        Returns:
          A (errno, errmsg) tuple containing the error number and the
          associated error message.
        Throws:
          If the parsing failed, a SyntaxError is raised.
        """

        try:
            packet = struct.unpack('!H', request[:2])
            errno = packet[0]
            errmsg = request[2:].split('\0')[0]

            l.debug("  < %s: %s" % (TFTP_OPS[OP_ERROR], errmsg))
            return errno, errmsg
        except (struct.error, IndexError):
            raise SyntaxError()

    def parseOACK(request):
        """
        Parses an OACK packet to extract the validated options.

        Args:
          request (string): the OACK packet without the TFTP opcode.
        Returns:
          A dictionnary of the acknowledged options.
        """

        packet = request.split('\0')[:-1]

        # If the length of the parsed list is not even, the packet is
        # malformed and thus parsing should fail.
        if len(packet) % 2 != 0:
            raise SyntaxError()

        opts = {}
        for i in xrange(0, len(packet)-1, 2):
            opts[packet[i]] = packet[i+1]

        l.debug("  <  %s: %s" % (TFTP_OPS[OP_OACK], opts))

        return opts

    def getOP(data):
        if data:
            try:
                return struct.unpack('!H', data[:2])[0]
            except (struct.error, KeyError):
                raise SyntaxError()

        return None

    def parse_options(opts):
        """
        Parse and validate the given options.

        Args:
          opts (dict): a dictionnary of validated TFTP options to use.
        Returns:
          The clean dictionnary of options.
        """

        used = {}

        if TFTP_OPTION_BLKSIZE in opts:
            blksize = int(opts[TFTP_OPTION_BLKSIZE])
            if blksize >= TFTP_BLKSIZE_MIN and blksize <= TFTP_BLKSIZE_MAX:
                used[TFTP_OPTION_BLKSIZE] = blksize
            else:
                return None
        else:
            used[TFTP_OPTION_BLKSIZE] = TFTP_DEFAULT_PACKET_SIZE

        if TFTP_OPTION_TIMEOUT in opts:
            timeout = int(opts[TFTP_OPTION_TIMEOUT])
            if timeout >= TFTP_TIMEOUT_MIN and timeout <= TFTP_TIMEOUT_MAX:
                used[TFTP_OPTION_TIMEOUT] = timeout
            else:
                return None

        if TFTP_OPTION_TSIZE in opts:
            used[TFTP_OPTION_TSIZE] = int(opts[TFTP_OPTION_TSIZE])

        return used

    createRRQ = staticmethod(createRRQ)
    createWRQ = staticmethod(createWRQ)
    createACK = staticmethod(createACK)
    createDATA = staticmethod(createDATA)
    createERROR = staticmethod(createERROR)
    createOACK = staticmethod(createOACK)

    parseRRQ = staticmethod(parseRRQ)
    parseWRQ = staticmethod(parseWRQ)
    parseACK = staticmethod(parseACK)
    parseDATA = staticmethod(parseDATA)
    parseERROR = staticmethod(parseERROR)
    parseOACK = staticmethod(parseOACK)

    getOP = staticmethod(getOP)
    parse_options = staticmethod(parse_options)
