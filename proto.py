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

import re
import struct

# The following values are defined in the following RFC documents:
#   - RFC1350 - The TFTP Protocol (revision 2)
#   - RFC2347 - TFTP Option Extension
#   - RFC2348 - TFTP Blocksize option
#   - RFC2349 - TFTP Timeout interval and Transfer size options

# TFTP data packet size. A data packet with a length less than this
# size is considered as being the last packet of the transmission.
TFTP_DEFAULT_PACKET_SIZE = 512

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

# UDP datagram size
UDP_TRANSFER_SIZE = 8192

# Command verbosity
_verbose = 1

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

        if _verbose > 0:
            print ("  >   %s: %s (mode: %s, opts: %s)" %
                   (TFTP_OPS[OP_RRQ], filename, mode, opts))

        packet = struct.pack('!H%dsc%dsc' % (len(filename), len(mode)),
                             OP_RRQ, filename, '\0', mode, '\0')

        for opt, val in opts.iteritems():
            packet += struct.pack('!%dsc%dsc' % (len(opt), len(str(val))),
                                  opt, '\0', val, '\0')

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

        if _verbose > 0:
            print ("  >   %s: %s (mode: %s)" %
                   (TFTP_OPS[OP_WRQ], filename, mode, opts))

        packet = struct.pack('!H%dsc%dsc' % (len(filename), len(mode)),
                             OP_RRQ, filename, '\0', mode, '\0')

        for opt, val in opts.iteritems():
            packet += struct.pack('!%dsc%dsc' % (len(opt), len(str(val))),
                                  opt, '\0', val, '\0')

        return packet

    def createACK(num):
        """
        Creates a packed TFTP ACK packet.

        Args:
          num (integer): the data packet number to ack.
        Returns:
          The ack packet as a string.
        """

        if _verbose > 1:
            print "  >   %s: %d" % (TFTP_OPS[OP_ACK], num)
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

        if _verbose > 0:
            print "  > %s: %d %s" % (TFTP_OPS[OP_ERROR], errno, error)
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

        if _verbose > 1:
            print "  >  %s: %d (len: %d)" % (TFTP_OPS[OP_DATA], num, len(data))
        return struct.pack('!HH%ds' % len(data), OP_DATA, num, data)


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
            return None

        filename = packet[0]
        mode = packet[1].lower()

        opts = {}
        for i in xrange(len(packet[2:])-1):
            opts[packet[i+2]] = packet[i+3]

        try:
            TFTP_MODES.index(mode)
            if filename != '':
                if _verbose > 0:
                    print ("  <   %s: %s (mode: %s, opts: %s)" %
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
            return None

        filename = packet[0]
        mode = packet[1].lower()

        opts = {}
        for i in xrange(len(packet[2:])-1):
            opts[packet[i+2]] = packet[i+3]

        try:
            TFTP_MODES.index(mode)
            if filename != '':
                if _verbose > 0:
                    print ("  <   %s: %s (mode: %s, opts: %s)" %
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

            if _verbose > 1:
                print "  <   %s: %d" % (TFTP_OPS[OP_ACK], num),
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

            if _verbose > 1:
                print "  <  %s: %d, %d bytes" % (TFTP_OPS[OP_DATA], num, len(data))
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

            if _verbose > 0:
                print "  < %s: %s" % (TFTP_OPS[OP_ERROR], errmsg)
            return errno, errmsg
        except (struct.error, IndexError):
            raise SyntaxError()

    def getOP(data):
        if data and len(data) >= 2:
            try:
                return struct.unpack('!H', data[:2])[0]
            except KeyError:
                raise SyntaxError()

        return None

    createRRQ = staticmethod(createRRQ)
    createWRQ = staticmethod(createWRQ)
    createACK = staticmethod(createACK)
    createDATA = staticmethod(createDATA)
    createERROR = staticmethod(createERROR)

    parseRRQ = staticmethod(parseRRQ)
    parseWRQ = staticmethod(parseWRQ)
    parseACK = staticmethod(parseACK)
    parseDATA = staticmethod(parseDATA)
    parseERROR = staticmethod(parseERROR)

    getOP = staticmethod(getOP)
