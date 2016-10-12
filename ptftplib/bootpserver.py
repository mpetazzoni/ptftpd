#!/usr/bin/env python

# Authors:    David Anderson
#             dave@natulte.net
#             Maxime Ripard
#             maxime.ripard@anandra.org
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

"""BOOTP Server.

This is a minimal BOOTP Server.  It fully complies with the RFC951 and supports
the BOOTP options defined in RFC1497.

If you are looking for something more advanced, use dhcpd.py, which is a more
complete DHCP server, but just as efficient.
"""

import errno
import logging
import random
import socket
import struct
import sys

l = logging.getLogger('bootpd')

# The IP protocol number in Ethernet frames.
ETHERNET_IP_PROTO = 0x800

# The UDP protocol number in IP datagrams.
IP_UDP_PROTO = 0x11

# The full size of a BOOTP packet
BOOTP_PACKET_SIZE = 300

# The BOOTP magic cookie value that precedes option fields.
BOOTP_MAGIC_COOKIE = 0x63825363

# BOOTP operation types.
BOOTP_OP_BOOTPREQUEST = 1
BOOTP_OP_BOOTPREPLY = 2

# BOOTP vendor information extensions, as defined in RFC 1497
BOOTP_OPTION_PAD = 0
BOOTP_OPTION_SUBNET = 1
BOOTP_OPTION_OFFSET = 2
BOOTP_OPTION_GATEWAY = 3
BOOTP_OPTION_TIMESERVER = 4
BOOTP_OPTION_IEN_NAMESERVER = 5
BOOTP_OPTION_DNS = 6
BOOTP_OPTION_LOGSERVER = 7
BOOTP_OPTION_QUOTESERVER = 8
BOOTP_OPTION_LPRSERVER = 9
BOOTP_OPTION_IMPRESSSERVER = 10
BOOTP_OPTION_RLPSERVER = 11
BOOTP_OPTION_HOSTNAME = 12
BOOTP_OPTION_BOOTFILESIZE = 13
BOOTP_OPTION_MERITDUMP = 14
BOOTP_OPTION_DOMAINNAME = 15
BOOTP_OPTION_SWAPSERVER = 16
BOOTP_OPTION_ROOTPATH = 17
BOOTP_OPTION_EXTENSION = 18
BOOTP_OPTION_END = 255

# Linux ioctl() commands to query the kernel.
SIOCGIFADDR = 0x8915                  # IP address for interface
SIOCGIFNETMASK = 0x891B               # Netmask for interface
SIOCGIFHWADDR = 0x8927                # MAC address for interface


def get_ip_config_for_iface(iface):
    """Retrieve and return the IP address/netmask and MAC address of the
    given interface."""

    if 'linux' not in sys.platform:
        raise NotImplementedError("get_ip_address_for_iface is not "
                                  "implemented on your OS.")

    def ip_from_response(resp):
        return socket.inet_ntoa(resp[20:24])

    def mac_from_response(resp):
        mac = struct.unpack('!6B', resp[18:24])
        return ':'.join(['%02x' % x for x in mac])

    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = struct.pack('256s', iface[:15])
    ip = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifname)
    mask = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, ifname)
    mac = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifname)
    return ip_from_response(ip), ip_from_response(mask), \
        mac_from_response(mac)


def compute_checksum(message):
    """Calculates the 16-bit one's complement of the one's complement sum
    of a given message."""

    # If the message length isn't a multiple of 2 bytes, we pad with
    # zeros
    if len(message) % 2:
        message += struct.pack('x')

    # We build our blocks to sum
    to_sum = struct.unpack('!%dH' % (len(message)/2), message)

    # UDP checksum
    checksum = 0
    for v in to_sum:
        checksum += v
        if checksum > 2**16:
            checksum = (checksum & 0xFFFF) + 1
    return 0xFFFF - checksum


def _pack_ip(ip_addr):
    """Pack a dotted quad IP string into a 4 byte string."""
    return socket.inet_aton(ip_addr)


def _unpack_ip(ip_addr):
    """Unpack a 4 byte IP address into a dotted quad string."""
    return socket.inet_ntoa(ip_addr)


def _pack_mac(mac_addr):
    """Pack a MAC address (00:00:00:00:00:00) into a 6 byte string."""
    fields = [int(x, 16) for x in mac_addr.split(':')]
    return struct.pack('!6B', *fields)


class NotBootpPacketError(Exception):
    """Packet being decoded is not a BOOTP packet."""


class UninterestingBootpPacket(Exception):
    """Packet is BOOTP, but we just don't care about it."""


class BootpPacket(object):
    def __init__(self, pkt):
        # Check the ethernet type. It needs to be IP (0x800).
        if struct.unpack('!H', pkt[12:14])[0] != ETHERNET_IP_PROTO:
            raise NotBootpPacketError()
        self.server_mac, self.client_mac = pkt[0:6], pkt[6:12]

        # Strip off the ethernet frame and check the IP packet type. It should
        # be UDP (0x11)
        pkt = pkt[14:]
        if ord(pkt[9]) != IP_UDP_PROTO:
            raise NotBootpPacketError()

        # Strip off the IP header and check the source/destination ports in the
        # UDP datagram. The packet should be from port 68 to port 67 to be
        # BOOTP. We don't care about checksum here
        header_len = (ord(pkt[0]) & 0xF) * 4
        pkt = pkt[header_len:]
        (src, dst) = struct.unpack('!2H4x', pkt[:8])
        if not (src == 68 and dst == 67):
            raise NotBootpPacketError()

        # Looks like a BOOTP request. Strip off the UDP headers, parse out the
        # interesting data from the base BOOTP packet and check that the magic
        # cookie is right.
        pkt = pkt[8:]
        bootp_fmt = '!4xL20x6s10x64s128xL'
        bootp_size = struct.calcsize(bootp_fmt)
        (xid, mac, sname, cookie) = struct.unpack(bootp_fmt, pkt[:bootp_size])

        # We strip off the padding bytes
        try:
            sname = sname[:sname.index('\x00')]
        except ValueError:
            pass

        self.sname = sname

        if cookie != BOOTP_MAGIC_COOKIE or self.client_mac != mac:
            raise NotBootpPacketError()

        self.xid = xid


class BOOTPServer(object):
    def __init__(self, interface, bootfile, router=None, tftp_server=None):
        self.interface = interface
        self.ip, self.netmask, self.mac = get_ip_config_for_iface(interface)
        self.hostname = socket.gethostname()
        self.bootfile = bootfile
        self.router = router or self.ip
        self.tftp_server = tftp_server or self.ip
        self.ips_allocated = {}

        self.sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        self.sock.bind((self.interface, ETHERNET_IP_PROTO))

    def serve_forever(self):
        l.info('Serving BOOTP requests on %s' % self.interface)
        while True:
            data = self.sock.recv(4096)
            try:
                pkt = BootpPacket(data)
                self.handle_bootp_request(pkt)
            except (NotBootpPacketError, UninterestingBootpPacket):
                continue

    def handle_bootp_request(self, pkt):
        # If the server is explicitly requested, and it's not ours,
        # we just ignore it
        if pkt.sname and pkt.sname != self.hostname:
            raise UninterestingBootpPacket()

        ip = self.generate_free_ip()
        l.info('Offering to boot client %s' % ip)
        l.info('Booting client %s with file %s' % (ip, self.bootfile))

        self.sock.send(self.encode_bootp_reply(pkt, ip))

    def encode_bootp_reply(self, request_pkt, client_ip):
        # Basic BOOTP reply
        reply = struct.pack('!B'    # The op (0x2)
                            'B'     # The htype (Ethernet -> 0x1)
                            'B'     # The hlen (0x6)
                            'x'     # The hops field, useless
                            'L'     # XID
                            '2x'    # secs since boot, useless for the server
                            'H'     # bootp flags (Broadcast -> 0x8000)
                            '4x'    # ciaddr, useless for the server
                            '4s'    # Client IP address
                            '4s'    # Next server IP address (TFTP server)
                            '4x'    # Gateway IP Adress, useless
                            '6s'    # Client MAC address
                            '10x'   # End of MAC Address
                            '64s'   # Server host name, often useless
                            '128s'  # PXE boot file
                            'L',    # Magic cookie
                            0x2, 0x1, 0x6, request_pkt.xid, 0x8000,
                            _pack_ip(client_ip), _pack_ip(self.tftp_server),
                            request_pkt.client_mac, self.hostname,
                            self.bootfile, BOOTP_MAGIC_COOKIE)

        bootp_options = (
            (BOOTP_OPTION_SUBNET, _pack_ip(self.netmask)),
            (BOOTP_OPTION_GATEWAY, _pack_ip(self.router)),
            )

        options = ''
        for option, data in bootp_options:
            options += struct.pack('!BB', option, len(data))
            options += data
        reply += options + struct.pack('!B', 0xff)

        # We add the padding bytes to fit the full size of a BOOTP packet
        if len(reply) < BOOTP_PACKET_SIZE:
            reply += struct.pack(str(BOOTP_PACKET_SIZE - len(reply)) + 'x')

        # Construct the UDP datagram.
        # First, the checksum. Here we build our pseudo IP headers required
        # for the checksum, and then compute the checksum.
        udp_headers = struct.pack('!HHH', 67, 68, len(reply) + 8)
        pseudo_header = struct.pack('!4s4sxBH', _pack_ip(self.ip),
                                    _pack_ip('255.255.255.255'), IP_UDP_PROTO,
                                    len(udp_headers) + 2 + len(reply))

        pseudo_packet = pseudo_header + udp_headers + reply
        checksum = compute_checksum(pseudo_packet)

        reply = udp_headers + struct.pack('!H', checksum) + reply

        # Now the IP datagram...
        ip_header1 = struct.pack('!BxH4xBB', 0x45, 20+len(reply), 0xFF,
                                 IP_UDP_PROTO)
        ip_header2 = struct.pack('4s4s', _pack_ip(self.ip),
                                 _pack_ip('255.255.255.255'))
        checksum = compute_checksum(ip_header1 + ip_header2)

        reply = ip_header1 + struct.pack('!H', checksum) + ip_header2 + reply

        # And finally the ethernet frame.
        reply = struct.pack('!6s6sH', _pack_mac('ff:ff:ff:ff:ff:ff'),
                            _pack_mac(self.mac),
                            ETHERNET_IP_PROTO) + reply

        # And here is our BOOTP packet
        return reply

    def generate_free_ip(self):
        server_ip = struct.unpack('!L', _pack_ip(self.ip))[0]
        netmask = struct.unpack('!L', _pack_ip(self.netmask))[0]
        anti_netmask = 0xFFFFFFFF - netmask

        while True:
            entropy = random.getrandbits(32)

            client_ip = (server_ip & netmask) | (entropy & anti_netmask)

            # Exclude using the server's address, the network's address, the
            # broadcast address, and any IP already in use.
            if (client_ip == server_ip or
                    (client_ip & netmask) == 0 or
                    (client_ip | netmask) == 0xFFFFFFFF):
                continue

            ip = _unpack_ip(struct.pack('!L', client_ip))
            if ip in self.ips_allocated:
                continue

            return ip


def main():
    import optparse

    usage = "Usage: %prog <interface> <PXE boot file>"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-t", "--tftp-server", dest="tftp_server",
                      help="The IP address of the TFTP server, if not running "
                      "on this machine", default=None)
    parser.add_option("-g", "--gateway", dest="router",
                      help="The IP address of the default gateway, if not "
                      "this machine", default=None)
    parser.add_option("-v", "--verbose", dest="loglevel", action="store_const",
                      const=logging.INFO, help="Output information messages",
                      default=logging.WARNING)

    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        return 1

    iface, bootfile = args

    logging.basicConfig(stream=sys.stdout, level=options.loglevel,
                        format='%(levelname)s(%(name)s): %(message)s')

    try:
        server = BOOTPServer(iface, bootfile, router=options.router,
                             tftp_server=options.tftp_server)
        server.serve_forever()
    except socket.error, e:
        sys.stderr.write('Socket error (%s): %s!\n' %
                         (errno.errorcode[e[0]], e[1]))
        return 1

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
