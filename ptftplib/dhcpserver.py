#!/usr/bin/env python

# Author:     David Anderson
#             dave@natulte.net
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

"""PXE DHCP Server.

This is a very simple, stripped down DHCP server, designed exclusively
as a complement to pTFTPd. It cannot handle anything complicated, and
only responds to DHCP requests that clearly originate from a system
attempting to PXE boot. Use in conjunction with ptftpd.py to have a
full, yet lightweight PXE boot setup.
"""

import errno
import logging
import random
import socket
import struct
import sys
import time

from . import notify

l = notify.getLogger('dhcpd')

# The IP protocol number in Ethernet frames.
ETHERNET_IP_PROTO = 0x800

# The UDP protocol number in IP datagrams.
IP_UDP_PROTO = 0x11

# The DHCP magic cookie value that precedes option fields.
DHCP_MAGIC_COOKIE = 0x63825363

# DHCP operation types. There are others, but we don't care.
DHCP_OP_DHCPDISCOVER = 1
DHCP_OP_DHCPOFFER = 2
DHCP_OP_DHCPREQUEST = 3
DHCP_OP_DHCPACK = 5

# DHCP options we care about.
DHCP_OPTION_SUBNET = 1                # Subnet mask
DHCP_OPTION_ROUTER = 3                # Router
DHCP_OPTION_REQUESTED_IP = 50         # Requested IP address
DHCP_OPTION_LEASE_TIME = 51           # Lease time for the IP address
DHCP_OPTION_OP = 53                   # The DHCP operation (see above)
DHCP_OPTION_SERVER_ID = 54            # Server Identifier (IP address)
DHCP_OPTION_PXE_REQ = 55              # The most basic PXE option. We
                                      # only use this to identify PXE
                                      # requests.
DHCP_OPTION_CLIENT_UUID = 61          # The client machine UUID
DHCP_OPTION_PXE_VENDOR = 43           # PXE vendor extensions
DHCP_OPTION_CLIENT_UUID2 = 97         # The client machine UUID

# Client UUID length. Some PXE clients use UUID2 to provide the client machine
# MAC address, resulting in invalid UUID parsing. We ensure we're dealing with
# client UUID by checking their length (16 bytes).
DHCP_CLIENT_UUID_LENGTH = 16

# DHCP lease timeout in seconds. Internally, we wait longer, to let
# the client wrap up cleanly.
DHCP_LEASE_TIMEOUT = 10*60            # 10 minutes
DHCP_LEASE_TIMEOUT_INTERNAL = 15*60   # 15 minutes

# Linux ioctl() commands to query the kernel.
SIOCGIFADDR = 0x8915                  # IP address for interface
SIOCGIFNETMASK = 0x891B               # Netmask for interface
SIOCGIFHWADDR = 0x8927                # Mac address for interface


def get_ip_config_for_iface(iface):
    """Retrieve and return the IP address/netmask of the given interface."""
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
    return ip_from_response(ip), ip_from_response(mask), mac_from_response(mac)


def _dhcp_options(options):
    """Generate a sequence of DHCP options from a raw byte stream."""
    i = 0
    while i < len(options):
        code = ord(options[i])

        # Handle pad and end options.
        if code == 0:
            i += 1
            continue
        if code == 255:
            return

        # Extract and yield the option number and option value.
        data_len = ord(options[i+1])
        data = options[i + 2:i + 2 + data_len]
        i += 2 + data_len
        yield (code, data)


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


def _unpack_uuid(uuid):
    """Unpack a PXE UUID to its long form
    (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)."""
    fields = ['%02x' % x for x in struct.unpack('!16B', uuid)]
    return '%s-%s-%s-%s-%s' % (''.join(fields[:4]),
                               ''.join(fields[4:6]),
                               ''.join(fields[6:8]),
                               ''.join(fields[8:10]),
                               ''.join(fields[10:16]))


class NotDhcpPacketError(Exception):
    """Packet being decoded is not a DHCP packet."""


class UninterestingDhcpPacket(Exception):
    """Packet is DHCP, but not of interest to us."""


class DhcpPacket(object):
    def __init__(self, pkt):
        # Check the ethernet type. It needs to be IP (0x800).
        if struct.unpack('!H', pkt[12:14])[0] != ETHERNET_IP_PROTO:
            raise NotDhcpPacketError()
        self.server_mac, self.client_mac = pkt[0:6], pkt[6:12]

        # Strip off the ethernet frame and check the IP packet type. It should
        # be UDP (0x11)
        pkt = pkt[14:]
        if ord(pkt[9]) != IP_UDP_PROTO:
            raise NotDhcpPacketError()

        # Strip off the IP header and check the source/destination ports in the
        # UDP datagram. The packet should be from port 68 to port 67 to
        # tentatively be DHCP.
        header_len = (ord(pkt[0]) & 0xF) * 4
        pkt = pkt[header_len:]
        (src, dst) = struct.unpack('!2H', pkt[:4])
        if not (src == 68 and dst == 67):
            raise NotDhcpPacketError()

        # Looks like a DHCP request. Parse out the interesting data from the
        # base DHCP packet and check that the magic cookie is right.
        dhcp_fmt = '!12xL20x6s202xL'
        dhcp_size = struct.calcsize(dhcp_fmt)
        (xid, mac, cookie) = struct.unpack(dhcp_fmt, pkt[:dhcp_size])

        if cookie != DHCP_MAGIC_COOKIE or self.client_mac != mac:
            raise NotDhcpPacketError()

        self.xid = xid

        self.uuid = 'not specified'

        self._parse_dhcp_options(pkt[dhcp_size:])

    def _parse_dhcp_options(self, options):
        self.unknown_options = []
        self.is_pxe_request = False
        self.requested_ip = None

        for option, value in _dhcp_options(options):
            if option == DHCP_OPTION_OP:
                self.op = ord(value)
                # We only care about interesting "incoming" DHCP ops.
                if self.op not in (DHCP_OP_DHCPDISCOVER, DHCP_OP_DHCPREQUEST):
                    raise UninterestingDhcpPacket()
            elif (option in (DHCP_OPTION_CLIENT_UUID,
                             DHCP_OPTION_CLIENT_UUID2) and
                  len(value[1:]) == DHCP_CLIENT_UUID_LENGTH):
                # First byte of the UUID is \0
                self.uuid = _unpack_uuid(value[1:])
            elif option == DHCP_OPTION_PXE_REQ:
                self.is_pxe_request = True
            elif option == DHCP_OPTION_REQUESTED_IP:
                self.requested_ip = _unpack_ip(value)
            else:
                # Keep them around, in case other code feels like
                # being knowledgeable.
                self.unknown_options.append((option, value))


class DHCPServer(object):
    def __init__(self, interface, bootfile, router=None, tftp_server=None):
        self.interface = interface
        self.ip, self.netmask, self.mac = get_ip_config_for_iface(interface)
        self.bootfile = bootfile
        self.router = router or self.ip
        self.tftp_server = tftp_server or self.ip
        self.ips_allocated = {}

        self.sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        self.sock.bind((self.interface, ETHERNET_IP_PROTO))

    def serve_forever(self):
        l.info('Serving PXE DHCP requests on %s' % self.interface)
        while True:
            data = self.sock.recv(4096)
            try:
                pkt = DhcpPacket(data)
                self.handle_dhcp_request(pkt)
            except (NotDhcpPacketError, UninterestingDhcpPacket):
                continue

    def handle_dhcp_request(self, pkt):
        if not pkt.is_pxe_request:
            l.info('Ignoring non-PXE DHCP request')
            return

        # Clean up old leases before trying to get one for our new
        # client.
        self.gc_allocated_ips()

        if pkt.op == DHCP_OP_DHCPDISCOVER:
            ip = self.generate_free_ip()
            l.info('Offering to boot client %s (uuid : %s)' % (ip, pkt.uuid))
        elif pkt.op == DHCP_OP_DHCPREQUEST:
            timeout = time.time() + DHCP_LEASE_TIMEOUT_INTERNAL
            if (pkt.requested_ip and
                    pkt.requested_ip not in self.ips_allocated):
                self.ips_allocated[pkt.requested_ip] = timeout
                ip = pkt.requested_ip
            else:
                ip = self.generate_free_ip()
                self.ips_allocated[ip] = timeout
            l.info('PXE booting client %s (uuid : %s)' % (ip, pkt.uuid))

        self.sock.send(self.encode_dhcp_reply(pkt, ip))

    def gc_allocated_ips(self):
        current = time.time()
        old = [ip for ip, to in self.ips_allocated.iteritems()
               if to <= current]
        for ip in old:
            l.info('Lease on %s expired' % ip)
            del self.ips_allocated[ip]

    def encode_dhcp_reply(self, request_pkt, client_ip):
        # Basic DHCP reply
        reply = struct.pack('!B'    # The op (0x2)
                            'B'     # The htype (Ethernet -> 0x1)
                            'B'     # The hlen (0x6)
                            'x'     # The hops field, useless
                            'L'     # XID
                            '8x'    # Useless fields
                            '4s'    # Client IP address
                            '4s'    # Next server IP address (TFTP server)
                            '4x'    # Useless fields
                            '6s'    # Client MAC address
                            '74x'   # BOOTP legacy padding.
                            '128s'  # PXE boot file
                            'L',    # Magic cookie
                            0x2, 0x1, 0x6, request_pkt.xid,
                            _pack_ip(client_ip), _pack_ip(self.tftp_server),
                            request_pkt.client_mac, self.bootfile,
                            DHCP_MAGIC_COOKIE)

        # DHCP options relevant to PXE
        reply_kind = {
            DHCP_OP_DHCPDISCOVER: DHCP_OP_DHCPOFFER,
            DHCP_OP_DHCPREQUEST: DHCP_OP_DHCPACK
            }[request_pkt.op]
        dhcp_options = (
            (DHCP_OPTION_OP, chr(reply_kind)),
            (DHCP_OPTION_LEASE_TIME, struct.pack('!L', DHCP_LEASE_TIMEOUT)),
            (DHCP_OPTION_SUBNET, _pack_ip(self.netmask)),
            (DHCP_OPTION_ROUTER, _pack_ip(self.router)),
            (DHCP_OPTION_SERVER_ID, _pack_ip(self.ip)),
            )
        buf = []
        for code, data in dhcp_options:
            buf.append(struct.pack('!BB', code, len(data)))
            buf.append(data)
        reply += ''.join(buf)

        # Construct the UDP datagram. We don't checksum, for
        # simplicity. UDP conformant clients should not care anyway, we
        # set the field to the "checksum not computed" value.
        reply = struct.pack('!HHH2x', 67, 68, len(reply) + 8) + reply

        # Now the IP datagram...
        ip_header1 = struct.pack('!BxH4xBB', 0x45, 20+len(reply), 0xFF,
                                 IP_UDP_PROTO)
        ip_header2 = struct.pack('4s4s', _pack_ip(self.ip),
                                 _pack_ip('255.255.255.255'))
        # Header checksum computation
        checksum = 0
        for v in struct.unpack('!5H', ip_header1) + \
                struct.unpack('!4H', ip_header2):
            checksum += v
            if checksum > 2**16:
                checksum = (checksum & 0xFFFF) + 1
        checksum = 0xFFFF - checksum
        reply = ip_header1 + struct.pack('!H', checksum) + ip_header2 + reply

        # And finally the ethernet frame.
        reply = struct.pack('!6s6sH', _pack_mac('ff:ff:ff:ff:ff:ff'),
                            _pack_mac(self.mac),
                            ETHERNET_IP_PROTO) + reply

        # Bingo, one DHCP reply russian doll^W^Wpacket!
        return reply

    def generate_free_ip(self):
        server_ip = struct.unpack('!L', _pack_ip(self.ip))[0]
        netmask = struct.unpack('!L', _pack_ip(self.netmask))[0]
        anti_netmask = 0xFFFFFFFF - netmask

        while True:
            entropy = random.getrandbits(32)

            client_ip = (server_ip & netmask) | (entropy & anti_netmask)

            # Exclude using the server's address, the network's
            # address, the broadcast address, and any IP already in
            # use.
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

    usage = "Usage: %prog [options] <iface> <PXE boot filename>"
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

    # Setup notification logging
    notify.StreamEngine.install(l, stream=sys.stdout,
                                loglevel=options.loglevel,
                                format='%(levelname)s(%(name)s): %(message)s')

    try:
        server = DHCPServer(iface, bootfile, router=options.router,
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
