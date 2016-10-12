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

"""PXE Server.

This program offers a streamlined combination of ptftpd.py and
dhcpd.py in a single executable. With both daemons running side by
side, the amount of configuration required to get a PXE boot system
working is laughably small: specify the interface, the directory to
serve over TFTP and the name of the PXE boot file, and you're all set.
"""

import errno
import logging
import socket
import sys
import threading

import notify
import tftpserver
import dhcpserver

l = notify.getLogger('pxed')


class DHCPThread(threading.Thread):
    def __init__(self, iface, bootfile, router):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.server = dhcpserver.DHCPServer(iface, bootfile, router=router)

    def run(self):
        self.server.serve_forever()


def main():
    import optparse

    usage = "Usage: %prog [options] <iface> <TFTP root> <PXE boot filename>"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-r", "--rfc1350", dest="strict_rfc1350",
                      action="store_true", default=False,
                      help="Run in strict RFC1350 compliance mode, "
                      "with no extensions")
    parser.add_option("-g", "--gateway", dest="router", default=None,
                      help="The IP address of the default gateway "
                      "(by default, the IP of the PXE server)")
    parser.add_option("-v", "--verbose", dest="loglevel", action="store_const",
                      const=logging.INFO, help="Output information messages",
                      default=logging.WARNING)
    parser.add_option("-D", "--debug", dest="loglevel", action="store_const",
                      const=logging.DEBUG, help="Output debugging information")

    (options, args) = parser.parse_args()
    if len(args) != 3:
        parser.print_help()
        return 1

    iface, root, bootfile = args

    # Setup notification logging
    notify.StreamEngine.install(l, stream=sys.stdout,
                                loglevel=options.loglevel,
                                format='%(levelname)s(%(name)s): %(message)s')
    notify.StreamEngine.install(dhcpserver.l, stream=sys.stdout,
                                loglevel=options.loglevel,
                                format='%(levelname)s(%(name)s): %(message)s')
    notify.StreamEngine.install(tftpserver.l, stream=sys.stdout,
                                loglevel=options.loglevel,
                                format='%(levelname)s(%(name)s): %(message)s')

    try:
        dhcp = DHCPThread(iface, bootfile, options.router)
        tftp = tftpserver.TFTPServer(iface, root,
                                     strict_rfc1350=options.strict_rfc1350)
    except tftpserver.TFTPServerConfigurationError, e:
        sys.stderr.write('TFTP server configuration error: %s!\n' %
                         e.message)
        return 1
    except socket.error, e:
        sys.stderr.write('Socket error (%s): %s!\n' %
                         (errno.errorcode[e[0]], e[1]))
        return 1

    dhcp.start()
    tftp.serve_forever()
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
