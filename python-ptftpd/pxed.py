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

import ptftpd
import dhcpd
import optparse
import sys
import threading
import logging

class DHCPThread(threading.Thread):
    def __init__(self, iface, bootfile, router):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.server = dhcpd.DHCPServer(iface, bootfile, router=router)

    def run(self):
        self.server.serve_forever()

def main():
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
        print 'Missing required arguments'
        parser.print_usage()
        sys.exit(1)

    iface, root, bootfile = args

    logging.basicConfig(stream=sys.stdout, level=options.loglevel,
                        format='%(levelname)s(%(name)s): %(message)s')

    try:
        dhcp = DHCPThread(iface, bootfile, options.router)
        tftp = ptftpd.TFTPServer(root, strict_rfc1350=options.strict_rfc1350)
    except ptftpd.TFTPServerConfigurationError, e:
        print 'TFTP server configuration error: %s' % e.message

    dhcp.start()
    tftp.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
