#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author:     Marc Poulhiès
#             dkm@kataplop.net
#
# This file is part of pTFTPd.
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

from distutils.core import setup

setup(name = "ptftpd",
    description = "pTFTPd, a pure-Python TFTP tool suite that works",
    long_description = """
pTFTPd is a pure-Python TFTP tool suite. It features a TFTP server and client
fully compliant to the TFTP specification defined in RFC1350. It also supports
the TFTP Option Extension protocol (per RFC2347), the block size option as
defined in RFC2348 and the transfer size option from RFC2349.

The pTFTPd tool suite also includes a mini-DHCP server, a BOOTP server, and a
complexe PXE solution based on the DHCP and TFTP servers.
""",
    version = "1.0",

    author = 'Maxime Petazzoni',
    author_email = 'maxime.petazzoni@bulix.org',
    url = "https://github.com/mpetazzoni/ptftpd",
    license = "GPL",

    maintainer = 'Maxime Petazzoni',
    maintainer_email = 'maxime.petazzoni@bulix.org',

    packages = ['ptftplib'],
    scripts = ['bin/%s' % i for i in ["bootpd",
                                      "ptftpd",
                                      "pxed",
                                      "ptftp",
                                      "dhcpd"]],
)

