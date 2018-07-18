pTFTPd - A pure-Python TFTP tool suite
======================================

pTFTPd is a collection of tools related to TFTP. It includes a TFTP
server, a TFTP client, and a complete PXE solution based on this TFTP
server and a micro-DHCP or BOOTP server. All these tools are written in
Python and designed to be fast, RFC compliant and easy to use.

Available tools include:

-  ``bootpd``: a BOOTP server (RFC951 and RFC1497 compliant)
-  ``dhcpd``: a simple, stripped-down DHCP server.
-  ``ptftpd``: the TFTP server (RFC1350, 2347, 2348, 2349 and 7440 compliant)
-  ``pxed``: a one-call PXE server using dhcpd and ptftpd.
-  ``ptftp``: a simple TFTP client (RFC1350, 2347, 2348, 2349 and 7440
   compliant and capable)

They all support the ``--help`` option to present the usage summary to
the user.

All tools also understand the ``--rfc1350`` option, which forces them in
basic TFTP RFC1350 compliance mode, disabling all TFTP extensions for
increased compatibility would you encouter any problem with your target
system.

Installation
------------

pTFTPd is available on PyPI as the ``ptftpd`` distribution.

.. code::

    $ pip install ptftpd

This will install the ``ptftplib`` Python package, as well as the scripts
listed above.

If you use the pTFTPd tool suite outside of a standard distribution
installation, you may need to specify the Python module search path with
``PYTHONPATH`` before executing the binaries:

.. code::

    $ export PYTHONPATH=`pwd`
    $ bin/ptftp
    Connected to localhost:69.

    tftp>

TFTP server and client
----------------------

The TFTP server, pTFTPd, fully supports the TFTP specification as
defined in RFC1350. It also supports the TFTP Option Extension protocol
(per RFC2347), the block size option as defined in RFC2348 and the
transfer size option from RFC2349.

For help on how to use pTFTPd, type:

.. code::

    $ ptftpd --help

The port used can be changed using the ``-p`` option. The root path is
given as a simple argument. For example, to serve ``/var/lib/tftp`` on
port 6969 through the eth0 network interface:

.. code::

    $ ptftpd -p 6969 eth0 /var/lib/tftp

The TFTP client is an interactive client, just launch it and type
``help`` to see the available commands:

.. code::

    $ ptftp
    tftp> help
    ...

PXE solution
------------

The PXE system is also very easy to use. It takes three arguments: the
network interface to listen on, the TFTP root path from which to serve
files, and the PXE boot filename. It will automatically start a TFTP
server and a DHCP server to serve hosts on the given interface. See
``--help`` for more details:

.. code::

    $ pxed --help

Mechanics for using ``pxed.py`` with the BOOTP server are not yet in
place, but such a solution can easily be constructed manually by
starting the BOOTP server and the TFTP server manually:

.. code::

    $ bootpd <interface> <PXE boot file> &
    $ ptftpd <interface>
