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

from setuptools import setup, find_packages

from ptftplib.version import name, version

with open('README.rst') as readme:
    long_description = readme.read()

with open('requirements.txt') as f:
    requirements = [line.strip() for line in f.readlines()]

setup(
    name=name,
    version=version,
    author='Maxime Petazzoni',
    author_email='maxime.petazzoni@bulix.org',
    description='pTFTPd, a pure-Python TFTP tool suite that works',
    license='GNU General Public License v2',
    long_description=long_description,
    zip_safe=True,
    install_requires=requirements,
    packages=find_packages(),
    entry_points={
        'console_scripts':
            ['bootpd=ptftplib.bootpserver:main',
             'dhcpd=ptftplib.dhcpserver:main',
             'ptftp=ptftplib.tftpclient:main',
             'ptftpd=ptftplib.tftpserver:main',
             'pxed=ptftplib.pxeserver:main'],
    },
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    url='https://github.com/mpetazzoni/ptftpd',
)
