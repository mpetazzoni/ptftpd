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

"""Notification and logging system for the pTFTPd tool suite.

This module implements a notification engine for the pTFTPd tools using
Python's logging module. Its main feature include easily configurable
notifications from various TFTP events such as start and end of a file
transfer.

These event notifications can be routed to several destinations by adding one
or more engines to the notification chain.
"""

import logging
import sys

# Transfer states
TRANSFER_STARTED = 1
TRANSFER_COMPLETED = 2
TRANSFER_FAILED = 3

_STATE_NAMES = {
        TRANSFER_STARTED: 'STARTED',
        TRANSFER_COMPLETED: 'COMPLETED',
        TRANSFER_FAILED: 'FAILED',
}


class NullEngine(logging.Handler):
    """A no-op notification engine. Simply results in no logging messages being
    outputted anywhere."""

    def emit(self, record):
        pass

    @staticmethod
    def install(logger):
        logger.addHandler(NullEngine())


class StreamEngine(logging.StreamHandler):
    """Simple stream log handler, similar to what you get using
    logging.basicConfig."""

    def __init__(self, stream, loglevel, format):
        """Creates a new notification engine that simply logs to the given
        stream.

        Args:
            stream (stream): logging stream.
            loglevel (logging.loglevel): minimum level of messages to be
                outputted.
            format (string format): default format string to apply
                on log messages.
        """

        logging.StreamHandler.__init__(self, stream)

        self.setFormatter(logging.Formatter(format))
        self.setLevel(loglevel)

    @staticmethod
    def install(logger, stream=sys.stderr, loglevel=logging.WARNING,
                format='%(message)s'):
        handler = StreamEngine(stream, loglevel, format)
        logger.addHandler(handler)


class DetailFilter(logging.Filter):
    """This log filter filters log records that don't posess the extra
    information we require for advanced notifications (host, port, file name
    and transfer state)."""

    def filter(self, record):
        r = record.__dict__
        return ('host' in r and 'port' in r and 'file' in r and 'state' in r)


class DetailledStreamEngine(StreamEngine):
    """The DetailledStreamEngine is a extension of the StreamEngine define
    above designed to log detailled notifications. Pertinent log records are
    filtered using the DetailFilter, as set up by the install() method."""

    def emit(self, record):
        """Emits the given LogRecord object, first replacing the transfer state
        by its string representation. The original state numeric value is
        restored afterwards for other log handlers down the chain."""

        state = record.state
        record.state = _STATE_NAMES[record.state]

        # Emit the log entry using the parent's method
        StreamEngine.emit(self, record)
        record.state = state

    @staticmethod
    def install(logger, stream=sys.stderr, loglevel=logging.INFO,
                format='%(message)s (%(host)s:%(port)d#%(file)s %(state)s)'):
        handler = DetailledStreamEngine(stream, loglevel, format)
        handler.addFilter(DetailFilter())
        logger.addHandler(handler)


class CallbackEngine(logging.Handler):
    """The CallbackEngine is another notification engine, using a callback
    mechanism. When a LogRecord is received by this handler and makes it
    through the DetailFilter, a callback function matchin the transfer state
    provided in the LogRecord object is called, passing the detail information
    along."""

    def __init__(self, callbacks):
        """Creates a callback notification engine using the provided callback
        mapping. This handler has a default loglevel of logging.DEBUG, hence
        making sure all messages that pass the filter will be processed and
        result in a callback call."""

        logging.Handler.__init__(self, logging.DEBUG)
        self.callbacks = callbacks

    def _nop(self, **kwargs):
        """Define a no-op callback to use as a default when no callback is
        provided for a transfer state."""
        pass

    def emit(self, record):
        """Call the defined callback for the transfer state found in the log
        record."""

        callable = self.callbacks.get(record.state, self._nop)
        callable(host=record.host,
                 port=record.port,
                 file=record.file,
                 state=record.state)

    @staticmethod
    def install(logger, callbacks={}):
        handler = CallbackEngine(callbacks)
        handler.addFilter(DetailFilter())
        logger.addHandler(handler)


def getLogger(name):
    """Return a named logger usable with the notification engines defined in
    this module. This logger is set with a loglevel of logging.DEBUG to make
    sure all log messages are processed by the logger and handed over to the
    attached handlers. It is then the responsibility of the handlers to define
    their desired logging level."""

    l = logging.getLogger(name)
    l.setLevel(logging.DEBUG)
    return l
