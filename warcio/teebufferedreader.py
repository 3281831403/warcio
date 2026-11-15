"""
A reader wrapper which tees every byte read from the wrapped stream
into a spool file and counts the logical (post-decompression) bytes
consumed, enabling byte-exact capture of record blocks while still
parsing them normally.
"""

import tempfile


# ============================================================================
class TeeBufferedReader(object):
    """ Wrap a buffered reader and copy all consumed bytes (both line and
    block reads) into a spooled temporary file, so callers can recover the
    exact on-the-wire bytes of records as they were parsed.

    ``num_read`` counts logical bytes handed to the parser, which for a
    decompressing reader is the position in the decompressed stream. Because
    the underlying buffered reader may read ahead in blocks, the count is the
    only reliable record boundary: spool file positions are not guaranteed to
    be monotonic relative to parser consumption.

    An optional ``on_statusline`` callback is invoked with the logical position
    immediately before every ``readline`` call whose returned line starts with
    one of the given status-line prefixes. This lets callers record the exact
    start of each record's header regardless of how blank-line separators are
    consumed, which differs between plain and gzipped archives.

    The wrapped object is otherwise used unchanged: all other attributes and
    methods are delegated via __getattr__.
    """

    def __init__(self, inner, spool=None, on_statusline=None,
                 statusline_prefixes=(b'WARC/',)):
        self.inner = inner
        self.spool = spool or tempfile.SpooledTemporaryFile(max_size=512 * 1024)
        self.num_read = 0
        self.on_statusline = on_statusline
        self.statusline_prefixes = tuple(statusline_prefixes)

    def read(self, length=None):
        if length is None:
            data = self.inner.read()
        else:
            data = self.inner.read(length)
        self._consumed(data)
        return data

    def readline(self, length=None):
        position_before = self.num_read
        if length is None:
            data = self.inner.readline()
        else:
            data = self.inner.readline(length)
        self._consumed(data)

        if self.on_statusline is not None and data.startswith(self.statusline_prefixes):
            self.on_statusline(position_before)

        return data

    def _consumed(self, data):
        self.spool.write(data)
        self.num_read += len(data)

    def tell(self):
        return self.num_read

    def __getattr__(self, name):
        return getattr(self.inner, name)
