from warcio.archiveiterator import ArchiveIterator
from warcio.exceptions import ArchiveLoadFailed

from warcio.warcwriter import WARCWriter, GzippingWrapper
from warcio.bufferedreaders import DecompressingBufferedReader
from warcio.teebufferedreader import TeeBufferedReader
from warcio.utils import fsspec_open, BUFF_SIZE

import tempfile
import shutil
import traceback
import sys


# ============================================================================
class Recompressor(object):
    def __init__(self, filename, output, verbose=False, gzip=True):
        self.filename = filename
        self.output = output
        self.verbose = verbose
        self.gzip = gzip

    def recompress(self):
        from warcio.cli import main
        try:
            count = 0
            msg = ''
            with fsspec_open(self.filename, 'rb') as stream:
                try:
                    count = self.load_and_write(stream, self.output)
                    msg = 'No Errors Found!'
                except Exception as e:
                    if self.verbose:
                        print('Parsing Error(s) Found:')
                        print(str(e) if isinstance(e, ArchiveLoadFailed) else repr(e))
                        print()

                    count = self.decompress_and_recompress(stream, self.output)
                    msg = 'Compression Errors Found and Fixed!'

                if self.verbose:
                    print('Records successfully read and compressed:')
                    main(['index', self.output])
                    print('')

                print('{0} records read and recompressed to file: {1}'.format(count, self.output))
                print(msg)

        except:
            if self.verbose:
                print('Exception Details:')
                traceback.print_exc()
                print('')

            print('Recompress Failed: {0} could not be read as a WARC or ARC'.format(self.filename))
            sys.exit(1)

    def load_and_write(self, stream, output):
        """ Parse the stream and write it back out.

        WARC records that parse cleanly are copied byte-for-byte: the exact
        on-the-wire block of each record is captured while parsing and written
        unmodified, so no headers are rewritten, digests added or recomputed,
        offsets within blocks changed, or revisit payloads dropped. Each block
        becomes its own gzip member when gzip output is requested.

        ARC records (which are converted to WARC) and any record that cannot be
        handled on the byte-exact path fall back to the normal parse/serialize
        writer, as does decompression-repair of a broken compression layer.
        """
        with fsspec_open(output, 'wb') as out:
            # The byte-exact pass may only discover it cannot handle a record
            # partway through (e.g. an ARC record after some WARC records), so
            # stage its output in a separate buffer. Only once every block has
            # been copied do we commit it; a fallback never leaves partial
            # bytes in the real output.
            with tempfile.TemporaryFile() as staged:
                try:
                    count = self._copy_warc_bytes(stream, staged)
                except _FallbackToLegacy:
                    stream.seek(0)
                    return self._legacy_load_and_write(stream, out)

                staged.seek(0)
                shutil.copyfileobj(staged, out)
                return count

    def _copy_warc_bytes(self, stream, out):
        iterator = ArchiveIterator(stream,
                                   no_record_parse=False,
                                   arc2warc=False,
                                   verify_http=False)

        # tee the iterator's decompressing reader so every logical byte
        # consumed while parsing is also captured, in order, into a spool.
        # The spool is written strictly in logical (post-decompression) byte
        # order, so a logical offset N is exactly the index of the Nth byte.
        # The on_statusline callback records the logical start of every WARC
        # status line; anchoring on the parser's own status-line reads is
        # robust to the different ways plain and gzipped archives expose the
        # blank-line separators between records.
        header_starts = []
        tee = TeeBufferedReader(
            iterator.reader,
            on_statusline=lambda position: header_starts.append(position))
        iterator.reader = tee
        spool = tee.spool

        records = []
        for record in iterator:
            if record.format != 'warc':
                # ARC input is a format conversion, not a round trip; use the
                # legacy path which builds WARC headers for ARC records.
                raise _FallbackToLegacy()

            records.append(record)

            # drain the record body so its bytes are captured too
            while True:
                buff = record.raw_stream.read(BUFF_SIZE)
                if not buff:
                    break
            iterator.read_to_end()

        if not records or len(header_starts) != len(records):
            # empty, unrecognized, or header boundaries could not be anchored;
            # let the legacy parse/serialize path handle or raise
            raise _FallbackToLegacy()

        total = tee.num_read

        # parsing is complete; the spool now holds the whole logical stream and
        # is safe to read from without disturbing any in-flight write position
        spool.seek(0)
        data = spool.read()

        # Each record block runs from its own WARC status line up to the next
        # record's status line (or end of stream). Blank-line separators belong
        # to the preceding block, so these ranges partition the stream exactly
        # without any offset arithmetic that depends on how separators are
        # consumed.
        boundaries = header_starts + [total]
        count = 0
        for index in range(len(records)):
            self._emit_raw_block(out, data,
                                 boundaries[index], boundaries[index + 1])
            count += 1

        return count

    def _emit_raw_block(self, out, data, start, end):
        block = data[start:end]

        # a legal record starts with a WARC status line and ends with the two
        # blank lines that terminate its block; guard against capturing
        # something unexpected
        if not block.startswith(b'WARC/') or not block.endswith(b'\r\n\r\n'):
            raise _FallbackToLegacy()

        self._write_raw_block(out, block)

    def _write_raw_block(self, out, block):
        if self.gzip:
            wrapper = GzippingWrapper(out)
            wrapper.write(block)
            wrapper.flush()
        else:
            out.write(block)

    def _legacy_load_and_write(self, stream, out):
        writer = WARCWriter(filebuf=out, gzip=self.gzip)

        count = 0
        for record in ArchiveIterator(stream,
                                      no_record_parse=False,
                                      arc2warc=True,
                                      verify_http=False):

            writer.write_record(record)
            count += 1

        return count

    def decompress_and_recompress(self, stream, output):
        with tempfile.TemporaryFile() as tout:
            decomp = DecompressingBufferedReader(stream, read_all_members=True)

            # decompress entire file to temp file
            stream.seek(0)
            shutil.copyfileobj(decomp, tout)

            # attempt to compress and write temp
            tout.seek(0)
            return self._load_decompressed(tout, output)

    def _load_decompressed(self, stream, output):
        with fsspec_open(output, 'wb') as out:
            with tempfile.TemporaryFile() as staged:
                try:
                    count = self._copy_warc_bytes(stream, staged)
                except _FallbackToLegacy:
                    stream.seek(0)
                    writer = WARCWriter(filebuf=out, gzip=self.gzip)
                    count = 0
                    for record in ArchiveIterator(stream,
                                                  no_record_parse=False,
                                                  arc2warc=True,
                                                  verify_http=False):
                        writer.write_record(record)
                        count += 1
                    return count

                staged.seek(0)
                shutil.copyfileobj(staged, out)
                return count


# ============================================================================
class _FallbackToLegacy(Exception):
    """Internal signal: the byte-exact copy path can't handle this stream,
    retry with the parse/serialize writer."""
    pass
