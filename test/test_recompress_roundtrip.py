"""
Tests for byte-exact WARC recompression and block-digest recomputation.

A legal WARC must round-trip through ``warcio recompress`` with no changes at
all once decompressed: no headers added or rewritten, no digests recomputed,
revisit payloads preserved, one gzip member per record. Only when a caller
mutates the HTTP headers of a parsed record should the block digest be
recomputed, and then from the bytes actually written.
"""

import base64
import hashlib
import zlib

from io import BytesIO

import pytest

from warcio.archiveiterator import ArchiveIterator
from warcio.bufferedreaders import DecompressingBufferedReader
from warcio.recompressor import Recompressor
from warcio.warcwriter import BufferWARCWriter
from warcio.checker import Checker

from . import get_test_file


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _sha1_b32(data):
    return 'sha1:' + base64.b32encode(hashlib.sha1(data).digest()).decode('ascii')


def _warc_record(warc_headers, block):
    """Build a single uncompressed WARC record from header pairs and a block."""
    lines = ['WARC/1.0']
    for name, value in warc_headers:
        lines.append('{}: {}'.format(name, value))
    lines.append('Content-Length: {}'.format(len(block)))
    return ('\r\n'.join(lines) + '\r\n\r\n').encode('utf-8') + block + b'\r\n\r\n'


def _gunzip_members(data):
    """Split a multi-member gzip stream into its per-member decompressed bytes."""
    members = []
    pos = 0
    while pos < len(data):
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        members.append(decomp.decompress(data[pos:]))
        pos += len(data[pos:]) - len(decomp.unused_data)
    return members


def _read_plain(path):
    with open(path, 'rb') as fh:
        magic = fh.read(2)
        fh.seek(0)
        if magic == b'\x1f\x8b':
            reader = DecompressingBufferedReader(fh, read_all_members=True)
            chunks = []
            while True:
                chunk = reader.read(1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
            return b''.join(chunks)
        return fh.read()


def _recompress(src, dst, gzip=True):
    Recompressor(src, dst, gzip=gzip).recompress()


def _check_exit(path):
    class _Cmd(object):
        inputs = [path]
        verbose = False
    return Checker(_Cmd()).process_all()


# ----------------------------------------------------------------------------
# byte-exact round trips over the shipped, known-good archives
# ----------------------------------------------------------------------------
@pytest.mark.parametrize('filename', ['example.warc', 'example.warc.gz'])
def test_recompress_roundtrip_byte_exact(filename, tmp_path):
    src = get_test_file(filename)
    dst = str(tmp_path / 'out.warc.gz')

    _recompress(src, dst)

    assert _read_plain(dst) == _read_plain(src)


def test_recompress_plain_output_byte_exact(tmp_path):
    src = get_test_file('example.warc')
    dst = str(tmp_path / 'out.warc')

    Recompressor(src, dst, gzip=False).recompress()

    with open(src, 'rb') as fh:
        original = fh.read()
    with open(dst, 'rb') as fh:
        rewritten = fh.read()
    assert rewritten == original


def test_recompress_one_gzip_member_per_record(tmp_path):
    src = get_test_file('example.warc.gz')
    dst = str(tmp_path / 'out.warc.gz')

    _recompress(src, dst)

    with open(src, 'rb') as fh:
        record_count = sum(1 for _ in ArchiveIterator(fh))
    with open(dst, 'rb') as fh:
        compressed = fh.read()

    members = _gunzip_members(compressed)
    assert len(members) == record_count
    # each decompressed member is one full, self-contained record
    assert all(member.startswith(b'WARC/') and member.endswith(b'\r\n\r\n')
               for member in members)


def test_recompress_preserves_headers_and_digests(tmp_path):
    src = get_test_file('example.warc')
    dst = str(tmp_path / 'out.warc.gz')

    _recompress(src, dst)

    def snapshot(path):
        rows = []
        with open(path, 'rb') as fh:
            for rec in ArchiveIterator(fh):
                rows.append((
                    rec.rec_type,
                    rec.rec_headers.get_header('WARC-Block-Digest'),
                    rec.rec_headers.get_header('WARC-Payload-Digest'),
                    rec.rec_headers.get_header('Content-Length'),
                ))
        return rows

    assert snapshot(dst) == snapshot(src)
    # no new block digest was invented for the warcinfo records that lacked one
    dst_rows = snapshot(dst)
    assert all(row[1] is None for row in dst_rows if row[0] == 'warcinfo')


def test_recompress_output_passes_check(tmp_path):
    src = get_test_file('example.warc')
    dst = str(tmp_path / 'out.warc.gz')

    _recompress(src, dst)

    assert _check_exit(dst) == 0


# ----------------------------------------------------------------------------
# folded and non-ASCII HTTP headers must survive verbatim
# ----------------------------------------------------------------------------
def test_recompress_preserves_folded_and_utf8_headers(tmp_path):
    http_block = (
        b'HTTP/1.1 200 OK\r\n'
        b'X-Long: first\r\n'
        b' folded-continuation\r\n'
        b'X-Unicode: \xd0\xb8\xd1\x81\xd0\xbf\xd1\x8b\xd1\x82\r\n'
        b'Content-Length: 4\r\n'
        b'\r\n'
        b'data'
    )
    record = _warc_record([
        ('WARC-Type', 'response'),
        ('WARC-Record-ID', '<urn:uuid:00000000-0000-0000-0000-000000000001>'),
        ('WARC-Target-URI', 'http://example.com/'),
        ('WARC-Date', '2020-01-01T00:00:00Z'),
        ('Content-Type', 'application/http; msgtype=response'),
        ('WARC-Block-Digest', _sha1_b32(http_block)),
    ], http_block)

    src = tmp_path / 'folded.warc'
    src.write_bytes(record)
    dst = str(tmp_path / 'folded.warc.gz')

    _recompress(str(src), dst)

    assert _read_plain(dst) == record
    assert _check_exit(dst) == 0


# ----------------------------------------------------------------------------
# a revisit record's payload must not be dropped
# ----------------------------------------------------------------------------
def test_recompress_preserves_revisit_payload(tmp_path):
    revisit_block = (
        b'HTTP/1.1 200 OK\r\n'
        b'Content-Type: text/html\r\n'
        b'\r\n'
        b'revisit-payload-bytes'
    )
    record = _warc_record([
        ('WARC-Type', 'revisit'),
        ('WARC-Record-ID', '<urn:uuid:00000000-0000-0000-0000-000000000002>'),
        ('WARC-Target-URI', 'http://example.com/'),
        ('WARC-Date', '2020-01-01T00:00:00Z'),
        ('WARC-Profile',
         'http://netpreserve.org/warc/1.0/revisit/identical-payload-digest'),
        ('WARC-Payload-Digest', 'sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
        ('Content-Type', 'application/http; msgtype=response'),
        ('WARC-Block-Digest', _sha1_b32(revisit_block)),
    ], revisit_block)

    src = tmp_path / 'revisit.warc'
    src.write_bytes(record)
    dst = str(tmp_path / 'revisit.warc.gz')

    _recompress(str(src), dst)

    assert _read_plain(dst) == record

    with open(dst, 'rb') as fh:
        rewritten = next(iter(ArchiveIterator(fh)))
    assert rewritten.raw_stream.read() == b'revisit-payload-bytes'
    assert _check_exit(dst) == 0


# ----------------------------------------------------------------------------
# damaged compression layers are still repaired into per-record members
# ----------------------------------------------------------------------------
def test_recompress_repairs_non_chunked_gzip(tmp_path):
    src = get_test_file('example-bad-non-chunked.warc.gz')
    dst = str(tmp_path / 'repaired.warc.gz')

    _recompress(src, dst)

    with open(dst, 'rb') as fh:
        compressed = fh.read()
    members = _gunzip_members(compressed)

    with open(dst, 'rb') as fh:
        record_count = sum(1 for _ in ArchiveIterator(fh))

    assert len(members) == record_count
    assert _check_exit(dst) == 0


# ----------------------------------------------------------------------------
# ARC input is still converted to WARC (not a byte-exact copy)
# ----------------------------------------------------------------------------
def test_recompress_arc_still_converted(tmp_path):
    src = get_test_file('example.arc.gz')
    dst = str(tmp_path / 'arc2warc.warc.gz')

    _recompress(src, dst)

    with open(dst, 'rb') as fh:
        records = list(ArchiveIterator(fh))

    assert records
    assert all(rec.format == 'warc' for rec in records)
    assert _check_exit(dst) == 0


# ----------------------------------------------------------------------------
# mutating HTTP headers forces a block-digest recompute on write
# ----------------------------------------------------------------------------
def test_writer_recomputes_block_digest_when_http_headers_mutated():
    src = get_test_file('example.warc')
    with open(src, 'rb') as fh:
        record = next(rec for rec in ArchiveIterator(fh)
                      if rec.rec_type == 'response')

    old_digest = record.rec_headers.get_header('WARC-Block-Digest')
    old_payload_digest = record.rec_headers.get_header('WARC-Payload-Digest')
    assert record.http_headers.modified is False
    assert record.http_headers.remove_header('Vary') is True
    assert record.http_headers.modified is True

    writer = BufferWARCWriter(gzip=False)
    writer.write_record(record)

    rewritten = next(iter(ArchiveIterator(BytesIO(writer.get_contents()))))
    new_digest = rewritten.rec_headers.get_header('WARC-Block-Digest')
    assert new_digest != old_digest

    # a header-only change must not invalidate the payload digest
    assert (rewritten.rec_headers.get_header('WARC-Payload-Digest')
            == old_payload_digest)

    # the new digest must match the block bytes that were actually written
    written = writer.get_contents()
    block = written.split(b'\r\n\r\n', 1)[1][:-4]
    assert new_digest == _sha1_b32(block)


def test_writer_keeps_block_digest_when_http_headers_untouched():
    src = get_test_file('example.warc')
    with open(src, 'rb') as fh:
        record = next(rec for rec in ArchiveIterator(fh)
                      if rec.rec_type == 'response')

    old_digest = record.rec_headers.get_header('WARC-Block-Digest')

    writer = BufferWARCWriter(gzip=False)
    writer.write_record(record)

    rewritten = next(iter(ArchiveIterator(BytesIO(writer.get_contents()))))
    assert rewritten.rec_headers.get_header('WARC-Block-Digest') == old_digest


def test_status_and_headers_modified_flag():
    from warcio.statusandheaders import StatusAndHeaders

    headers = StatusAndHeaders('200 OK', [('Set-Cookie', 'a=b')],
                               protocol='HTTP/1.0')
    assert headers.modified is False

    headers.add_header('X-New', '1')
    assert headers.modified is True

    headers.modified = False
    headers.replace_header('X-New', '2')
    assert headers.modified is True

    headers.modified = False
    assert headers.remove_header('X-New') is True
    assert headers.modified is True

    headers.modified = False
    assert headers.remove_header('X-Absent') is False
    assert headers.modified is False
