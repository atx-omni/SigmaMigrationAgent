"""Private, inert PNG/JSON evidence. Never weakens the shared text scanner."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import zlib

from omni_migrator.security.scanner import assert_safe_bytes
from omni_migrator.security.transport import RESPONSE_BYTES, check_json_structure
from omni_migrator.security.workspace import assert_private_output


def atomic_private_write(path: Path, data: bytes, *, text: bool = True):
    """Exclusive final name, private temporary file, fsync and atomic hard-link commit."""
    path = Path(path)
    assert_private_output(path)
    if not isinstance(data, bytes) or len(data) > 25 * 1024 * 1024:
        raise ValueError("Evidence exceeds the local storage bound")
    if path.exists() or path.is_symlink():
        raise ValueError("Evidence destination already exists")
    if text:
        assert_safe_bytes(data, filename=path.name)
    fd, temporary = tempfile.mkstemp(prefix=".capture-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.unlink(temporary)


def png_dimensions(data: bytes):
    """Validate a bounded non-interlaced 8-bit PNG, including CRC and zlib stream."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Downloaded image is not a PNG")
    pos, width, height, channels = 8, None, None, None
    compressed = bytearray()
    ended = False
    while pos < len(data):
        if pos + 12 > len(data):
            raise ValueError("Truncated PNG chunk")
        size = struct.unpack(">I", data[pos:pos + 4])[0]
        kind = data[pos + 4:pos + 8]
        if pos + size + 12 > len(data):
            raise ValueError("Truncated PNG payload")
        chunk = data[pos + 8:pos + 8 + size]
        crc = struct.unpack(">I", data[pos + 8 + size:pos + 12 + size])[0]
        if zlib.crc32(kind + chunk) & 0xffffffff != crc:
            raise ValueError("PNG checksum mismatch")
        if width is None and kind != b"IHDR":
            raise ValueError("PNG must start with its header")
        if kind == b"IHDR":
            if width is not None or size != 13:
                raise ValueError("Invalid PNG header")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunk)
            channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
            if (not channels or depth != 8 or compression or filtering or interlace
                    or not 0 < width <= 8192 or not 0 < height <= 8192
                    or width * height > 16_000_000):
                raise ValueError("PNG encoding or dimensions exceed the supported capture slice")
        elif kind == b"IDAT":
            compressed.extend(chunk)
        elif kind == b"IEND":
            if size or not compressed or pos + 12 != len(data):
                raise ValueError("Invalid PNG ending")
            ended = True
            break
        elif kind not in {b"sRGB", b"gAMA", b"cHRM", b"pHYs", b"bKGD", b"sBIT"}:
            raise ValueError("PNG contains unsupported ancillary or critical chunks")
        pos += size + 12
    if not ended:
        raise ValueError("PNG is incomplete")
    expected = (width * channels + 1) * height
    if expected > 64 * 1024 * 1024:
        raise ValueError("Decoded PNG exceeds the pixel budget")
    decoder = zlib.decompressobj()
    try:
        pixels = decoder.decompress(bytes(compressed), expected + 1)
    except zlib.error:
        raise ValueError("PNG compression is invalid") from None
    if len(pixels) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("PNG decoded size is inconsistent")
    stride = width * channels + 1
    if any(pixels[row * stride] > 4 for row in range(height)):
        raise ValueError("PNG row filter is invalid")
    return {"width": width, "height": height}


def inspect_evidence(data: bytes, kind: str, content_type: str, row_limit: int):
    if not data or len(data) > RESPONSE_BYTES:
        raise ValueError("Empty or oversized export evidence")
    mime = content_type.split(";", 1)[0].strip().lower()
    if kind == "png":
        if mime != "image/png":
            raise ValueError("PNG export returned a different media type")
        return {"actual_dimensions": png_dimensions(data), "requested_dimensions": None}
    if kind != "json" or mime != "application/json":
        raise ValueError("JSON export returned a different media type")
    check_json_structure(data)
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate result property")
            value[key] = item
        return value
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite result")))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("Exported result is not valid UTF-8 JSON") from None
    if not isinstance(value, (dict, list)):
        raise ValueError("Exported result must be a JSON object or array")
    rows = value if isinstance(value, list) else value.get("rows")
    count = len(rows) if isinstance(rows, list) else None
    if count is not None and count > row_limit:
        raise ValueError("Exported results exceed the requested row limit")
    return {"observed_rows": count, "requested_row_limit": row_limit,
            "row_completeness": "not_established", "result_shape": "array" if isinstance(value, list) else "object"}


def persist_evidence(path: Path, data: bytes, kind: str, content_type: str, row_limit: int):
    metadata = inspect_evidence(data, kind, content_type, row_limit)
    atomic_private_write(path, data, text=kind == "json")
    return {"path": path.name, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "format": kind, "media_type": content_type.split(";", 1)[0],
            "privacy_review": "pending", **metadata}
