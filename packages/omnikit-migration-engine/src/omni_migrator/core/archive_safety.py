"""Bounded inspection and streaming reads for untrusted ZIP-based BI artifacts."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class ArchiveSafetyLimits:
    max_members: int = 10_000
    max_filename_bytes: int = 1_024
    max_member_uncompressed_bytes: int = 512 * 1024 * 1024
    max_total_uncompressed_bytes: int = 1024 * 1024 * 1024
    max_expansion_ratio: float = 200.0

    def __post_init__(self) -> None:
        integer_limits = (
            self.max_members,
            self.max_filename_bytes,
            self.max_member_uncompressed_bytes,
            self.max_total_uncompressed_bytes,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in integer_limits):
            raise ValueError("archive byte and member limits must be positive integers")
        if (
            not isinstance(self.max_expansion_ratio, (int, float))
            or isinstance(self.max_expansion_ratio, bool)
            or self.max_expansion_ratio < 1
        ):
            raise ValueError("archive expansion ratio must be at least 1")


DEFAULT_ARCHIVE_LIMITS = ArchiveSafetyLimits()
NESTED_MIGRATION_ARCHIVE_SUFFIXES = frozenset({".zip", ".pbix", ".twbx", ".tdsx"})
SUPPORTED_COMPRESSION_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_READ_CHUNK_BYTES = 1024 * 1024


def validate_zip_archive(
    archive: zipfile.ZipFile,
    archive_name: str,
    limits: ArchiveSafetyLimits = DEFAULT_ARCHIVE_LIMITS,
) -> tuple[zipfile.ZipInfo, ...]:
    """Validate central-directory metadata without expanding archive members."""
    entries = tuple(archive.infolist())
    if len(entries) > limits.max_members:
        raise ValueError(
            f"archive contains more than {limits.max_members} entries: {archive_name}"
        )

    total_uncompressed = 0
    total_compressed = 0
    normalized_members: set[str] = set()
    for entry in entries:
        filename = entry.filename
        if len(filename.encode("utf-8", errors="surrogatepass")) > limits.max_filename_bytes:
            raise ValueError(f"archive member filename exceeds the safe byte limit: {archive_name}")

        member = PurePosixPath(filename.replace("\\", "/"))
        normalized = member.as_posix()
        normalized_key = normalized.casefold()
        if (
            not filename
            or normalized in {"", "."}
            or "\x00" in filename
            or member.is_absolute()
            or ".." in member.parts
        ):
            raise ValueError(f"archive contains an unsafe path: {archive_name}")
        if normalized_key in normalized_members:
            raise ValueError(f"archive contains a duplicate path: {archive_name}")
        normalized_members.add(normalized_key)

        if entry.flag_bits & 0x1:
            raise ValueError(f"encrypted archive entries are not accepted: {archive_name}")
        mode = entry.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError(f"archive contains a symbolic link: {archive_name}")
        file_type = stat.S_IFMT(mode)
        if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"archive contains a non-regular member: {archive_name}")
        if entry.compress_type not in SUPPORTED_COMPRESSION_METHODS:
            raise ValueError(f"archive uses an unsupported compression method: {archive_name}")
        if entry.file_size < 0 or entry.compress_size < 0 or entry.header_offset < 0:
            raise ValueError(f"archive contains invalid member metadata: {archive_name}")
        if entry.is_dir() and (entry.file_size != 0 or entry.compress_size != 0):
            raise ValueError(f"archive directory metadata is inconsistent: {archive_name}")
        if not entry.is_dir() and member.suffix.lower() in NESTED_MIGRATION_ARCHIVE_SUFFIXES:
            raise ValueError(f"nested migration archives are not accepted: {archive_name}")
        if entry.file_size > limits.max_member_uncompressed_bytes:
            raise ValueError(f"archive member expands beyond the safe byte limit: {archive_name}")

        if entry.file_size > 0:
            if entry.compress_size <= 0:
                raise ValueError(f"archive member expansion ratio exceeds the safe limit: {archive_name}")
            if entry.file_size / entry.compress_size > limits.max_expansion_ratio:
                raise ValueError(f"archive member expansion ratio exceeds the safe limit: {archive_name}")

        total_uncompressed += entry.file_size
        total_compressed += entry.compress_size
        if total_uncompressed > limits.max_total_uncompressed_bytes:
            raise ValueError(f"archive expands beyond the safe total byte limit: {archive_name}")

    if (
        total_uncompressed > 0
        and (total_compressed <= 0 or total_uncompressed / total_compressed > limits.max_expansion_ratio)
    ):
        raise ValueError(f"archive expansion ratio exceeds the safe limit: {archive_name}")
    return entries


def _open_bounded_file(path: Path, *, max_bytes: int, label: str):
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("file byte limit must be a positive integer")
    source = path.open("rb")
    try:
        expected_size = os.fstat(source.fileno()).st_size
        if expected_size > max_bytes:
            raise ValueError(f"{label} exceeds the safe byte limit: {path.name}")
        return source, expected_size
    except Exception:
        source.close()
        raise


def read_file_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read one regular file without allocating beyond its parser-specific ceiling."""
    source, expected_size = _open_bounded_file(path, max_bytes=max_bytes, label=label)
    output = bytearray()
    with source:
        while True:
            chunk = source.read(min(_READ_CHUNK_BYTES, max_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_bytes:
                raise ValueError(f"{label} exceeds the safe byte limit: {path.name}")
        if len(output) != expected_size or os.fstat(source.fileno()).st_size != expected_size:
            raise ValueError(f"{label} changed while it was being read: {path.name}")
    return bytes(output)


def sha256_file_bounded(path: Path, *, max_bytes: int, label: str = "artifact") -> str:
    """Hash an artifact incrementally while enforcing a stable, bounded file size."""
    source, expected_size = _open_bounded_file(path, max_bytes=max_bytes, label=label)
    digest = hashlib.sha256()
    total = 0
    with source:
        while True:
            chunk = source.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds the safe byte limit: {path.name}")
            digest.update(chunk)
        if total != expected_size or os.fstat(source.fileno()).st_size != expected_size:
            raise ValueError(f"{label} changed while it was being hashed: {path.name}")
    return digest.hexdigest()


def read_zip_member_bounded(
    archive: zipfile.ZipFile,
    entry: zipfile.ZipInfo,
    *,
    archive_name: str,
    max_bytes: int,
) -> bytes:
    """Stream one validated member and enforce the actual expanded-byte ceiling."""
    if entry.file_size > max_bytes:
        raise ValueError(f"archive member expands beyond the parser byte limit: {archive_name}")
    output = bytearray()
    with archive.open(entry, "r") as source:
        while True:
            chunk = source.read(min(_READ_CHUNK_BYTES, max_bytes + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > max_bytes:
                raise ValueError(f"archive member expands beyond the parser byte limit: {archive_name}")
    if len(output) != entry.file_size:
        raise ValueError(f"archive member size did not match its declared metadata: {archive_name}")
    return bytes(output)
