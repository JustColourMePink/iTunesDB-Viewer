import sys
import struct
import json
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any

# Tkinter standard library GUI (no external deps)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.font as tkfont


# Known 4CC tags we care about (extendable)
KNOWN_TAGS = {
    b"mhbd",  # Database header (root)
    b"mhsd",  # Dataset
    b"mhla",  # Album List
    b"mhia",  # Album Item
    b"mhod",  # Data Object
    b"mhlt",  # Track list
    b"mhit",  # Track item
    b"mhlp",  # Playlist list
    b"mhyp",  # Playlist
    b"mhip",  # Playlist item
}


@dataclass
class Chunk:
    """Represents a detected chunk in the iTunesDB file.

    This struct is intentionally generic. We only implement concrete parsing
    for `mhbd` initially, but the structure can be extended easily for other tags.
    """

    tag: bytes                 # 4CC (e.g., b"mhbd")
    offset: int               # File offset where tag starts
    size: Optional[int]       # Parsed size (header size for mhbd)
    endian: Optional[str]     # 'le' or 'be' if size determined
    raw_header: bytes         # Raw bytes starting at tag (first N bytes)
    children: List["Chunk"]   # Nested chunks if known
    fields: Optional[Dict[str, object]] = None  # Parsed fields for known tags

    def display_name(self) -> str:
        tag_text = self.tag.decode('ascii', errors='replace')
        off = f"0x{self.offset:08X}"
        if self.size is not None and self.endian is not None:
            return f"{tag_text} @ {off} (size={self.size}, {self.endian})"
        else:
            return f"{tag_text} @ {off} (size=? )"


def hex_preview(data: bytes, width: int = 16, max_bytes: int = 128) -> str:
    """Return a compact hex+ASCII preview.

    If max_bytes is None or < 0, render full data; otherwise truncate.
    """
    if max_bytes is not None and max_bytes >= 0:
        data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f"{b:02X}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:04X}  {hex_part:<{width*3}}  {ascii_part}")
    return '\n'.join(lines)


def ascii_repr(data: bytes) -> str:
    """ASCII view where non-printables become '.'"""
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def bytes_spaced_hex(data: bytes) -> str:
    """Format bytes as space-separated lowercase hex pairs (e.g., '6d 68 62 64')."""
    return ' '.join(f"{b:02x}" for b in data)


def hfs_to_iso(ts: Optional[int]) -> Optional[str]:
    """Convert HFS epoch seconds (since 1904-01-01 UTC) to ISO string.

    Returns None for None or zero values.
    """
    if ts is None or ts == 0:
        return None
    try:
        base = datetime(1904, 1, 1, tzinfo=timezone.utc)
        dt = base + timedelta(seconds=int(ts))
        return dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception:
        return None


def q16_to_int(val: Optional[int]) -> Optional[int]:
    """Convert 16.16 fixed-point integer to integer Hz (rounded)."""
    if val is None:
        return None
    return int(round(val / 65536))


def float_from_le_bytes(b: bytes) -> Optional[float]:
    if not b or len(b) < 4:
        return None
    try:
        return struct.unpack('<f', b[:4])[0]
    except Exception:
        return None


def decode_filetype_ascii(b: bytes) -> Optional[str]:
    """Map 4-byte filetype to a known code (MP3, AAC, M4A, M4P).

    Returns a string label like 'M4A' or None if unknown. Detects reversed
    order by also testing the reversed ASCII.
    """
    if not b or len(b) < 4:
        return None
    known = {"MP3 ": "MP3", "AAC ": "AAC", "M4A ": "M4A", "M4P ": "M4P"}
    s = ''.join(chr(x) for x in b[:4])
    sr = ''.join(chr(x) for x in b[:4][::-1])
    if s in known:
        return known[s]
    if sr in known:
        return known[sr] + " (reversed)"
    return None


class ITunesDBParser:
    """Incremental binary parser for iTunesDB-like structures.

    Phase 1 (this commit):
    - Detect and parse `mhbd` chunks.
    - Show offsets, candidate sizes (LE/BE), and a short hex preview.

    Notes on format uncertainty:
    The iTunesDB format uses 4CC tags (e.g., 'mhbd'). Many binary formats store
    a 4-byte size after the tag. Endianness can vary by format. Since we are
    working incrementally and may not know the exact endianness for your file,
    we attempt both little-endian and big-endian interpretations and validate
    based on simple plausibility checks (bounds within file, minimum size).

    As we add support for more tags (mhsd, mhlt, mhit, ...), we will refine the
    heuristics and move to a definitive read of size and schema per tag.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.length = len(data)

    def _read_u32_be(self, offset: int) -> Optional[int]:
        if offset + 4 <= self.length:
            return struct.unpack_from('>I', self.data, offset)[0]
        return None

    def _read_u64_be(self, offset: int) -> Optional[int]:
        if offset + 8 <= self.length:
            return struct.unpack_from('>Q', self.data, offset)[0]
        return None

    def _read_i64_be(self, offset: int) -> Optional[int]:
        if offset + 8 <= self.length:
            return struct.unpack_from('>q', self.data, offset)[0]
        return None

    def _read_u32_le(self, offset: int) -> Optional[int]:
        if offset + 4 <= self.length:
            return struct.unpack_from('<I', self.data, offset)[0]
        return None

    def _read_u16_le(self, offset: int) -> Optional[int]:
        if offset + 2 <= self.length:
            return struct.unpack_from('<H', self.data, offset)[0]
        return None

    def _read_u64_le(self, offset: int) -> Optional[int]:
        if offset + 8 <= self.length:
            return struct.unpack_from('<Q', self.data, offset)[0]
        return None

    def _find_all(self, needle: bytes) -> List[int]:
        """Find all occurrences of a 4-byte tag in the file and return offsets."""
        offsets = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    def parse_mhbd(self) -> List[Chunk]:
        """Detect and parse all mhbd chunks (little-endian) and decode fields.

        Layout (relative to the tag start):
        - 0..3:    tag 'mhbd'
        - 4..7:    header_size (u32, LE)
        - 8..11:   total_file_size (u32, LE)
        - 12..15:  always_1 (u32, LE)
        - 16..19:  database_version (u32, LE)
        - 20..23:  num_mhsd_sets (u32, LE)
        - 24..31:  database_uuid (8 bytes)
        - 32..33:  constant_2 (u16, LE)
        - 34..43:  stable_identifier (10 bytes)
        - 44..45:  iso_639_1 (2 bytes, ASCII)
        - 46..53:  persistent_library_id (8 bytes)
        - ...:     zero padding up to header_size
        """
        results: List[Chunk] = []
        for off in self._find_all(b'mhbd'):
            header_size = self._read_u32_le(off + 4)
            # Validate header size plausibility: must at least cover defined fields
            min_header = 168  # last defined field ends at offset 166 + 2
            if header_size is None or header_size < min_header or (off + header_size) > self.length:
                # Fall back to a conservative preview if invalid
                header_preview = self.data[off:off + 64]
                chunk = Chunk(tag=b'mhbd', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None)
                results.append(chunk)
                continue

            # Capture raw little-endian bytes for all fields
            tag_bytes = self.data[off: off + 4]
            header_size_bytes = self.data[off + 4: off + 8]
            total_file_size_bytes = self.data[off + 8: off + 12]
            unk1_bytes = self.data[off + 12: off + 16]
            database_version_bytes = self.data[off + 16: off + 20]
            num_mhsd_sets_bytes = self.data[off + 20: off + 24]
            database_uuid = self.data[off + 24: off + 32]
            unk2_bytes = self.data[off + 32: off + 34]
            stable_identifier = self.data[off + 34: off + 44]
            language_bytes = self.data[off + 70: off + 72]
            persistent_library_id = self.data[off + 72: off + 80]
            unk3_bytes = self.data[off + 80: off + 84]
            unk4_bytes = self.data[off + 84: off + 88]
            unk5_bytes = self.data[off + 108: off + 110]
            unk6_bytes = self.data[off + 110: off + 112]
            unk7_bytes = self.data[off + 160: off + 164]
            unk8_bytes = self.data[off + 164: off + 166]
            unk9_bytes = self.data[off + 166: off + 168]

            # Parse numeric values (little-endian) for convenience/validation
            total_file_size = self._read_u32_le(off + 8)
            unk1 = self._read_u32_le(off + 12)
            database_version = self._read_u32_le(off + 16)
            num_mhsd_sets = self._read_u32_le(off + 20)
            unk2 = self._read_u16_le(off + 32)
            unk3 = self._read_u32_le(off + 80)
            unk4 = self._read_u32_le(off + 84)
            unk5 = self._read_u16_le(off + 108)
            unk6 = self._read_u16_le(off + 110)
            unk7 = self._read_u32_le(off + 160)
            unk8 = self._read_u16_le(off + 164)
            unk9 = self._read_u16_le(off + 166)

            # Try ASCII decode for language (2 bytes)
            try:
                language_ascii = language_bytes.decode('ascii') if len(language_bytes) == 2 else None
            except Exception:
                language_ascii = None

            fields = {
                'tag_bytes': tag_bytes,
                'header_size': header_size,
                'header_size_bytes': header_size_bytes,
                'total_file_size': total_file_size,
                'total_file_size_bytes': total_file_size_bytes,
                'unk1': unk1,
                'unk1_bytes': unk1_bytes,
                'database_version': database_version,
                'database_version_bytes': database_version_bytes,
                'num_mhsd_sets': num_mhsd_sets,
                'num_mhsd_sets_bytes': num_mhsd_sets_bytes,
                'database_uuid_bytes': database_uuid,
                'unk2': unk2,
                'unk2_bytes': unk2_bytes,
                'stable_identifier_bytes': stable_identifier,
                'language_bytes': language_bytes,
                'language_ascii': language_ascii,
                'persistent_library_id_bytes': persistent_library_id,
                'unk3': unk3,
                'unk3_bytes': unk3_bytes,
                'unk4': unk4,
                'unk4_bytes': unk4_bytes,
                'unk5': unk5,
                'unk5_bytes': unk5_bytes,
                'unk6': unk6,
                'unk6_bytes': unk6_bytes,
                'unk7': unk7,
                'unk7_bytes': unk7_bytes,
                'unk8': unk8,
                'unk8_bytes': unk8_bytes,
                'unk9': unk9,
                'unk9_bytes': unk9_bytes,
            }

            # Entire header preview
            header_preview = self.data[off: off + header_size]

            chunk = Chunk(
                tag=b'mhbd',
                offset=off,
                size=header_size,
                endian='le',
                raw_header=header_preview,
                children=[],
                fields=fields,
            )
            results.append(chunk)
        return results

    def _range_contains_known_tag(self, start: int, end: int) -> bool:
        """Return True if any known tag occurs fully within [start, end)."""
        if start >= end:
            return False
        # Scan for any 4CC in the region. We check bytes that match ASCII letters
        # to avoid O(len*|KNOWN_TAGS|) nested loops; but correctness comes from
        # directly testing KNOWN_TAGS membership.
        pos = start
        data = self.data
        limit = max(start, min(end, self.length))
        while pos + 4 <= limit:
            fourcc = data[pos:pos+4]
            if fourcc in KNOWN_TAGS:
                return True
            pos += 1
        return False

    def _find_all_in_range(self, needle: bytes, start: int, end: int) -> List[int]:
        offs = []
        pos = max(0, start)
        end = min(self.length, end)
        while True:
            idx = self.data.find(needle, pos, end)
            if idx == -1:
                break
            offs.append(idx)
            pos = idx + 1
        return offs

    def parse_mhsd(self) -> List[Chunk]:
        """Detect and parse all mhsd sections (little-endian).

        Layout:
        - 0..3:   tag 'mhsd'
        - 4..7:   header_length (u32, LE)
        - 8..11:  total_length (u32, LE)
        - 12..15: type (u32, LE)
        - ...:    header bytes up to header_length
        - children region: [offset + header_length, offset + total_length)
        """
        results: List[Chunk] = []
        for off in self._find_all(b'mhsd'):
            header_len = self._read_u32_le(off + 4)
            total_len = self._read_u32_le(off + 8)
            type_val = self._read_u32_le(off + 12)
            # basic plausibility checks
            if (
                header_len is None or total_len is None or type_val is None or
                header_len < 12 or total_len < header_len or
                (off + header_len) > self.length or (off + total_len) > self.length
            ):
                header_preview = self.data[off: off + 64]
                ch = Chunk(tag=b'mhsd', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None)
                results.append(ch)
                continue

            tag_bytes = self.data[off: off + 4]
            header_len_bytes = self.data[off + 4: off + 8]
            total_len_bytes = self.data[off + 8: off + 12]
            type_bytes = self.data[off + 12: off + 16]
            header_preview = self.data[off: off + header_len]

            fields = {
                'tag_bytes': tag_bytes,
                'header_length': header_len,
                'header_length_bytes': header_len_bytes,
                'total_length': total_len,
                'total_length_bytes': total_len_bytes,
                'type': type_val,
                'type_bytes': type_bytes,
            }

            # For mhsd, display total_length in the size column (section size)
            ch = Chunk(tag=b'mhsd', offset=off, size=total_len, endian='le', raw_header=header_preview, children=[], fields=fields)
            results.append(ch)
        return sorted(results, key=lambda c: c.offset)

    # --- Child list sections within mhsd ---
    def _parse_generic_list_section(self, tag: bytes, off: int) -> Optional[Chunk]:
        """Parse a generic section with (tag, header_length, total_length).

        Many list-like sections (mhlt, mhlp, mhla) appear to follow this layout.
        If plausibility checks fail, returns a minimal chunk with only a preview.
        """
        if off < 0 or off + 8 > self.length:
            return None
        if self.data[off:off+4] != tag:
            return None
        header_len = self._read_u32_le(off + 4)
        total_len = self._read_u32_le(off + 8)
        if header_len is None or total_len is None:
            header_preview = self.data[off: off + 64]
            return Chunk(tag=tag, offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None)

        # Plausibility: header_len at least 12 (tag+hdr_len+tot_len), total_len >= header_len, and within file
        if header_len < 12 or total_len < header_len or (off + header_len) > self.length or (off + total_len) > self.length:
            header_preview = self.data[off: off + min(64, max(0, self.length - off))]
            return Chunk(tag=tag, offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None)

        fields = {
            'tag_bytes': self.data[off: off + 4],
            'header_length': header_len,
            'header_length_bytes': self.data[off + 4: off + 8],
            'total_length': total_len,
            'total_length_bytes': self.data[off + 8: off + 12],
        }
        header_preview = self.data[off: off + header_len]
        return Chunk(tag=tag, offset=off, size=total_len, endian='le', raw_header=header_preview, children=[], fields=fields)

    def parse_mhlt_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhlt (Track List) sections in range.

        Layout:
        - 0..3:  tag 'mhlt'
        - 4..7:  header_length (u32, LE)
        - 8..11: number_of_songs (u32, LE)
        - ...:   zero padding up to header_length
        Children region begins at offset + header_length and contains mhit items.
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhlt', start, end):
            header_len = self._read_u32_le(off + 4)
            num_songs = self._read_u32_le(off + 8)
            if header_len is None or num_songs is None or header_len < 12 or (off + header_len) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhlt', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            tag_bytes = self.data[off: off + 4]
            header_len_bytes = self.data[off + 4: off + 8]
            num_songs_bytes = self.data[off + 8: off + 12]
            header_preview = self.data[off: off + header_len]

            fields = {
                'tag_bytes': tag_bytes,
                'header_length': header_len,
                'header_length_bytes': header_len_bytes,
                'number_of_songs': num_songs,
                'number_of_songs_bytes': num_songs_bytes,
            }

            results.append(Chunk(tag=b'mhlt', offset=off, size=header_len, endian='le', raw_header=header_preview, children=[], fields=fields))
        return sorted(results, key=lambda c: c.offset)

    def parse_mhit_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhit (Track Item) sections in range.

        Implements the field map you provided up to offset 260, storing both
        raw bytes and LE-decoded numeric values where applicable.
        Children (mhod strings) can be parsed using number_of_strings and the
        range [offset + header_length, offset + total_length).
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhit', start, end):
            hl = self._read_u32_le(off + 4)
            tl = self._read_u32_le(off + 8)
            nstr = self._read_u32_le(off + 12)
            if hl is None or tl is None or nstr is None or hl < 16 or tl < hl or (off + hl) > self.length or (off + tl) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhit', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            # Capture raw bytes and values for key fields
            def bytes_at(o: int, n: int) -> bytes:
                return self.data[off + o: off + o + n]

            fields = {
                'tag_bytes': bytes_at(0, 4),
                'header_length': hl,
                'header_length_bytes': bytes_at(4, 4),
                'total_length': tl,
                'total_length_bytes': bytes_at(8, 4),
                'number_of_strings': nstr,
                'number_of_strings_bytes': bytes_at(12, 4),
                'unique_id': self._read_u32_le(off + 16),
                'unique_id_bytes': bytes_at(16, 4),
                'visible': self._read_u32_le(off + 20),
                'visible_bytes': bytes_at(20, 4),
                'filetype_bytes': bytes_at(24, 4),
                'type1': self.data[off + 28] if off + 29 <= self.length else None,
                'type1_bytes': bytes_at(28, 1),
                'type2': self.data[off + 29] if off + 30 <= self.length else None,
                'type2_bytes': bytes_at(29, 1),
                'compilation_flag': self.data[off + 30] if off + 31 <= self.length else None,
                'compilation_flag_bytes': bytes_at(30, 1),
                'rating': self.data[off + 31] if off + 32 <= self.length else None,
                'rating_bytes': bytes_at(31, 1),
                'last_modified_time': self._read_u32_le(off + 32),
                'last_modified_time_bytes': bytes_at(32, 4),
                'size_bytes': bytes_at(36, 4),
                'size': self._read_u32_le(off + 36),
                'length_ms_bytes': bytes_at(40, 4),
                'length_ms': self._read_u32_le(off + 40),
                'track_number_bytes': bytes_at(44, 4),
                'track_number': self._read_u32_le(off + 44),
                'total_tracks_bytes': bytes_at(48, 4),
                'total_tracks': self._read_u32_le(off + 48),
                'year_bytes': bytes_at(52, 4),
                'year': self._read_u32_le(off + 52),
                'bitrate_bytes': bytes_at(56, 4),
                'bitrate': self._read_u32_le(off + 56),
                'sample_rate_q16_bytes': bytes_at(60, 4),
                'sample_rate_q16': self._read_u32_le(off + 60),
                'volume_bytes': bytes_at(64, 4),
                'volume': self._read_u32_le(off + 64),
                'start_time_bytes': bytes_at(68, 4),
                'start_time': self._read_u32_le(off + 68),
                'stop_time_bytes': bytes_at(72, 4),
                'stop_time': self._read_u32_le(off + 72),
                'soundcheck_bytes': bytes_at(76, 4),
                'soundcheck': self._read_u32_le(off + 76),
                'play_count_bytes': bytes_at(80, 4),
                'play_count': self._read_u32_le(off + 80),
                'play_count2_bytes': bytes_at(84, 4),
                'play_count2': self._read_u32_le(off + 84),
                'last_played_time_bytes': bytes_at(88, 4),
                'last_played_time': self._read_u32_le(off + 88),
                'disc_number_bytes': bytes_at(92, 4),
                'disc_number': self._read_u32_le(off + 92),
                'total_discs_bytes': bytes_at(96, 4),
                'total_discs': self._read_u32_le(off + 96),
                'user_id_bytes': bytes_at(100, 4),
                'user_id': self._read_u32_le(off + 100),
                'date_added_bytes': bytes_at(104, 4),
                'date_added': self._read_u32_le(off + 104),
                'bookmark_time_bytes': bytes_at(108, 4),
                'bookmark_time': self._read_u32_le(off + 108),
                'dbid_bytes': bytes_at(112, 8),
                'checked_bytes': bytes_at(120, 1),
                'checked': self.data[off + 120] if off + 121 <= self.length else None,
                'app_rating_bytes': bytes_at(121, 1),
                'app_rating': self.data[off + 121] if off + 122 <= self.length else None,
                'bpm_bytes': bytes_at(122, 2),
                'bpm': self._read_u16_le(off + 122),
                'artwork_count_bytes': bytes_at(124, 2),
                'artwork_count': self._read_u16_le(off + 124),
                'unk9_bytes': bytes_at(126, 2),
                'unk9': self._read_u16_le(off + 126),
                'artwork_size_bytes': bytes_at(128, 4),
                'artwork_size': self._read_u32_le(off + 128),
                'unk11_bytes': bytes_at(132, 4),
                'unk11': self._read_u32_le(off + 132),
                'sample_rate_f_bytes': bytes_at(136, 4),
                'sample_rate_f_raw': self._read_u32_le(off + 136),
                'date_released_bytes': bytes_at(140, 4),
                'date_released': self._read_u32_le(off + 140),
                'unk14_1_bytes': bytes_at(144, 2),
                'unk14_1': self._read_u16_le(off + 144),
                'unk14_2_bytes': bytes_at(146, 2),
                'unk14_2': self._read_u16_le(off + 146),
                'unk15_bytes': bytes_at(148, 4),
                'unk15': self._read_u32_le(off + 148),
                'unk16_bytes': bytes_at(152, 4),
                'unk16': self._read_u32_le(off + 152),
                'skip_count_bytes': bytes_at(156, 4),
                'skip_count': self._read_u32_le(off + 156),
                'last_skipped_bytes': bytes_at(160, 4),
                'last_skipped': self._read_u32_le(off + 160),
                'has_artwork_bytes': bytes_at(164, 1),
                'has_artwork': self.data[off + 164] if off + 165 <= self.length else None,
                'skip_when_shuffling_bytes': bytes_at(165, 1),
                'skip_when_shuffling': self.data[off + 165] if off + 166 <= self.length else None,
                'remember_playback_position_bytes': bytes_at(166, 1),
                'remember_playback_position': self.data[off + 166] if off + 167 <= self.length else None,
                'flag7_bytes': bytes_at(167, 1),
                'flag7': self.data[off + 167] if off + 168 <= self.length else None,
                'dbid2_bytes': bytes_at(168, 8),
                'lyrics_flag_bytes': bytes_at(176, 1),
                'lyrics_flag': self.data[off + 176] if off + 177 <= self.length else None,
                'movie_file_flag_bytes': bytes_at(177, 1),
                'movie_file_flag': self.data[off + 177] if off + 178 <= self.length else None,
                'played_mark_bytes': bytes_at(178, 1),
                'played_mark': self.data[off + 178] if off + 179 <= self.length else None,
                'unk17_bytes': bytes_at(179, 1),
                'unk17': self.data[off + 179] if off + 180 <= self.length else None,
                'unk21_bytes': bytes_at(180, 4),
                'unk21': self._read_u32_le(off + 180),
                'pregap_bytes': bytes_at(184, 4),
                'pregap': self._read_u32_le(off + 184),
                'sample_count_bytes': bytes_at(188, 8),
                'sample_count': self._read_u64_le(off + 188),
                'unk25_bytes': bytes_at(196, 4),
                'unk25': self._read_u32_le(off + 196),
                'postgap_bytes': bytes_at(200, 4),
                'postgap': self._read_u32_le(off + 200),
                'unk27_bytes': bytes_at(204, 4),
                'unk27': self._read_u32_le(off + 204),
                'media_type_bytes': bytes_at(208, 4),
                'media_type': self._read_u32_le(off + 208),
                'season_number_bytes': bytes_at(212, 4),
                'season_number': self._read_u32_le(off + 212),
                'episode_number_bytes': bytes_at(216, 4),
                'episode_number': self._read_u32_le(off + 216),
                'unk31_bytes': bytes_at(220, 4),
                'unk31': self._read_u32_le(off + 220),
                'unk32_bytes': bytes_at(224, 4),
                'unk32': self._read_u32_le(off + 224),
                'unk33_bytes': bytes_at(228, 4),
                'unk33': self._read_u32_le(off + 228),
                'unk34_bytes': bytes_at(232, 4),
                'unk34': self._read_u32_le(off + 232),
                'unk35_bytes': bytes_at(236, 4),
                'unk35': self._read_u32_le(off + 236),
                'unk36_bytes': bytes_at(240, 4),
                'unk36': self._read_u32_le(off + 240),
                'unk37_bytes': bytes_at(244, 4),
                'unk37': self._read_u32_le(off + 244),
                'gaplessData_bytes': bytes_at(248, 4),
                'gaplessData': self._read_u32_le(off + 248),
                'unk38_bytes': bytes_at(252, 4),
                'unk38': self._read_u32_le(off + 252),
                'gaplessTrackFlag_bytes': bytes_at(256, 2),
                'gaplessTrackFlag': self._read_u16_le(off + 256),
                'gaplessAlbumFlag_bytes': bytes_at(258, 2),
                'gaplessAlbumFlag': self._read_u16_le(off + 258),
                'unk39_bytes': bytes_at(260, 20),
            }

            header_preview = self.data[off: off + hl]
            results.append(Chunk(tag=b'mhit', offset=off, size=tl, endian='le', raw_header=header_preview, children=[], fields=fields))

        return sorted(results, key=lambda c: c.offset)

    def parse_mhlp_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhlp (Playlist List) sections in range.

        Layout:
        - 0..3:  tag 'mhlp'
        - 4..7:  header_length (u32, LE)
        - 8..11: number_of_playlists (u32, LE)
        - ...:   zero padding up to header_length
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhlp', start, end):
            header_len = self._read_u32_le(off + 4)
            num_lists = self._read_u32_le(off + 8)
            if header_len is None or num_lists is None or header_len < 12 or (off + header_len) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhlp', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            tag_bytes = self.data[off: off + 4]
            header_len_bytes = self.data[off + 4: off + 8]
            num_lists_bytes = self.data[off + 8: off + 12]
            header_preview = self.data[off: off + header_len]

            fields = {
                'tag_bytes': tag_bytes,
                'header_length': header_len,
                'header_length_bytes': header_len_bytes,
                'number_of_playlists': num_lists,
                'number_of_playlists_bytes': num_lists_bytes,
            }

            results.append(Chunk(tag=b'mhlp', offset=off, size=header_len, endian='le', raw_header=header_preview, children=[], fields=fields))
        return sorted(results, key=lambda c: c.offset)

    def parse_mhyp_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhyp (Playlist) sections in range.

        Layout (offsets from section start):
        - 0..3:   tag 'mhyp'
        - 4..7:   header_length (u32, LE)
        - 8..11:  total_length (u32, LE)
        - 12..15: data_object_child_count (u32, LE)
        - 16..19: playlist_item_count (u32, LE)
        - 20:     is_master_playlist (u8)
        - 21..23: flags3 (3 bytes)
        - 24..27: timestamp (u32, LE) [HFS epoch]
        - 28..35: persistent_playlist_id (8 bytes)
        - 36..39: unk3 (u32, LE)
        - 40..41: string_mhod_count (u16, LE)
        - 42..43: podcast_flag (u16, LE)
        - 44..47: list_sort_order (u32, LE)
        - ...:    zero padding up to header_length
        Children: mhod strings and mhip items will be inside [off+header_length, off+total_length).
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhyp', start, end):
            hl = self._read_u32_le(off + 4)
            tl = self._read_u32_le(off + 8)
            if hl is None or tl is None or hl < 48 or tl < hl or (off + hl) > self.length or (off + tl) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhyp', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            def bytes_at(o: int, n: int) -> bytes:
                return self.data[off + o: off + o + n]

            tag_b = bytes_at(0, 4)
            header_len_bytes = bytes_at(4, 4)
            total_len_bytes = bytes_at(8, 4)
            doc_count = self._read_u32_le(off + 12)
            doc_count_bytes = bytes_at(12, 4)
            pl_item_count = self._read_u32_le(off + 16)
            pl_item_count_bytes = bytes_at(16, 4)
            is_master_b = bytes_at(20, 1)
            is_master = is_master_b[0] if len(is_master_b) == 1 else None
            flags3 = bytes_at(21, 3)
            timestamp = self._read_u32_le(off + 24)
            timestamp_bytes = bytes_at(24, 4)
            persist_pl_id = bytes_at(28, 8)
            unk3 = self._read_u32_le(off + 36)
            unk3_bytes = bytes_at(36, 4)
            string_mhod_count = self._read_u16_le(off + 40)
            string_mhod_count_bytes = bytes_at(40, 2)
            podcast_flag = self._read_u16_le(off + 42)
            podcast_flag_bytes = bytes_at(42, 2)
            sort_order = self._read_u32_le(off + 44)
            sort_order_bytes = bytes_at(44, 4)

            header_preview = self.data[off: off + hl]

            fields = {
                'tag_bytes': tag_b,
                'header_length': hl,
                'header_length_bytes': header_len_bytes,
                'total_length': tl,
                'total_length_bytes': total_len_bytes,
                'data_object_child_count': doc_count,
                'data_object_child_count_bytes': doc_count_bytes,
                'playlist_item_count': pl_item_count,
                'playlist_item_count_bytes': pl_item_count_bytes,
                'is_master_playlist': is_master,
                'is_master_playlist_bytes': is_master_b,
                'flags3_bytes': flags3,
                'timestamp': timestamp,
                'timestamp_bytes': timestamp_bytes,
                'persistent_playlist_id_bytes': persist_pl_id,
                'unk3': unk3,
                'unk3_bytes': unk3_bytes,
                'string_mhod_count': string_mhod_count,
                'string_mhod_count_bytes': string_mhod_count_bytes,
                'podcast_flag': podcast_flag,
                'podcast_flag_bytes': podcast_flag_bytes,
                'list_sort_order': sort_order,
                'list_sort_order_bytes': sort_order_bytes,
            }

            results.append(Chunk(tag=b'mhyp', offset=off, size=tl, endian='le', raw_header=header_preview, children=[], fields=fields))

        return sorted(results, key=lambda c: c.offset)

    def parse_mhip_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhip (Playlist Item) sections in range.

        Layout (offsets from section start):
        - 0..3:   tag 'mhip'
        - 4..7:   header_length (u32, LE)
        - 8..11:  total_length (u32, LE)
        - 12..15: data_object_child_count (u32, LE)
        - 16..17: podcast_grouping_flag (u16, LE) 0x0000=normal, 0x0100=Podcast Group
        - 18:     unk4 (u8)
        - 19:     unk5 (u8)
        - 20..23: group_id (u32, LE)
        - 24..27: track_id (u32, LE)
        - 28..31: timestamp (u32, LE) HFS epoch
        - 32..35: podcast_grouping_reference (u32, LE)
        - ...:    zero padding up to header_length
        Children region: [off+header_length, off+total_length)
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhip', start, end):
            hl = self._read_u32_le(off + 4)
            tl = self._read_u32_le(off + 8)
            if hl is None or tl is None or hl < 36 or tl < hl or (off + hl) > self.length or (off + tl) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhip', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            def bytes_at(o: int, n: int) -> bytes:
                return self.data[off + o: off + o + n]

            fields = {
                'tag_bytes': bytes_at(0, 4),
                'header_length': hl,
                'header_length_bytes': bytes_at(4, 4),
                'total_length': tl,
                'total_length_bytes': bytes_at(8, 4),
                'data_object_child_count': self._read_u32_le(off + 12),
                'data_object_child_count_bytes': bytes_at(12, 4),
                'podcast_grouping_flag': self._read_u16_le(off + 16),
                'podcast_grouping_flag_bytes': bytes_at(16, 2),
                'unk4': (self.data[off + 18] if off + 19 <= self.length else None),
                'unk4_bytes': bytes_at(18, 1),
                'unk5': (self.data[off + 19] if off + 20 <= self.length else None),
                'unk5_bytes': bytes_at(19, 1),
                'group_id': self._read_u32_le(off + 20),
                'group_id_bytes': bytes_at(20, 4),
                'track_id': self._read_u32_le(off + 24),
                'track_id_bytes': bytes_at(24, 4),
                'timestamp': self._read_u32_le(off + 28),
                'timestamp_bytes': bytes_at(28, 4),
                'podcast_grouping_reference': self._read_u32_le(off + 32),
                'podcast_grouping_reference_bytes': bytes_at(32, 4),
            }

            header_preview = self.data[off: off + hl]
            results.append(Chunk(tag=b'mhip', offset=off, size=tl, endian='le', raw_header=header_preview, children=[], fields=fields))

        return sorted(results, key=lambda c: c.offset)

    def parse_mhla_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhla sections in range.

        Layout:
        - 0..3:  tag 'mhla'
        - 4..7:  header_length (u32, LE)
        - 8..11: number_of_album_items (u32, LE)
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhla', start, end):
            header_len = self._read_u32_le(off + 4)
            num_items = self._read_u32_le(off + 8)

            if header_len is None or num_items is None or header_len < 12 or (off + header_len) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhla', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            tag_bytes = self.data[off: off + 4]
            header_len_bytes = self.data[off + 4: off + 8]
            num_items_bytes = self.data[off + 8: off + 12]
            header_preview = self.data[off: off + header_len]

            fields = {
                'tag_bytes': tag_bytes,
                'header_length': header_len,
                'header_length_bytes': header_len_bytes,
                'number_of_album_items': num_items,
                'number_of_album_items_bytes': num_items_bytes,
            }

            # Size column: show header length (no explicit total length field specified)
            results.append(Chunk(tag=b'mhla', offset=off, size=header_len, endian='le', raw_header=header_preview, children=[], fields=fields))

        return sorted(results, key=lambda c: c.offset)

    def parse_mhia_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhia sections in range.

        Layout (offsets from section start):
        - 0..3:   tag 'mhia'
        - 4..7:   header_length (u32, LE)
        - 8..11:  total_length (u32, LE)
        - 12..15: number_of_strings (u32, LE)
        - 16..19: album_reference_id (u32, LE)
        - 20..27: unk10 (8 bytes)
        - 28..31: unk11 (u32, LE)
        - 32..39: unk12 (8 bytes)
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhia', start, end):
            # Read header primitives
            header_len = self._read_u32_le(off + 4)
            total_len = self._read_u32_le(off + 8)
            num_strings = self._read_u32_le(off + 12)
            album_ref = self._read_u32_le(off + 16)

            # Plausibility: header covers to 40 bytes at least
            if (
                header_len is None or total_len is None or
                header_len < 40 or total_len < header_len or
                (off + header_len) > self.length or (off + total_len) > self.length
            ):
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhia', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            # Capture raw bytes for all fields
            tag_bytes = self.data[off: off + 4]
            header_len_bytes = self.data[off + 4: off + 8]
            total_len_bytes = self.data[off + 8: off + 12]
            num_strings_bytes = self.data[off + 12: off + 16]
            album_ref_bytes = self.data[off + 16: off + 20]
            unk10_bytes = self.data[off + 20: off + 28]
            unk11_bytes = self.data[off + 28: off + 32]
            unk12_bytes = self.data[off + 32: off + 40]
            header_preview = self.data[off: off + header_len]

            fields = {
                'tag_bytes': tag_bytes,
                'header_length': header_len,
                'header_length_bytes': header_len_bytes,
                'total_length': total_len,
                'total_length_bytes': total_len_bytes,
                'number_of_strings': num_strings,
                'number_of_strings_bytes': num_strings_bytes,
                'album_reference_id': album_ref,
                'album_reference_id_bytes': album_ref_bytes,
                'unk10_bytes': unk10_bytes,
                'unk11': self._read_u32_le(off + 28),
                'unk11_bytes': unk11_bytes,
                'unk12_bytes': unk12_bytes,
            }

            results.append(Chunk(tag=b'mhia', offset=off, size=total_len, endian='le', raw_header=header_preview, children=[], fields=fields))

        return sorted(results, key=lambda c: c.offset)

    def parse_mhod_in_range(self, start: int, end: int) -> List[Chunk]:
        """Parse mhod sections in range.

        Layout (offsets from section start) – generic string MHODs:
        - 0..3:   tag 'mhod'
        - 4..7:   header_length (u32, LE) — for most string MHODs this is 0x18 (24)
        - 8..11:  total_length (u32, LE)
        - 12..15: type (u32, LE)
        - 16..19: unk1 (u32, LE)
        - 20..23: unk2 (u32, LE)
        - 24..27: position (u32, LE)
        - 28..31: string_length (u32, LE)
        - 32..35: unk13 (u32, LE)
        - 40..N:  string bytes (length per string_length). Not NULL-terminated, not zero padded.

        Special-case MHOD types 15/16 (Podcast Enclosure / RSS URL):
        - header_length is typically 0x18 (24)
        - there is no position/string_length/unk13; the string starts at offset + header_length
          and occupies (total_length - header_length) bytes, interpreted as UTF-8.
        """
        results: List[Chunk] = []
        for off in self._find_all_in_range(b'mhod', start, end):
            hdr_len = self._read_u32_le(off + 4)
            tot_len = self._read_u32_le(off + 8)
            typ = self._read_u32_le(off + 12)
            if hdr_len is None or tot_len is None or typ is None:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhod', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            # Plausibility: header_len typically >= 24, total_len within file
            min_hdr = 24
            if hdr_len < min_hdr or (off + hdr_len) > self.length or (off + tot_len) > self.length:
                header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                results.append(Chunk(tag=b'mhod', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                continue

            tag_b = self.data[off: off + 4]
            hdr_len_b = self.data[off + 4: off + 8]
            tot_len_b = self.data[off + 8: off + 12]
            typ_b = self.data[off + 12: off + 16]
            unk1 = self._read_u32_le(off + 16)
            unk1_b = self.data[off + 16: off + 20]
            unk2 = self._read_u32_le(off + 20)
            unk2_b = self.data[off + 20: off + 24]

            # Playlist column definition / order entry (type 100) – two known shapes,
            # distinguished by total_length:
            # - 0x2C  => per-track Playlist Order Entry
            # - 0x288 => Playlist Column Definition (iTunes-only metadata)
            if typ == 100 and tot_len is not None:
                # Small "playlist order entry" (per-track) variant.
                if tot_len == 0x2C and (off + tot_len) <= self.length:
                    position = self._read_u32_le(off + 24)
                    position_b = self.data[off + 24: off + 28]
                    padding16_b = self.data[off + 28: off + 44]
                    header_preview = self.data[off: off + tot_len]
                    fields = {
                        'tag_bytes': tag_b,
                        'header_length': hdr_len,
                        'header_length_bytes': hdr_len_b,
                        'total_length': tot_len,
                        'total_length_bytes': tot_len_b,
                        'type': typ,
                        'type_bytes': typ_b,
                        'variant': 'order_entry',
                        'unk1': unk1,
                        'unk1_bytes': unk1_b,
                        'unk2': unk2,
                        'unk2_bytes': unk2_b,
                        'position': position,
                        'position_bytes': position_b,
                        'padding16_bytes': padding16_b,
                    }
                    results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))
                    continue

                # Large "playlist column definition" variant used by iTunes.
                if tot_len == 0x288 and (off + tot_len) <= self.length:
                    unk3 = self._read_u32_le(off + 24)
                    unk3_b = self.data[off + 24: off + 28]
                    unk4_bytes = self.data[off + 28: off + 36]
                    unk4_val = self._read_u64_le(off + 28)
                    unk8 = self._read_u32_le(off + 36)
                    unk8_b = self.data[off + 36: off + 40]
                    unk9 = self._read_u16_le(off + 40)
                    unk9_b = self.data[off + 40: off + 42]
                    unk10 = self._read_u16_le(off + 42)
                    unk10_b = self.data[off + 42: off + 44]
                    sort_type = self._read_u32_le(off + 44)
                    sort_type_b = self.data[off + 44: off + 48]
                    num_cols = self._read_u32_le(off + 48)
                    num_cols_b = self.data[off + 48: off + 52]
                    unknown1 = self._read_u16_le(off + 52)
                    unknown1_b = self.data[off + 52: off + 54]
                    unknown2 = self._read_u16_le(off + 54)
                    unknown2_b = self.data[off + 54: off + 56]

                    cols_start = off + 56
                    cols: List[Dict[str, object]] = []
                    if isinstance(num_cols, int) and num_cols > 0:
                        max_bytes = num_cols * 16
                        cols_end = min(off + tot_len, cols_start + max_bytes)
                        pos_c = cols_start
                        while pos_c + 16 <= cols_end:
                            col_id = self._read_u16_le(pos_c)
                            col_id_b = self.data[pos_c: pos_c + 2]
                            width = self._read_u16_le(pos_c + 2)
                            width_b = self.data[pos_c + 2: pos_c + 4]
                            sort_dir = self._read_u32_le(pos_c + 4)
                            sort_dir_b = self.data[pos_c + 4: pos_c + 8]
                            unk_c1_b = self.data[pos_c + 8: pos_c + 12]
                            unk_c2_b = self.data[pos_c + 12: pos_c + 16]
                            cols.append(
                                {
                                    'column_id': col_id,
                                    'column_id_bytes': col_id_b,
                                    'width': width,
                                    'width_bytes': width_b,
                                    'sort_direction': sort_dir,
                                    'sort_direction_bytes': sort_dir_b,
                                    'unknown1_bytes': unk_c1_b,
                                    'unknown2_bytes': unk_c2_b,
                                }
                            )
                            pos_c += 16

                    header_preview = self.data[off: off + tot_len]
                    fields = {
                        'tag_bytes': tag_b,
                        'header_length': hdr_len,
                        'header_length_bytes': hdr_len_b,
                        'total_length': tot_len,
                        'total_length_bytes': tot_len_b,
                        'type': typ,
                        'type_bytes': typ_b,
                        'variant': 'column_def',
                        'unk1': unk1,
                        'unk1_bytes': unk1_b,
                        'unk2': unk2,
                        'unk2_bytes': unk2_b,
                        'unk3': unk3,
                        'unk3_bytes': unk3_b,
                        'unk4': unk4_val,
                        'unk4_bytes': unk4_bytes,
                        'unk8': unk8,
                        'unk8_bytes': unk8_b,
                        'unk9': unk9,
                        'unk9_bytes': unk9_b,
                        'unk10': unk10,
                        'unk10_bytes': unk10_b,
                        'sort_type': sort_type,
                        'sort_type_bytes': sort_type_b,
                        'number_of_columns': num_cols,
                        'number_of_columns_bytes': num_cols_b,
                        'unknown1': unknown1,
                        'unknown1_bytes': unknown1_b,
                        'unknown2': unknown2,
                        'unknown2_bytes': unknown2_b,
                        'columns': cols,
                    }
                    results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))
                    continue

            # For Smart Playlist Data (type 50), interpret the body as flag/limit
            # structure instead of a string payload.
            if typ == 50:
                def b_at(rel: int) -> Optional[int]:
                    idx = off + rel
                    if idx < self.length:
                        return self.data[idx]
                    return None

                def bytes_at(rel: int, n: int) -> bytes:
                    return self.data[off + rel: off + rel + n]

                live_update = b_at(24)
                check_rules = b_at(25)
                check_limits = b_at(26)
                limit_type = b_at(27)
                limit_sort = b_at(28)
                zeros_29_31 = bytes_at(29, 3)
                limit_value = self._read_u32_le(off + 32)
                limit_value_bytes = bytes_at(32, 4)
                match_checked_only = b_at(36)
                reverse_limit_sort = b_at(37)

                header_preview = self.data[off: off + tot_len]
                fields = {
                    'tag_bytes': tag_b,
                    'header_length': hdr_len,
                    'header_length_bytes': hdr_len_b,
                    'total_length': tot_len,
                    'total_length_bytes': tot_len_b,
                    'type': typ,
                    'type_bytes': typ_b,
                    'unk1': unk1,
                    'unk1_bytes': unk1_b,
                    'unk2': unk2,
                    'unk2_bytes': unk2_b,
                    'live_update': live_update,
                    'live_update_bytes': bytes_at(24, 1),
                    'check_rules': check_rules,
                    'check_rules_bytes': bytes_at(25, 1),
                    'check_limits': check_limits,
                    'check_limits_bytes': bytes_at(26, 1),
                    'limit_type': limit_type,
                    'limit_type_bytes': bytes_at(27, 1),
                    'limit_sort': limit_sort,
                    'limit_sort_bytes': bytes_at(28, 1),
                    'zeros_29_31_bytes': zeros_29_31,
                    'limit_value': limit_value,
                    'limit_value_bytes': limit_value_bytes,
                    'match_checked_only': match_checked_only,
                    'match_checked_only_bytes': bytes_at(36, 1),
                    'reverse_limit_sort': reverse_limit_sort,
                    'reverse_limit_sort_bytes': bytes_at(37, 1),
                }
                results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))
                continue

            # For Library Playlist Index (type 52), parse the index header and entry list.
            if typ == 52:
                # Need space through index entries header (offset 72)
                if tot_len is None or tot_len < 72 or (off + 72) > self.length or (off + tot_len) > self.length:
                    header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                    results.append(Chunk(tag=b'mhod', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                    continue

                index_type = self._read_u32_le(off + 24)
                index_type_b = self.data[off + 24: off + 28]
                count = self._read_u32_le(off + 28)
                count_b = self.data[off + 28: off + 32]
                padding_b = self.data[off + 32: off + 72]

                entries_start = off + 72
                expected_bytes = 0
                if isinstance(count, int) and count > 0:
                    expected_bytes = count * 4
                entries_end = min(off + tot_len, entries_start + expected_bytes)
                entries_bytes = self.data[entries_start: entries_end]

                entries: List[int] = []
                pos = entries_start
                while pos + 4 <= entries_end:
                    val = self._read_u32_le(pos)
                    if val is None:
                        break
                    entries.append(val)
                    pos += 4

                header_preview = self.data[off: off + tot_len]
                fields = {
                    'tag_bytes': tag_b,
                    'header_length': hdr_len,
                    'header_length_bytes': hdr_len_b,
                    'total_length': tot_len,
                    'total_length_bytes': tot_len_b,
                    'type': typ,
                    'type_bytes': typ_b,
                    'unk1': unk1,
                    'unk1_bytes': unk1_b,
                    'unk2': unk2,
                    'unk2_bytes': unk2_b,
                    'index_type': index_type,
                    'index_type_bytes': index_type_b,
                    'count': count,
                    'count_bytes': count_b,
                    'padding_bytes': padding_b,
                    'entries_bytes': entries_bytes,
                    'entries': entries,
                }
                results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))
                continue

            # For Letter Jump Table (type 53), parse the index header and per-letter entries.
            if typ == 53:
                # Need space through letter index header (offset 40)
                if tot_len is None or tot_len < 40 or (off + 40) > self.length or (off + tot_len) > self.length:
                    header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                    results.append(Chunk(tag=b'mhod', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                    continue

                index_type = self._read_u32_le(off + 24)
                index_type_b = self.data[off + 24: off + 28]
                count = self._read_u32_le(off + 28)
                count_b = self.data[off + 28: off + 32]
                padding_b = self.data[off + 32: off + 40]

                entries_start = off + 40
                expected_bytes = 0
                if isinstance(count, int) and count > 0:
                    expected_bytes = count * 12
                entries_end = min(off + tot_len, entries_start + expected_bytes)
                entries_bytes = self.data[entries_start: entries_end]

                entries = []
                pos = entries_start
                while pos + 12 <= entries_end:
                    letter_raw = self._read_u32_le(pos)
                    first_index = self._read_u32_le(pos + 4)
                    entry_count = self._read_u32_le(pos + 8)
                    if letter_raw is None or first_index is None or entry_count is None:
                        break
                    letter_bytes = self.data[pos: pos + 4]
                    # Lower 16 bits are UTF-16LE code unit; upper 16 bits padding.
                    ch_code = letter_raw & 0xFFFF
                    try:
                        letter_char = chr(ch_code)
                    except ValueError:
                        letter_char = ''
                    entries.append(
                        {
                            'letter_raw': letter_raw,
                            'letter_bytes': letter_bytes,
                            'letter_char': letter_char,
                            'first_index': first_index,
                            'entry_count': entry_count,
                        }
                    )
                    pos += 12

                header_preview = self.data[off: off + tot_len]
                fields = {
                    'tag_bytes': tag_b,
                    'header_length': hdr_len,
                    'header_length_bytes': hdr_len_b,
                    'total_length': tot_len,
                    'total_length_bytes': tot_len_b,
                    'type': typ,
                    'type_bytes': typ_b,
                    'unk1': unk1,
                    'unk1_bytes': unk1_b,
                    'unk2': unk2,
                    'unk2_bytes': unk2_b,
                    'index_type': index_type,
                    'index_type_bytes': index_type_b,
                    'count': count,
                    'count_bytes': count_b,
                    'padding_bytes': padding_b,
                    'entries_bytes': entries_bytes,
                    'entries': entries,
                }
                results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))
                continue

            # For Smart Playlist Rules (type 51), parse the mixed-endian header and
            # the big-endian SLst rules payload into a structured list.
            if typ == 51:
                # We require enough space for the fixed 160-byte header region.
                # Some databases may report a header_length smaller than 160,
                # but the SLst block (and padding) still start at offset 24 and
                # extend through offset 160, so we key off total_length here.
                if tot_len is None or tot_len < 160 or (off + 160) > self.length or (off + tot_len) > self.length:
                    header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                    results.append(Chunk(tag=b'mhod', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                    continue

                smart_list_id = self.data[off + 24: off + 28]
                # Everything from here on is big-endian.
                unk5 = self._read_u32_be(off + 28)
                unk5_b = self.data[off + 28: off + 32]
                num_rules = self._read_u32_be(off + 32)
                num_rules_b = self.data[off + 32: off + 36]
                rules_op = self._read_u32_be(off + 36)
                rules_op_b = self.data[off + 36: off + 40]
                padding_b = self.data[off + 40: off + 160]

                rules_start = off + 160
                rules_end = off + tot_len
                rules = []

                pos = rules_start
                while pos < rules_end:
                    # Need at least field+action to proceed.
                    if pos + 8 > rules_end:
                        break

                    field_id = self._read_u32_be(pos)
                    action = self._read_u32_be(pos + 4)
                    field_b = self.data[pos: pos + 4]
                    action_b = self.data[pos + 4: pos + 8]
                    if field_id is None or action is None:
                        break

                    # High byte bit 0 indicates string vs non-string.
                    high = (action >> 24) & 0xFF
                    is_string = bool(high & 0x01)

                    rule: Dict[str, object] = {
                        'offset_within_rules': pos - rules_start,
                        'field_id': field_id,
                        'field_bytes': field_b,
                        'action': action,
                        'action_bytes': action_b,
                        'is_string': is_string,
                    }

                    if is_string:
                        # String rule: field (4) + action (4) + 44 padding + 4 length + UTF-16BE string.
                        if pos + 56 > rules_end:
                            break
                        padding_rule_b = self.data[pos + 8: pos + 52]
                        strlen = self._read_u32_be(pos + 52) or 0
                        str_start = pos + 56
                        str_end = min(str_start + max(0, strlen), rules_end)
                        s_bytes = self.data[str_start: str_end]
                        try:
                            s_txt = s_bytes.decode('utf-16-be', errors='replace')
                        except Exception:
                            s_txt = ''

                        rule.update({
                            'padding_bytes': padding_rule_b,
                            'string_length': strlen,
                            'string_bytes': s_bytes,
                            'string_text': s_txt,
                        })
                        pos = str_start + len(s_bytes)
                    else:
                        # Non-string rule: fixed 0x44 payload with from/to value/date/units.
                        rule_size = 124  # 4+4+44+4+(6*8)+20
                        if pos + rule_size > rules_end:
                            break

                        padding_rule_b = self.data[pos + 8: pos + 52]
                        length_be = self._read_u32_be(pos + 52)
                        from_val = self._read_u64_be(pos + 56)
                        from_date = self._read_i64_be(pos + 64)
                        from_units = self._read_u64_be(pos + 72)
                        to_val = self._read_u64_be(pos + 80)
                        to_date = self._read_i64_be(pos + 88)
                        to_units = self._read_u64_be(pos + 96)
                        unknown_b = self.data[pos + 104: pos + 124]

                        rule.update({
                            'padding_bytes': padding_rule_b,
                            'length_be': length_be,
                            'from_value': from_val,
                            'from_date': from_date,
                            'from_units': from_units,
                            'to_value': to_val,
                            'to_date': to_date,
                            'to_units': to_units,
                            'unknown_bytes': unknown_b,
                        })
                        pos += rule_size

                    rules.append(rule)

                header_preview = self.data[off: off + tot_len]
                fields = {
                    'tag_bytes': tag_b,
                    'header_length': hdr_len,
                    'header_length_bytes': hdr_len_b,
                    'total_length': tot_len,
                    'total_length_bytes': tot_len_b,
                    'type': typ,
                    'type_bytes': typ_b,
                    'unk1': unk1,
                    'unk1_bytes': unk1_b,
                    'unk2': unk2,
                    'unk2_bytes': unk2_b,
                    'smart_list_id_bytes': smart_list_id,
                    'unk5': unk5,
                    'unk5_bytes': unk5_b,
                    'number_of_rules': num_rules,
                    'number_of_rules_bytes': num_rules_b,
                    'rules_operator': rules_op,
                    'rules_operator_bytes': rules_op_b,
                    'rules_padding_bytes': padding_b,
                    'rules_bytes': self.data[rules_start: rules_end],
                    'rules': rules,
                }
                results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))
                continue

            # Layout diverges for podcast URL types (15, 16): the string starts
            # directly at offset + header_length and there is no separate
            # position/string_length/unk13 trio in the header.
            if typ in (15, 16):
                pos = None
                pos_b = b""
                # Derive string length from header/total lengths
                str_start = off + int(hdr_len)
                str_len = max(0, (tot_len or 0) - int(hdr_len))
                str_len_b = b""
                unk13 = None
                unk13_b = b""
                pad16_b = b""
            else:
                # Generic string MHOD layout
                # Ensure we at least have space up to string start (offset 40) inside total_len.
                if tot_len < 40:
                    header_preview = self.data[off: off + min(64, max(0, self.length - off))]
                    results.append(Chunk(tag=b'mhod', offset=off, size=None, endian='le', raw_header=header_preview, children=[], fields=None))
                    continue
                pos = self._read_u32_le(off + 24)
                pos_b = self.data[off + 24: off + 28]
                str_len = self._read_u32_le(off + 28)
                str_len_b = self.data[off + 28: off + 32]
                unk13 = self._read_u32_le(off + 32)
                unk13_b = self.data[off + 32: off + 36]
                pad16_b = self.data[off + 28: off + 44]
                # String region for generic string MHODs starts at fixed offset 40
                str_start = off + 40

            limit = min(self.length, off + tot_len)
            if typ in (15, 16) or str_len is None:
                effective_len = max(0, limit - str_start)
            else:
                declared = max(0, int(str_len))
                max_available = max(0, limit - str_start)
                effective_len = min(declared, max_available)

            string_b = self.data[str_start: str_start + effective_len]
            # For mhod, preview the entire section (total_length), not just the header
            header_preview = self.data[off: off + tot_len]

            fields = {
                'tag_bytes': tag_b,
                'header_length': hdr_len,
                'header_length_bytes': hdr_len_b,
                'total_length': tot_len,
                'total_length_bytes': tot_len_b,
                'type': typ,
                'type_bytes': typ_b,
                'position': pos,
                'position_bytes': pos_b,
                'unk1': unk1,
                'unk1_bytes': unk1_b,
                'unk2': unk2,
                'unk2_bytes': unk2_b,
                'string_length': str_len,
                'string_length_bytes': str_len_b,
                'unk13': unk13,
                'unk13_bytes': unk13_b,
                'padding16_bytes': pad16_b,
                'string_bytes': string_b,
            }

            results.append(Chunk(tag=b'mhod', offset=off, size=tot_len, endian='le', raw_header=header_preview, children=[], fields=fields))

        return sorted(results, key=lambda c: c.offset)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("iTunesDB Explorer (Phase 1: mhbd)")
        self.geometry("1200x800")
        self._build_ui()
        self.file_bytes: Optional[bytes] = None
        self.parser: Optional[ITunesDBParser] = None
        self.reverse_bytes: bool = False  # When True, reverse display of byte fields

    def _build_ui(self):
        # Menu
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open iTunesDB...", command=self.open_file)
        filemenu.add_command(label="Export parsed tree...", command=self.export_parsed_tree)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        self.config(menu=menubar)

        # Layout: left = Tree, right = details
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(0, weight=1)

        # Tree
        self.tree = ttk.Treeview(self, columns=("offset", "size", "endian"), show="tree headings")
        self.tree.heading("offset", text="Offset")
        self.tree.heading("size", text="Size")
        self.tree.heading("endian", text="Endian")
        self.tree.column("offset", width=120, anchor='w', stretch=False)
        self.tree.column("size", width=100, anchor='w', stretch=False)
        self.tree.column("endian", width=80, anchor='w', stretch=False)
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Details panel
        right = ttk.Frame(self)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        self.detail_title = ttk.Label(right, text="Select a node to see details", font=("Segoe UI", 10, "bold"))
        self.detail_title.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))

        # Options row
        opts = ttk.Frame(right)
        opts.grid(row=1, column=0, sticky="w", padx=8)
        self.reverse_var = tk.BooleanVar(value=False)
        reverse_cb = ttk.Checkbutton(opts, text="Reverse byte-order for byte fields", variable=self.reverse_var, command=self.on_toggle_reverse)
        reverse_cb.grid(row=0, column=0, sticky="w")

        self.detail_text = tk.Text(right, font=("Consolas", 10), wrap="none")
        self.detail_text.grid(row=2, column=0, sticky="nsew", padx=8, pady=8)

        # Scrollbars for text
        yscroll = ttk.Scrollbar(right, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=2, column=1, sticky="ns")

        # Bind selection
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<<TreeviewOpen>>", lambda e: self._autosize_tree_columns())
        self.tree.bind("<<TreeviewClose>>", lambda e: self._autosize_tree_columns())

        # Store mapping from tree item to metadata
        self._node_meta: Dict[str, Dict] = {}

    def on_toggle_reverse(self):
        self.reverse_bytes = bool(self.reverse_var.get())
        # Re-render currently selected node with new preference
        self.on_tree_select()

    def open_file(self):
        path = filedialog.askopenfilename(title="Open iTunesDB file", filetypes=[("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{e}")
            return

        self.file_bytes = data
        self.parser = ITunesDBParser(data)
        self.populate_tree(path)

    def _serialize_for_export(self, obj: Any) -> Any:
        """Recursively convert parser/tree data into JSON-serializable types.

        - bytes -> hex string ("aa bb cc")
        - dicts / lists -> walk recursively
        - other primitives left as-is
        """
        if isinstance(obj, bytes):
            return bytes_spaced_hex(obj)
        if isinstance(obj, dict):
            return {str(k): self._serialize_for_export(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._serialize_for_export(v) for v in obj]
        return obj

    def export_parsed_tree(self):
        """Export the current tree structure and parsed fields to a JSON file.

        The export is designed for offline diffing/analysis across multiple
        iTunesDB snapshots. It includes:
        - tree hierarchy
        - chunk offsets/sizes/tags
        - parsed fields, with all byte blobs rendered as hex strings
        """
        if not self.parser or not self.file_bytes:
            messagebox.showerror("Export error", "No iTunesDB file is loaded.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Export parsed tree",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not save_path:
            return

        # Build a tree-shaped representation based on the current Treeview.
        def node_to_dict(item_id: str) -> Dict[str, Any]:
            meta = self._node_meta.get(item_id, {})
            children_ids = self.tree.get_children(item_id)
            children = [node_to_dict(cid) for cid in children_ids]

            if meta.get("type") == "file":
                return {
                    "kind": "file",
                    "path": meta.get("path"),
                    "size": meta.get("size"),
                    "children": children,
                }

            if meta.get("type") == "chunk":
                ch: Chunk = meta.get("chunk")
                base = {
                    "kind": "chunk",
                    "tag": ch.tag.decode("ascii", errors="replace"),
                    "offset": ch.offset,
                    "size": ch.size,
                    "endian": ch.endian,
                    "raw_header_hex": bytes_spaced_hex(ch.raw_header),
                    "children": children,
                }
                if ch.fields:
                    base["fields"] = self._serialize_for_export(ch.fields)
                return base

            # Fallback: unknown node type; just capture text + children.
            return {
                "kind": "unknown",
                "text": self.tree.item(item_id, "text"),
                "children": children,
            }

        roots = []
        for root_id in self.tree.get_children(''):
            roots.append(node_to_dict(root_id))

        export_obj = {
            "export_version": 1,
            "source": {
                "note": "Paths are as opened in this session",
            },
            "tree": roots,
        }

        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(export_obj, f, indent=2, sort_keys=True)
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to write export:\n{e}")

    def populate_tree(self, path: str):
        self.tree.delete(*self.tree.get_children())
        self._node_meta.clear()

        filesize = len(self.file_bytes) if self.file_bytes is not None else 0
        root_text = f"File: {path} ({filesize} bytes)"
        root_id = self.tree.insert('', 'end', text=root_text, values=("-", "-", "-"))
        self._node_meta[root_id] = {"type": "file", "path": path, "size": filesize}

        if not self.parser:
            return

        # Parse mhbd and mhsd, and nest mhsd under mhbd by offset ranges
        mhbd_chunks = sorted(self.parser.parse_mhbd(), key=lambda c: c.offset)
        mhsd_chunks = self.parser.parse_mhsd()

        if not mhbd_chunks:
            no_id = self.tree.insert(root_id, 'end', text="No mhbd tag found", values=("-", "-", "-"))
            self._node_meta[no_id] = {"type": "info"}
        else:
            # Partition mhsd by mhbd ranges (header end .. next mhbd start)
            for idx, ch in enumerate(mhbd_chunks):
                ch.children = []
                start = (ch.offset + (ch.size or 0))
                end = mhbd_chunks[idx + 1].offset if (idx + 1) < len(mhbd_chunks) else self.parser.length
                for sd in mhsd_chunks:
                    if sd.offset >= start and sd.offset < end:
                        ch.children.append(sd)
                # Fallback: if no mhsd was associated by range, but we have
                # parsed mhsd chunks at all, attach them all under the first
                # mhbd so that the tree remains navigable even for unusual
                # layouts.
                if not ch.children and mhsd_chunks and idx == 0:
                    ch.children.extend(mhsd_chunks)

            for ch in mhbd_chunks:
                off = f"0x{ch.offset:08X}"
                size_str = str(ch.size) if ch.size is not None else "?"
                endian = ch.endian or "?"
                node_id = self.tree.insert(root_id, 'end', text=ch.tag.decode('ascii', 'replace'), values=(off, size_str, endian))
                self._node_meta[node_id] = {"type": "chunk", "chunk": ch}

                # Insert children (mhsd) under mhbd
                for sd in ch.children:
                    off_sd = f"0x{sd.offset:08X}"
                    size_sd = str(sd.size) if sd.size is not None else "?"
                    endian_sd = sd.endian or "?"
                    sd_id = self.tree.insert(node_id, 'end', text=sd.tag.decode('ascii', 'replace'), values=(off_sd, size_sd, endian_sd))
                    self._node_meta[sd_id] = {"type": "chunk", "chunk": sd}

                    # For each mhsd, parse and insert its expected child list(s)
                    if sd.fields and 'header_length' in sd.fields and 'total_length' in sd.fields:
                        hl = sd.fields['header_length']
                        tl = sd.fields['total_length']
                        start = sd.offset + hl
                        end = sd.offset + tl
                        type_val = sd.fields.get('type')

                        # Decide which tags to look for based on type
                        child_chunks: List[Chunk] = []
                        if type_val == 1:
                            child_chunks.extend(self.parser.parse_mhlt_in_range(start, end))
                        elif type_val in (2, 3, 5):
                            child_chunks.extend(self.parser.parse_mhlp_in_range(start, end))
                        elif type_val == 4:
                            child_chunks.extend(self.parser.parse_mhla_in_range(start, end))
                        else:
                            # Unknown: try all known list types
                            child_chunks.extend(self.parser.parse_mhlt_in_range(start, end))
                            child_chunks.extend(self.parser.parse_mhlp_in_range(start, end))
                            child_chunks.extend(self.parser.parse_mhla_in_range(start, end))

                        # Attach to tree
                        for cc in sorted(child_chunks, key=lambda c: c.offset):
                            off_cc = f"0x{cc.offset:08X}"
                            size_cc = str(cc.size) if cc.size is not None else "?"
                            endian_cc = cc.endian or "?"
                            cc_id = self.tree.insert(sd_id, 'end', text=cc.tag.decode('ascii', 'replace'), values=(off_cc, size_cc, endian_cc))
                            self._node_meta[cc_id] = {"type": "chunk", "chunk": cc}

                            # If this is mhlt, parse and attach mhit tracks
                            if cc.tag == b'mhlt' and cc.fields:
                                cc_hl = cc.fields.get('header_length') or 0
                                cc_ns = cc.fields.get('number_of_songs') or 0
                                th_start = cc.offset + cc_hl
                                th_end = end
                                hit_chunks = self.parser.parse_mhit_in_range(th_start, th_end)
                                for hi in hit_chunks:
                                    off_hi = f"0x{hi.offset:08X}"
                                    size_hi = str(hi.size) if hi.size is not None else "?"
                                    endian_hi = hi.endian or "?"
                                    hi_id = self.tree.insert(cc_id, 'end', text=hi.tag.decode('ascii', 'replace'), values=(off_hi, size_hi, endian_hi))
                                    self._node_meta[hi_id] = {"type": "chunk", "chunk": hi}

                                    # Under each mhit, attach mhod strings
                                    if hi.fields and 'header_length' in hi.fields and 'total_length' in hi.fields:
                                        hit_hl = hi.fields['header_length']
                                        hit_tl = hi.fields['total_length']
                                        hit_start = hi.offset + hit_hl
                                        hit_end = hi.offset + hit_tl
                                        nstr = hi.fields.get('number_of_strings') or 0
                                        od_chunks = self.parser.parse_mhod_in_range(hit_start, hit_end)
                                        for od in od_chunks:
                                            off_od = f"0x{od.offset:08X}"
                                            size_od = str(od.size) if od.size is not None else "?"
                                            endian_od = od.endian or "?"
                                            tv = od.fields.get('type') if od.fields else None
                                            type_desc_map = {1:'Title',2:'Location',3:'Album',4:'Artist',5:'Genre',6:'Filetype',7:'EQ Setting',8:'Comment',9:'Category',12:'Composer',13:'Grouping',14:'Description',15:'Enclosure URL',16:'RSS URL',17:'Chapter data',18:'Subtitle',19:'Show',20:'Episode #',21:'TV Network',22:'Album Artist',23:'Artist (sort)',24:'Keywords',25:'Locale',27:'Title (sort)',28:'Album (sort)',29:'Album-Artist (sort)',30:'Composer (sort)',31:'TV-Show (sort)',32:'Binary',50:'Smart Playlist Data',51:'Smart Playlist Rules',52:'Library Playlist Index',53:'Letter Jump Table',100:'Playlist Order Entry',200:'Album (AL)',201:'Artist (AL)',202:'Artist (sort, AL)',203:'Podcast URL (AL)',204:'TV Show (AL)'}
                                            desc = type_desc_map.get(tv, 'Unknown') if isinstance(tv, int) else 'Unknown'
                                            if desc.endswith('(sort)'):
                                                base = desc[:-6].strip()
                                                desc = f"{base} - Sort"
                                            od_label = f"mhod ({desc})"
                                            od_id = self.tree.insert(hi_id, 'end', text=od_label, values=(off_od, size_od, endian_od))
                                            self._node_meta[od_id] = {"type": "chunk", "chunk": od}

                            # If this is mhlp, parse and attach mhyp playlists
                            if cc.tag == b'mhlp' and cc.fields:
                                pl_hl = cc.fields.get('header_length') or 0
                                pl_count = cc.fields.get('number_of_playlists') or 0
                                pl_start = cc.offset + pl_hl
                                pl_end = end
                                hyp_chunks = self.parser.parse_mhyp_in_range(pl_start, pl_end)
                                for py in hyp_chunks[:max(0, int(pl_count))]:
                                    off_py = f"0x{py.offset:08X}"
                                    size_py = str(py.size) if py.size is not None else "?"
                                    endian_py = py.endian or "?"
                                    py_id = self.tree.insert(cc_id, 'end', text=py.tag.decode('ascii', 'replace'), values=(off_py, size_py, endian_py))
                                    self._node_meta[py_id] = {"type": "chunk", "chunk": py}

                                    # Under each mhyp, attach mhod strings and mhip playlist items
                                    if py.fields and 'header_length' in py.fields and 'total_length' in py.fields:
                                        py_hl = py.fields['header_length']
                                        py_tl = py.fields['total_length']
                                        py_start = py.offset + py_hl
                                        py_end = py.offset + py_tl

                                        # Attach string MHODs (type < 50), cap by string_mhod_count when provided
                                        str_cap = py.fields.get('string_mhod_count') or 0
                                        py_mhods = self.parser.parse_mhod_in_range(py_start, py_end)
                                        # We won’t filter by type here; just cap to count if nonzero
                                        for od in py_mhods:
                                            off_od = f"0x{od.offset:08X}"
                                            size_od = str(od.size) if od.size is not None else "?"
                                            endian_od = od.endian or "?"
                                            tv = od.fields.get('type') if od.fields else None
                                            type_desc_map = {1:'Title',2:'Location',3:'Album',4:'Artist',5:'Genre',6:'Filetype',7:'EQ Setting',8:'Comment',9:'Category',12:'Composer',13:'Grouping',14:'Description',15:'Enclosure URL',16:'RSS URL',17:'Chapter data',18:'Subtitle',19:'Show',20:'Episode #',21:'TV Network',22:'Album Artist',23:'Artist (sort)',24:'Keywords',25:'Locale',27:'Title (sort)',28:'Album (sort)',29:'Album-Artist (sort)',30:'Composer (sort)',31:'TV-Show (sort)',32:'Binary',50:'Smart Playlist Data',51:'Smart Playlist Rules',52:'Library Playlist Index',53:'Letter Jump Table',100:'Playlist Order Entry',200:'Album (AL)',201:'Artist (AL)',202:'Artist (sort, AL)',203:'Podcast URL (AL)',204:'TV Show (AL)'}
                                            desc = type_desc_map.get(tv, 'Unknown') if isinstance(tv, int) else 'Unknown'
                                            if desc.endswith('(sort)'):
                                                base = desc[:-6].strip()
                                                desc = f"{base} - Sort"
                                            od_label = f"mhod ({desc})"
                                            od_id = self.tree.insert(py_id, 'end', text=od_label, values=(off_od, size_od, endian_od))
                                            self._node_meta[od_id] = {"type": "chunk", "chunk": od}

                                        # Attach mhip playlist items
                                        plc = py.fields.get('playlist_item_count') or 0
                                        mhip_chunks = self.parser.parse_mhip_in_range(py_start, py_end)
                                        for pi in mhip_chunks:
                                            off_pi = f"0x{pi.offset:08X}"
                                            size_pi = str(pi.size) if pi.size is not None else "?"
                                            endian_pi = pi.endian or "?"
                                            pi_id = self.tree.insert(py_id, 'end', text=pi.tag.decode('ascii', 'replace'), values=(off_pi, size_pi, endian_pi))
                                            self._node_meta[pi_id] = {"type": "chunk", "chunk": pi}

                                            # Attach mhod children under each mhip (cap by data_object_child_count)
                                            if pi.fields and 'header_length' in pi.fields and 'total_length' in pi.fields:
                                                pii_hl = pi.fields['header_length']
                                                pii_tl = pi.fields['total_length']
                                                pii_start = pi.offset + pii_hl
                                                pii_end = pi.offset + pii_tl
                                                child_cap = pi.fields.get('data_object_child_count') or 0
                                                od2 = self.parser.parse_mhod_in_range(pii_start, pii_end)
                                                for o2 in od2:
                                                    off_o2 = f"0x{o2.offset:08X}"
                                                    size_o2 = str(o2.size) if o2.size is not None else "?"
                                                    endian_o2 = o2.endian or "?"
                                                    o2_id = self.tree.insert(pi_id, 'end', text=o2.tag.decode('ascii', 'replace'), values=(off_o2, size_o2, endian_o2))
                                                    self._node_meta[o2_id] = {"type": "chunk", "chunk": o2}

                            # If this is mhla, try to populate mhia children.
                            if cc.tag == b'mhla' and cc.fields:
                                hl = cc.fields.get('header_length') or 0
                                nai = cc.fields.get('number_of_album_items') or 0
                                start_ai = cc.offset + hl
                                end_ai = end
                                ai_chunks = self.parser.parse_mhia_in_range(start_ai, end_ai)
                                # Only attach up to the number of album items reported
                                for ai in ai_chunks:
                                    off_ai = f"0x{ai.offset:08X}"
                                    size_ai = str(ai.size) if ai.size is not None else "?"
                                    endian_ai = ai.endian or "?"
                                    ai_id = self.tree.insert(cc_id, 'end', text=ai.tag.decode('ascii', 'replace'), values=(off_ai, size_ai, endian_ai))
                                    self._node_meta[ai_id] = {"type": "chunk", "chunk": ai}

                                    # Parse and attach mhod strings under each mhia
                                    if ai.fields and 'header_length' in ai.fields and 'total_length' in ai.fields:
                                        mih_hl = ai.fields['header_length']
                                        mih_tl = ai.fields['total_length']
                                        mih_start = ai.offset + mih_hl
                                        mih_end = ai.offset + mih_tl
                                        nstr = ai.fields.get('number_of_strings') or 0
                                        mhod_chunks = self.parser.parse_mhod_in_range(mih_start, mih_end)
                                        for od in mhod_chunks:
                                            off_od = f"0x{od.offset:08X}"
                                            size_od = str(od.size) if od.size is not None else "?"
                                            endian_od = od.endian or "?"
                                            tv = od.fields.get('type') if od.fields else None
                                            type_desc_map = {1:'Title',2:'Location',3:'Album',4:'Artist',5:'Genre',6:'Filetype',7:'EQ Setting',8:'Comment',9:'Category',12:'Composer',13:'Grouping',14:'Description',15:'Enclosure URL',16:'RSS URL',17:'Chapter data',18:'Subtitle',19:'Show',20:'Episode #',21:'TV Network',22:'Album Artist',23:'Artist (sort)',24:'Keywords',25:'Locale',27:'Title (sort)',28:'Album (sort)',29:'Album-Artist (sort)',30:'Composer (sort)',31:'TV-Show (sort)',32:'Binary',50:'Smart Playlist Data',51:'Smart Playlist Rules',52:'Library Playlist Index',53:'Letter Jump Table',100:'Order indicator',200:'Album (AL)',201:'Artist (AL)',202:'Artist (sort, AL)',203:'Podcast URL (AL)',204:'TV Show (AL)'}
                                            desc = type_desc_map.get(tv, 'Unknown') if isinstance(tv, int) else 'Unknown'
                                            if desc.endswith('(sort)'):
                                                base = desc[:-6].strip()
                                                desc = f"{base} - Sort"
                                            od_label = f"mhod ({desc})"
                                            od_id = self.tree.insert(ai_id, 'end', text=od_label, values=(off_od, size_od, endian_od))
                                            self._node_meta[od_id] = {"type": "chunk", "chunk": od}

        self.tree.item(root_id, open=True)
        # Autosize columns to content after population
        self._autosize_tree_columns()

    def on_tree_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        meta = self._node_meta.get(item_id)
        if not meta:
            return

        self.detail_text.config(state='normal')
        self.detail_text.delete('1.0', tk.END)

        if meta["type"] == "file":
            self.detail_title.config(text="File Details")
            size = meta.get("size", 0)
            path = meta.get("path", "")
            self.detail_text.insert(tk.END, f"Path: {path}\nSize: {size} bytes\n")
        elif meta["type"] == "chunk":
            ch: Chunk = meta["chunk"]
            self.detail_title.config(text=f"Chunk: {ch.tag.decode('ascii', 'replace')}")
            self.detail_text.insert(tk.END, f"Tag: {ch.tag.decode('ascii', 'replace')}\n")
            self.detail_text.insert(tk.END, f"Offset: 0x{ch.offset:08X} ({ch.offset})\n")
            self.detail_text.insert(tk.END, f"Size: {ch.size if ch.size is not None else '?'}\n")
            self.detail_text.insert(tk.END, f"Endian: {ch.endian or '?'}\n\n")

            # If we parsed known fields (mhbd), render them.
            if ch.fields and ch.tag == b'mhbd':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhbd header fields (LE):\n")

                # Bytes to display (optionally reversed for presentation)
                tag_b = f.get('tag_bytes') or b''
                db_uuid = f.get('database_uuid_bytes') or b''
                stable = f.get('stable_identifier_bytes') or b''
                lang_b = f.get('language_bytes') or b''
                plid = f.get('persistent_library_id_bytes') or b''
                if self.reverse_bytes:
                    db_uuid = db_uuid[::-1]
                    stable = stable[::-1]
                    lang_b = lang_b[::-1]
                    plid = plid[::-1]

                # Numeric fields
                hs = f.get('header_size')
                hs_b = f.get('header_size_bytes') or b''
                tfs = f.get('total_file_size')
                tfs_b = f.get('total_file_size_bytes') or b''
                unk1 = f.get('unk1')
                unk1_b = f.get('unk1_bytes') or b''
                dv = f.get('database_version')
                dv_b = f.get('database_version_bytes') or b''
                nsets = f.get('num_mhsd_sets')
                nsets_b = f.get('num_mhsd_sets_bytes') or b''
                unk2 = f.get('unk2')
                unk2_b = f.get('unk2_bytes') or b''
                unk3 = f.get('unk3')
                unk3_b = f.get('unk3_bytes') or b''
                unk4 = f.get('unk4')
                unk4_b = f.get('unk4_bytes') or b''
                unk5 = f.get('unk5')
                unk5_b = f.get('unk5_bytes') or b''
                unk6 = f.get('unk6')
                unk6_b = f.get('unk6_bytes') or b''
                unk7 = f.get('unk7')
                unk7_b = f.get('unk7_bytes') or b''
                unk8 = f.get('unk8')
                unk8_b = f.get('unk8_bytes') or b''
                unk9 = f.get('unk9')
                unk9_b = f.get('unk9_bytes') or b''

                # Render fields with hex + converted forms
                self.detail_text.insert(tk.END, f"- mhbd: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header size: {bytes_spaced_hex(hs_b)} ({hs}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total file size: {bytes_spaced_hex(tfs_b)} ({tfs}) bytes\n")
                self.detail_text.insert(tk.END, f"- unk1: {bytes_spaced_hex(unk1_b)} ({unk1})\n")
                self.detail_text.insert(tk.END, f"- Database version: {bytes_spaced_hex(dv_b)} ({dv})\n")
                self.detail_text.insert(tk.END, f"- Number of mhsd sets: {bytes_spaced_hex(nsets_b)} ({nsets})\n")

                self.detail_text.insert(tk.END, f"- Database UUID: {bytes_spaced_hex(db_uuid)}\n")
                if unk2 is not None:
                    self.detail_text.insert(tk.END, f"- unk2: {bytes_spaced_hex(unk2_b)} ({unk2})\n")
                self.detail_text.insert(tk.END, f"- Stable identifier: {bytes_spaced_hex(stable)}  ('{ascii_repr(stable)}')\n")
                self.detail_text.insert(tk.END, f"- Language: {bytes_spaced_hex(lang_b)}  ('{ascii_repr(lang_b)}')\n")
                self.detail_text.insert(tk.END, f"- Persistent Library ID: {bytes_spaced_hex(plid)}  ('{ascii_repr(plid)}')\n")

                if unk3 is not None:
                    self.detail_text.insert(tk.END, f"- unk3: {bytes_spaced_hex(unk3_b)} ({unk3})\n")
                if unk4 is not None:
                    self.detail_text.insert(tk.END, f"- unk4: {bytes_spaced_hex(unk4_b)} ({unk4})\n")
                if unk5 is not None:
                    self.detail_text.insert(tk.END, f"- unk5: {bytes_spaced_hex(unk5_b)} ({unk5})\n")
                if unk6 is not None:
                    self.detail_text.insert(tk.END, f"- unk6: {bytes_spaced_hex(unk6_b)} ({unk6})\n")
                if unk7 is not None:
                    self.detail_text.insert(tk.END, f"- unk7: {bytes_spaced_hex(unk7_b)} ({unk7})\n")
                if unk8 is not None:
                    self.detail_text.insert(tk.END, f"- unk8: {bytes_spaced_hex(unk8_b)} ({unk8})\n")
                if unk9 is not None:
                    self.detail_text.insert(tk.END, f"- unk9: {bytes_spaced_hex(unk9_b)} ({unk9})\n")
                self.detail_text.insert(tk.END, "\n")

                # Quick validations shown inline
                issues = []
                if self.file_bytes is not None and f.get('total_file_size') != len(self.file_bytes):
                    issues.append(f"total_file_size({f.get('total_file_size')}) != actual({len(self.file_bytes)})")
                if issues:
                    self.detail_text.insert(tk.END, "Potential header anomalies:\n- " + "\n- ".join(issues) + "\n\n")

            elif ch.fields and ch.tag == b'mhsd':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhsd header fields (LE):\n")
                tag_b = f.get('tag_bytes') or b''
                hl = f.get('header_length')
                hl_b = f.get('header_length_bytes') or b''
                tl = f.get('total_length')
                tl_b = f.get('total_length_bytes') or b''
                tv = f.get('type')
                tv_b = f.get('type_bytes') or b''

                # Type descriptions
                type_desc = {
                    1: 'Track list (mhlt)',
                    2: 'Playlist list (mhlp)',
                    3: 'Podcast list (mhlp)',
                    4: 'Album list (mhla)',
                    5: 'New Playlist List with Smart Playlists',
                }.get(tv, 'Unknown')

                self.detail_text.insert(tk.END, f"- mhsd: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({hl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total length: {bytes_spaced_hex(tl_b)} ({tl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Type: {bytes_spaced_hex(tv_b)} ({tv})  [{type_desc}]\n\n")

            elif ch.fields and ch.tag == b'mhlt':
                f = ch.fields
                tag_b = f.get('tag_bytes') or b''
                hl = f.get('header_length')
                hl_b = f.get('header_length_bytes') or b''
                ns = f.get('number_of_songs')
                ns_b = f.get('number_of_songs_bytes') or b''
                self.detail_text.insert(tk.END, "mhlt header fields (LE):\n")
                self.detail_text.insert(tk.END, f"- mhlt: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({hl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Number of Songs: {bytes_spaced_hex(ns_b)} ({ns})\n\n")

            elif ch.fields and ch.tag == b'mhlp':
                f = ch.fields
                tag_b = f.get('tag_bytes') or b''
                hl = f.get('header_length')
                hl_b = f.get('header_length_bytes') or b''
                np = f.get('number_of_playlists')
                np_b = f.get('number_of_playlists_bytes') or b''
                self.detail_text.insert(tk.END, "mhlp header fields (LE):\n")
                self.detail_text.insert(tk.END, f"- mhlp: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({hl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Number of Playlists: {bytes_spaced_hex(np_b)} ({np})\n\n")

            elif ch.fields and ch.tag == b'mhyp':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhyp header fields (LE):\n")
                tag_b = f.get('tag_bytes') or b''
                hl_b = f.get('header_length_bytes') or b''
                tl_b = f.get('total_length_bytes') or b''
                self.detail_text.insert(tk.END, f"- mhyp: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({f.get('header_length')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total length: {bytes_spaced_hex(tl_b)} ({f.get('total_length')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Data Object Child Count: {bytes_spaced_hex(f.get('data_object_child_count_bytes') or b'')} ({f.get('data_object_child_count')})\n")
                self.detail_text.insert(tk.END, f"- Playlist Item Count: {bytes_spaced_hex(f.get('playlist_item_count_bytes') or b'')} ({f.get('playlist_item_count')})\n")
                is_m = f.get('is_master_playlist')
                is_m_b = f.get('is_master_playlist_bytes') or b''
                is_m_desc = 'Master (Library) playlist' if is_m == 1 else ('Not master' if is_m is not None else '')
                self.detail_text.insert(tk.END, f"- Is Master: {bytes_spaced_hex(is_m_b)} ({is_m}) {is_m_desc and '[' + is_m_desc + ']'}\n")
                self.detail_text.insert(tk.END, f"- Flags3: {bytes_spaced_hex(f.get('flags3_bytes') or b'')}\n")
                ts = f.get('timestamp'); ts_iso = hfs_to_iso(ts)
                self.detail_text.insert(tk.END, f"- Timestamp: {bytes_spaced_hex(f.get('timestamp_bytes') or b'')} ({ts})" + (f" => {ts_iso}" if ts_iso else '') + "\n")
                ppid = f.get('persistent_playlist_id_bytes') or b''
                self.detail_text.insert(tk.END, f"- Persistent Playlist ID: {bytes_spaced_hex(ppid)} ('{ascii_repr(ppid)}')\n")
                self.detail_text.insert(tk.END, f"- unk3: {bytes_spaced_hex(f.get('unk3_bytes') or b'')} ({f.get('unk3')})\n")
                self.detail_text.insert(tk.END, f"- String MHOD count: {bytes_spaced_hex(f.get('string_mhod_count_bytes') or b'')} ({f.get('string_mhod_count')})\n")
                self.detail_text.insert(tk.END, f"- Podcast Flag: {bytes_spaced_hex(f.get('podcast_flag_bytes') or b'')} ({f.get('podcast_flag')})\n")
                so = f.get('list_sort_order')
                so_map = {
                    1: 'playlist order', 2: 'unknown', 3: 'songtitle', 4: 'album', 5: 'artist', 6: 'bitrate', 7: 'genre', 8: 'kind', 9: 'date modified',
                    10: 'track number', 11: 'size', 12: 'time', 13: 'year', 14: 'sample rate', 15: 'comment', 16: 'date added', 17: 'equalizer',
                    18: 'composer', 19: 'unknown', 20: 'play count', 21: 'last played', 22: 'disc number', 23: 'my rating', 24: 'release date',
                    25: 'BPM', 26: 'grouping', 27: 'category', 28: 'description', 29: 'show', 30: 'season', 31: 'episode number'
                }
                so_desc = so_map.get(so, 'Unknown')
                self.detail_text.insert(tk.END, f"- List Sort Order: {bytes_spaced_hex(f.get('list_sort_order_bytes') or b'')} ({so}) [{so_desc}]\n\n")

            elif ch.fields and ch.tag == b'mhip':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhip header fields (LE):\n")
                tb = f.get('tag_bytes') or b''
                self.detail_text.insert(tk.END, f"- mhip: {bytes_spaced_hex(tb)} ('{ascii_repr(tb)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(f.get('header_length_bytes') or b'')} ({f.get('header_length')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total length: {bytes_spaced_hex(f.get('total_length_bytes') or b'')} ({f.get('total_length')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Data Object Child Count: {bytes_spaced_hex(f.get('data_object_child_count_bytes') or b'')} ({f.get('data_object_child_count')})\n")
                pgf = f.get('podcast_grouping_flag')
                pgf_desc = 'Normal file' if pgf == 0x0000 else ('Podcast Group' if pgf == 0x0100 else 'Other')
                self.detail_text.insert(tk.END, f"- Podcast Grouping Flag: {bytes_spaced_hex(f.get('podcast_grouping_flag_bytes') or b'')} ({pgf}) [{pgf_desc}]\n")
                self.detail_text.insert(tk.END, f"- unk4: {bytes_spaced_hex(f.get('unk4_bytes') or b'')} ({f.get('unk4')})\n")
                self.detail_text.insert(tk.END, f"- unk5: {bytes_spaced_hex(f.get('unk5_bytes') or b'')} ({f.get('unk5')})\n")
                self.detail_text.insert(tk.END, f"- Group ID: {bytes_spaced_hex(f.get('group_id_bytes') or b'')} ({f.get('group_id')})\n")
                self.detail_text.insert(tk.END, f"- Track ID: {bytes_spaced_hex(f.get('track_id_bytes') or b'')} ({f.get('track_id')})\n")
                ts = f.get('timestamp'); ts_iso = hfs_to_iso(ts)
                self.detail_text.insert(tk.END, f"- Timestamp: {bytes_spaced_hex(f.get('timestamp_bytes') or b'')} ({ts})" + (f" => {ts_iso}" if ts_iso else '') + "\n")
                self.detail_text.insert(tk.END, f"- Podcast Grouping Reference: {bytes_spaced_hex(f.get('podcast_grouping_reference_bytes') or b'')} ({f.get('podcast_grouping_reference')})\n\n")

            elif ch.fields and ch.tag == b'mhit':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhit header fields (LE):\n")
                def B(name):
                    return f.get(name) or b''
                def V(name):
                    return f.get(name)
                # Header
                self.detail_text.insert(tk.END, f"- mhit: {bytes_spaced_hex(B('tag_bytes'))} ('{ascii_repr(B('tag_bytes'))}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(B('header_length_bytes'))} ({V('header_length')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total length: {bytes_spaced_hex(B('total_length_bytes'))} ({V('total_length')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Number of Strings: {bytes_spaced_hex(B('number_of_strings_bytes'))} ({V('number_of_strings')})\n")
                # Core identifiers
                self.detail_text.insert(tk.END, f"- Unique ID: {bytes_spaced_hex(B('unique_id_bytes'))} ({V('unique_id')})\n")
                vis = V('visible')
                vis_desc = 'visible' if vis == 1 else ('hidden' if vis is not None else '')
                self.detail_text.insert(tk.END, f"- Visible: {bytes_spaced_hex(B('visible_bytes'))} ({vis}) {vis_desc and '[' + vis_desc + ']'}\n")
                ft_b = B('filetype_bytes')
                ft_label = decode_filetype_ascii(ft_b)
                ft_suffix = f" [{ft_label}]" if ft_label else ''
                self.detail_text.insert(tk.END, f"- Filetype: {bytes_spaced_hex(ft_b)} ('{ascii_repr(ft_b)}'){ft_suffix}\n")
                # Flags & meta
                self.detail_text.insert(tk.END, f"- Type1: {bytes_spaced_hex(B('type1_bytes'))} ({V('type1')})\n")
                self.detail_text.insert(tk.END, f"- Type2: {bytes_spaced_hex(B('type2_bytes'))} ({V('type2')})\n")
                self.detail_text.insert(tk.END, f"- Compilation Flag: {bytes_spaced_hex(B('compilation_flag_bytes'))} ({V('compilation_flag')})\n")
                rating = V('rating')
                stars = (rating // 20) if isinstance(rating, int) else None
                star_suffix = f" [~{stars}/5 stars]" if stars is not None else ''
                self.detail_text.insert(tk.END, f"- Rating: {bytes_spaced_hex(B('rating_bytes'))} ({rating}){star_suffix}\n")
                # Timing + sizes
                lm = V('last_modified_time'); lm_iso = hfs_to_iso(lm)
                self.detail_text.insert(tk.END, f"- Last Modified Time: {bytes_spaced_hex(B('last_modified_time_bytes'))} ({lm})" + (f" => {lm_iso}" if lm_iso else '') + "\n")
                self.detail_text.insert(tk.END, f"- Size: {bytes_spaced_hex(B('size_bytes'))} ({V('size')}) bytes\n")
                self.detail_text.insert(tk.END, f"- Length (ms): {bytes_spaced_hex(B('length_ms_bytes'))} ({V('length_ms')})\n")
                # Track indexing
                self.detail_text.insert(tk.END, f"- Track Number: {bytes_spaced_hex(B('track_number_bytes'))} ({V('track_number')})\n")
                self.detail_text.insert(tk.END, f"- Total Tracks: {bytes_spaced_hex(B('total_tracks_bytes'))} ({V('total_tracks')})\n")
                self.detail_text.insert(tk.END, f"- Year: {bytes_spaced_hex(B('year_bytes'))} ({V('year')})\n")
                # Audio params
                self.detail_text.insert(tk.END, f"- Bitrate: {bytes_spaced_hex(B('bitrate_bytes'))} ({V('bitrate')})\n")
                sr_q16 = V('sample_rate_q16'); sr_hz = q16_to_int(sr_q16)
                sr_note = f" -> {sr_hz} Hz" if sr_hz is not None else ''
                self.detail_text.insert(tk.END, f"- Sample Rate (Q16): {bytes_spaced_hex(B('sample_rate_q16_bytes'))} ({sr_q16}){sr_note}\n")
                # User adjustments and ranges
                vol_b = B('volume_bytes')
                vol_val = struct.unpack('<i', vol_b + b'\x00'*(4-len(vol_b)))[0] if len(vol_b) == 4 else V('volume')
                self.detail_text.insert(tk.END, f"- Volume: {bytes_spaced_hex(vol_b)} ({vol_val})\n")
                self.detail_text.insert(tk.END, f"- Start Time: {bytes_spaced_hex(B('start_time_bytes'))} ({V('start_time')})\n")
                self.detail_text.insert(tk.END, f"- Stop Time: {bytes_spaced_hex(B('stop_time_bytes'))} ({V('stop_time')})\n")
                self.detail_text.insert(tk.END, f"- Soundcheck: {bytes_spaced_hex(B('soundcheck_bytes'))} ({V('soundcheck')})\n")
                # Counts & dates
                self.detail_text.insert(tk.END, f"- Play Count: {bytes_spaced_hex(B('play_count_bytes'))} ({V('play_count')})\n")
                self.detail_text.insert(tk.END, f"- Play Count 2: {bytes_spaced_hex(B('play_count2_bytes'))} ({V('play_count2')})\n")
                lpt = V('last_played_time'); lpt_iso = hfs_to_iso(lpt)
                self.detail_text.insert(tk.END, f"- Last Played Time: {bytes_spaced_hex(B('last_played_time_bytes'))} ({lpt})" + (f" => {lpt_iso}" if lpt_iso else '') + "\n")
                self.detail_text.insert(tk.END, f"- Disc Number: {bytes_spaced_hex(B('disc_number_bytes'))} ({V('disc_number')})\n")
                self.detail_text.insert(tk.END, f"- Total Discs: {bytes_spaced_hex(B('total_discs_bytes'))} ({V('total_discs')})\n")
                self.detail_text.insert(tk.END, f"- UserID: {bytes_spaced_hex(B('user_id_bytes'))} ({V('user_id')})\n")
                da = V('date_added'); da_iso = hfs_to_iso(da)
                self.detail_text.insert(tk.END, f"- Date Added: {bytes_spaced_hex(B('date_added_bytes'))} ({da})" + (f" => {da_iso}" if da_iso else '') + "\n")
                self.detail_text.insert(tk.END, f"- Bookmark Time: {bytes_spaced_hex(B('bookmark_time_bytes'))} ({V('bookmark_time')})\n")
                dbid_b = B('dbid_bytes')
                self.detail_text.insert(tk.END, f"- dbid: {bytes_spaced_hex(dbid_b)} ('{ascii_repr(dbid_b)}')\n")
                # Flags/shorts
                self.detail_text.insert(tk.END, f"- Checked: {bytes_spaced_hex(B('checked_bytes'))} ({V('checked')})\n")
                self.detail_text.insert(tk.END, f"- Application Rating: {bytes_spaced_hex(B('app_rating_bytes'))} ({V('app_rating')})\n")
                self.detail_text.insert(tk.END, f"- BPM: {bytes_spaced_hex(B('bpm_bytes'))} ({V('bpm')})\n")
                self.detail_text.insert(tk.END, f"- Artwork Count: {bytes_spaced_hex(B('artwork_count_bytes'))} ({V('artwork_count')})\n")
                self.detail_text.insert(tk.END, f"- unk9: {bytes_spaced_hex(B('unk9_bytes'))} ({V('unk9')})\n")
                # Artwork and more
                self.detail_text.insert(tk.END, f"- Artwork Size: {bytes_spaced_hex(B('artwork_size_bytes'))} ({V('artwork_size')})\n")
                self.detail_text.insert(tk.END, f"- unk11: {bytes_spaced_hex(B('unk11_bytes'))} ({V('unk11')})\n")
                sr2_b = B('sample_rate_f_bytes')
                sr2 = float_from_le_bytes(sr2_b)
                sr2_note = f" -> {sr2:.2f} Hz" if sr2 is not None else ''
                self.detail_text.insert(tk.END, f"- Sample Rate 2 (float raw): {bytes_spaced_hex(sr2_b)} ({V('sample_rate_f_raw')}){sr2_note}\n")
                dr = V('date_released'); dr_iso = hfs_to_iso(dr)
                self.detail_text.insert(tk.END, f"- Date Released: {bytes_spaced_hex(B('date_released_bytes'))} ({dr})" + (f" => {dr_iso}" if dr_iso else '') + "\n")
                self.detail_text.insert(tk.END, f"- unk14/1: {bytes_spaced_hex(B('unk14_1_bytes'))} ({V('unk14_1')})\n")
                self.detail_text.insert(tk.END, f"- unk14/2: {bytes_spaced_hex(B('unk14_2_bytes'))} ({V('unk14_2')})\n")
                self.detail_text.insert(tk.END, f"- unk15: {bytes_spaced_hex(B('unk15_bytes'))} ({V('unk15')})\n")
                self.detail_text.insert(tk.END, f"- unk16: {bytes_spaced_hex(B('unk16_bytes'))} ({V('unk16')})\n")
                self.detail_text.insert(tk.END, f"- Skip Count: {bytes_spaced_hex(B('skip_count_bytes'))} ({V('skip_count')})\n")
                ls = V('last_skipped'); ls_iso = hfs_to_iso(ls)
                self.detail_text.insert(tk.END, f"- Last Skipped: {bytes_spaced_hex(B('last_skipped_bytes'))} ({ls})" + (f" => {ls_iso}" if ls_iso else '') + "\n")
                self.detail_text.insert(tk.END, f"- has_artwork: {bytes_spaced_hex(B('has_artwork_bytes'))} ({V('has_artwork')})\n")
                self.detail_text.insert(tk.END, f"- skip_when_shuffling: {bytes_spaced_hex(B('skip_when_shuffling_bytes'))} ({V('skip_when_shuffling')})\n")
                self.detail_text.insert(tk.END, f"- remember_playback_position: {bytes_spaced_hex(B('remember_playback_position_bytes'))} ({V('remember_playback_position')})\n")
                dbid2_b = B('dbid2_bytes')
                self.detail_text.insert(tk.END, f"- dbid2: {bytes_spaced_hex(dbid2_b)} ('{ascii_repr(dbid2_b)}')\n")
                self.detail_text.insert(tk.END, f"- lyrics_flag: {bytes_spaced_hex(B('lyrics_flag_bytes'))} ({V('lyrics_flag')})\n")
                self.detail_text.insert(tk.END, f"- movie_file_flag: {bytes_spaced_hex(B('movie_file_flag_bytes'))} ({V('movie_file_flag')})\n")
                self.detail_text.insert(tk.END, f"- played_mark: {bytes_spaced_hex(B('played_mark_bytes'))} ({V('played_mark')})\n")
                self.detail_text.insert(tk.END, f"- unk17: {bytes_spaced_hex(B('unk17_bytes'))} ({V('unk17')})\n")
                self.detail_text.insert(tk.END, f"- unk21: {bytes_spaced_hex(B('unk21_bytes'))} ({V('unk21')})\n")
                self.detail_text.insert(tk.END, f"- pregap: {bytes_spaced_hex(B('pregap_bytes'))} ({V('pregap')})\n")
                self.detail_text.insert(tk.END, f"- sample_count: {bytes_spaced_hex(B('sample_count_bytes'))} ({V('sample_count')})\n")
                self.detail_text.insert(tk.END, f"- unk25: {bytes_spaced_hex(B('unk25_bytes'))} ({V('unk25')})\n")
                self.detail_text.insert(tk.END, f"- postgap: {bytes_spaced_hex(B('postgap_bytes'))} ({V('postgap')})\n")
                self.detail_text.insert(tk.END, f"- unk27: {bytes_spaced_hex(B('unk27_bytes'))} ({V('unk27')})\n")
                mt = V('media_type')
                media_map = {
                    0x00: 'Audio/Video',
                    0x01: 'Audio',
                    0x02: 'Video',
                    0x04: 'Podcast',
                    0x06: 'Video Podcast',
                    0x08: 'Audiobook',
                    0x20: 'Music Video',
                    0x40: 'TV Show (TV only)',
                    0x60: 'TV Show (music lists too)',
                }
                mt_desc = media_map.get(mt, 'Unknown')
                self.detail_text.insert(tk.END, f"- Media Type: {bytes_spaced_hex(B('media_type_bytes'))} ({mt}) [{mt_desc}]\n")
                self.detail_text.insert(tk.END, f"- Season Number: {bytes_spaced_hex(B('season_number_bytes'))} ({V('season_number')})\n")
                self.detail_text.insert(tk.END, f"- Episode Number: {bytes_spaced_hex(B('episode_number_bytes'))} ({V('episode_number')})\n")
                self.detail_text.insert(tk.END, f"- unk31: {bytes_spaced_hex(B('unk31_bytes'))} ({V('unk31')})\n")
                self.detail_text.insert(tk.END, f"- unk32: {bytes_spaced_hex(B('unk32_bytes'))} ({V('unk32')})\n")
                self.detail_text.insert(tk.END, f"- unk33: {bytes_spaced_hex(B('unk33_bytes'))} ({V('unk33')})\n")
                self.detail_text.insert(tk.END, f"- unk34: {bytes_spaced_hex(B('unk34_bytes'))} ({V('unk34')})\n")
                self.detail_text.insert(tk.END, f"- unk35: {bytes_spaced_hex(B('unk35_bytes'))} ({V('unk35')})\n")
                self.detail_text.insert(tk.END, f"- unk36: {bytes_spaced_hex(B('unk36_bytes'))} ({V('unk36')})\n")
                self.detail_text.insert(tk.END, f"- unk37: {bytes_spaced_hex(B('unk37_bytes'))} ({V('unk37')})\n")
                self.detail_text.insert(tk.END, f"- gaplessData: {bytes_spaced_hex(B('gaplessData_bytes'))} ({V('gaplessData')})\n")
                self.detail_text.insert(tk.END, f"- unk38: {bytes_spaced_hex(B('unk38_bytes'))} ({V('unk38')})\n")
                self.detail_text.insert(tk.END, f"- gaplessTrackFlag: {bytes_spaced_hex(B('gaplessTrackFlag_bytes'))} ({V('gaplessTrackFlag')})\n")
                self.detail_text.insert(tk.END, f"- gaplessAlbumFlag: {bytes_spaced_hex(B('gaplessAlbumFlag_bytes'))} ({V('gaplessAlbumFlag')})\n")
                self.detail_text.insert(tk.END, f"- unk39 (20 bytes): {bytes_spaced_hex(B('unk39_bytes'))}\n\n")

            elif ch.fields and ch.tag == b'mhla':
                f = ch.fields
                tag_b = f.get('tag_bytes') or b''
                hl = f.get('header_length')
                hl_b = f.get('header_length_bytes') or b''
                nai = f.get('number_of_album_items')
                nai_b = f.get('number_of_album_items_bytes') or b''
                self.detail_text.insert(tk.END, "mhla header fields (LE):\n")
                self.detail_text.insert(tk.END, f"- mhla: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({hl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Number of Album Items: {bytes_spaced_hex(nai_b)} ({nai}) albums\n\n")

            elif ch.fields and ch.tag == b'mhia':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhia header fields (LE):\n")
                tag_b = f.get('tag_bytes') or b''
                hl = f.get('header_length')
                hl_b = f.get('header_length_bytes') or b''
                tl = f.get('total_length')
                tl_b = f.get('total_length_bytes') or b''
                nstr = f.get('number_of_strings')
                nstr_b = f.get('number_of_strings_bytes') or b''
                arid = f.get('album_reference_id')
                arid_b = f.get('album_reference_id_bytes') or b''
                unk10_b = f.get('unk10_bytes') or b''
                unk11 = f.get('unk11')
                unk11_b = f.get('unk11_bytes') or b''
                unk12_b = f.get('unk12_bytes') or b''

                # Only reverse display for 8-byte opaque fields
                if self.reverse_bytes:
                    unk10_b = unk10_b[::-1]
                    unk12_b = unk12_b[::-1]

                self.detail_text.insert(tk.END, f"- mhia: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({hl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total length: {bytes_spaced_hex(tl_b)} ({tl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Number of strings: {bytes_spaced_hex(nstr_b)} ({nstr})\n")
                self.detail_text.insert(tk.END, f"- Album reference ID: {bytes_spaced_hex(arid_b)} ({arid})\n")
                self.detail_text.insert(tk.END, f"- Unk10: {bytes_spaced_hex(unk10_b)}\n")
                self.detail_text.insert(tk.END, f"- Unk11: {bytes_spaced_hex(unk11_b)} ({unk11})\n")
                self.detail_text.insert(tk.END, f"- Unk12: {bytes_spaced_hex(unk12_b)}\n\n")

            elif ch.fields and ch.tag == b'mhod':
                f = ch.fields
                self.detail_text.insert(tk.END, "mhod header fields (LE):\n")
                tag_b = f.get('tag_bytes') or b''
                hl = f.get('header_length')
                hl_b = f.get('header_length_bytes') or b''
                tl = f.get('total_length')
                tl_b = f.get('total_length_bytes') or b''
                tv = f.get('type')
                tv_b = f.get('type_bytes') or b''
                pos = f.get('position')
                pos_b = f.get('position_bytes') or b''
                slen = f.get('string_length')
                slen_b = f.get('string_length_bytes') or b''
                u13 = f.get('unk13')
                u13_b = f.get('unk13_bytes') or b''
                s_b = f.get('string_bytes') or b''

                type_desc_map = {
                    1: 'Title', 2: 'Location', 3: 'Album', 4: 'Artist', 5: 'Genre', 6: 'Filetype', 7: 'EQ Setting', 8: 'Comment', 9: 'Category',
                    12: 'Composer', 13: 'Grouping', 14: 'Description text', 15: 'Podcast Enclosure URL', 16: 'Podcast RSS URL', 17: 'Chapter data',
                    18: 'Subtitle', 19: 'Show (TV)', 20: 'Episode # (TV)', 21: 'TV Network', 22: 'Album Artist', 23: 'Artist (sort)', 24: 'Keywords list',
                    25: 'Locale (TV show?)', 27: 'Title (sort)', 28: 'Album (sort)', 29: 'Album-Artist (sort)', 30: 'Composer (sort)', 31: 'TV-Show (sort)',
                    32: 'Unknown (binary)', 50: 'Smart Playlist Data', 51: 'Smart Playlist Rules', 52: 'Library Playlist Index', 53: 'Letter Jump Table',
                    100: 'Playlist Order Entry', 200: 'Album (Album List)', 201: 'Artist (Album List)', 202: 'Artist (sort, Album List)',
                    203: 'Podcast URL (Album List)', 204: 'TV Show (Album List)'
                }
                tv_desc = type_desc_map.get(tv, 'Unknown')

                # Decode string preview based on type
                s_txt = ''
                STRING_UTF8 = {15, 16}
                # Treat these types as opaque / ignored for now.
                BINARY_TYPES = {17, 18, 19, 20, 21, 25, 32, 50, 51, 52, 53, 100}
                if isinstance(tv, int):
                    if tv in STRING_UTF8:
                        try:
                            s_txt = s_b.decode('utf-8', errors='replace')
                        except Exception:
                            s_txt = ''
                    elif tv in BINARY_TYPES:
                        s_txt = ''  # opaque
                    else:
                        if len(s_b) >= 2:
                            try:
                                s_txt = s_b.decode('utf-16le', errors='replace')
                            except Exception:
                                s_txt = ''

                self.detail_text.insert(tk.END, f"- mhod: {bytes_spaced_hex(tag_b)} ('{ascii_repr(tag_b)}')\n")
                self.detail_text.insert(tk.END, f"- Header length: {bytes_spaced_hex(hl_b)} ({hl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Total length: {bytes_spaced_hex(tl_b)} ({tl}) bytes\n")
                self.detail_text.insert(tk.END, f"- Type: {bytes_spaced_hex(tv_b)} ({tv}) [{tv_desc}]\n")
                if tv == 100:
                    variant = f.get('variant') or 'order_entry'
                    if variant == 'column_def':
                        # Playlist column definition header
                        self.detail_text.insert(tk.END, "- Playlist Column Definition (iTunes-only metadata):\n")
                        self.detail_text.insert(tk.END, f"  unk1: {bytes_spaced_hex(f.get('unk1_bytes') or b'')} ({f.get('unk1')})\n")
                        self.detail_text.insert(tk.END, f"  unk2: {bytes_spaced_hex(f.get('unk2_bytes') or b'')} ({f.get('unk2')})\n")
                        self.detail_text.insert(tk.END, f"  unk3: {bytes_spaced_hex(f.get('unk3_bytes') or b'')} ({f.get('unk3')})\n")
                        self.detail_text.insert(tk.END, f"  unk4: {bytes_spaced_hex(f.get('unk4_bytes') or b'')} ({f.get('unk4')})\n")
                        self.detail_text.insert(tk.END, f"  unk8: {bytes_spaced_hex(f.get('unk8_bytes') or b'')} ({f.get('unk8')})\n")
                        self.detail_text.insert(tk.END, f"  unk9: {bytes_spaced_hex(f.get('unk9_bytes') or b'')} ({f.get('unk9')})\n")
                        self.detail_text.insert(tk.END, f"  unk10: {bytes_spaced_hex(f.get('unk10_bytes') or b'')} ({f.get('unk10')})\n")

                        st = f.get('sort_type')
                        st_b = f.get('sort_type_bytes') or b''
                        self.detail_text.insert(tk.END, f"  Sort Type: {bytes_spaced_hex(st_b)} ({st})\n")
                        nc = f.get('number_of_columns')
                        nc_b = f.get('number_of_columns_bytes') or b''
                        self.detail_text.insert(tk.END, f"  Number of Columns: {bytes_spaced_hex(nc_b)} ({nc})\n")
                        self.detail_text.insert(tk.END, f"  unknown1: {bytes_spaced_hex(f.get('unknown1_bytes') or b'')} ({f.get('unknown1')})\n")
                        self.detail_text.insert(tk.END, f"  unknown2: {bytes_spaced_hex(f.get('unknown2_bytes') or b'')} ({f.get('unknown2')})\n\n")

                        # Column definitions
                        col_id_map = {
                            0x01: 'Position',
                            0x02: 'Name',
                            0x03: 'Album',
                            0x04: 'Artist',
                            0x05: 'Bit Rate',
                            0x06: 'Sample Rate',
                            0x07: 'Year',
                            0x08: 'Genre',
                            0x09: 'Kind',
                            0x0A: 'Date Modified',
                            0x0B: 'Track Number',
                            0x0C: 'Size',
                            0x0D: 'Time',
                            0x0E: 'Comment',
                            0x10: 'Date Added',
                            0x11: 'Equalizer',
                            0x12: 'Composer',
                            0x14: 'Play Count',
                            0x15: 'Last Played',
                            0x16: 'Disc Number',
                            0x17: 'My Rating',
                            0x19: 'Date Released (Podcasts)',
                            0x1A: 'BPM',
                            0x1C: 'Grouping',
                            0x1E: 'Category',
                            0x1F: 'Description',
                            0x21: 'Show',
                            0x22: 'Season',
                            0x23: 'Episode Number',
                        }
                        cols = f.get('columns') or []
                        if cols:
                            self.detail_text.insert(tk.END, "  Columns (left to right in iTunes):\n")
                            for idx, col in enumerate(cols, 1):
                                cid = col.get('column_id')
                                cid_b = col.get('column_id_bytes') or b''
                                width = col.get('width')
                                width_b = col.get('width_bytes') or b''
                                sort_dir = col.get('sort_direction')
                                sort_dir_b = col.get('sort_direction_bytes') or b''
                                cid_name = col_id_map.get(cid, 'Unknown')
                                sort_note = 'reversed' if sort_dir == 1 else 'normal'
                                self.detail_text.insert(
                                    tk.END,
                                    f"    Col #{idx}: ID {bytes_spaced_hex(cid_b)} ({cid}) [{cid_name}], "
                                    f"Width {bytes_spaced_hex(width_b)} ({width}) px, "
                                    f"SortDir {bytes_spaced_hex(sort_dir_b)} ({sort_dir}) [{sort_note}]\n"
                                )
                            self.detail_text.insert(tk.END, "\n")
                    else:
                        # Playlist Order Entry specifics
                        self.detail_text.insert(tk.END, f"- unk1: {bytes_spaced_hex(f.get('unk1_bytes') or b'')} ({f.get('unk1')})\n")
                        self.detail_text.insert(tk.END, f"- unk2: {bytes_spaced_hex(f.get('unk2_bytes') or b'')} ({f.get('unk2')})\n")
                        self.detail_text.insert(tk.END, f"- Position: {bytes_spaced_hex(pos_b)} ({pos})  [playlist order info]\n")
                        self.detail_text.insert(tk.END, f"- Padding (16 bytes): {bytes_spaced_hex(f.get('padding16_bytes') or b'')}\n\n")
                elif tv == 50:
                    # Smart Playlist Data (no string payload; a packed flag structure)
                    lu = f.get('live_update')
                    cr = f.get('check_rules')
                    cl = f.get('check_limits')
                    lt = f.get('limit_type')
                    ls = f.get('limit_sort')
                    lv = f.get('limit_value')
                    mco = f.get('match_checked_only')
                    rls = f.get('reverse_limit_sort')

                    # Human-readable descriptions
                    limit_type_map = {
                        1: 'Minutes',
                        2: 'Megabytes',
                        3: 'Songs',
                        4: 'Hours',
                        5: 'Gigabytes',
                    }
                    limit_sort_map = {
                        0x02: 'Random',
                        0x03: 'Song Name (alphabetical)',
                        0x04: 'Album (alphabetical)',
                        0x05: 'Artist (alphabetical)',
                        0x07: 'Genre (alphabetical)',
                        0x10: 'Most Recently Added',
                        0x14: 'Most Often Played',
                        0x15: 'Most Recently Played',
                        0x17: 'Highest Rating',
                    }

                    self.detail_text.insert(tk.END, f"- unk1: {bytes_spaced_hex(f.get('unk1_bytes') or b'')} ({f.get('unk1')})\n")
                    self.detail_text.insert(tk.END, f"- unk2: {bytes_spaced_hex(f.get('unk2_bytes') or b'')} ({f.get('unk2')})\n")
                    self.detail_text.insert(tk.END, f"- Live Update: {bytes_spaced_hex(f.get('live_update_bytes') or b'')} ({lu}) [{'on' if lu == 1 else 'off' if lu is not None else ''}]\n")
                    self.detail_text.insert(tk.END, f"- Check Rules: {bytes_spaced_hex(f.get('check_rules_bytes') or b'')} ({cr}) [{'on' if cr == 1 else 'off' if cr is not None else ''}]\n")
                    self.detail_text.insert(tk.END, f"- Check Limits: {bytes_spaced_hex(f.get('check_limits_bytes') or b'')} ({cl}) [{'on' if cl == 1 else 'off' if cl is not None else ''}]\n")
                    lt_desc = limit_type_map.get(lt, 'Unknown')
                    self.detail_text.insert(tk.END, f"- Limit Type: {bytes_spaced_hex(f.get('limit_type_bytes') or b'')} ({lt}) [{lt_desc}]\n")
                    ls_desc = limit_sort_map.get(ls, 'Unknown')
                    self.detail_text.insert(tk.END, f"- Limit Sort: {bytes_spaced_hex(f.get('limit_sort_bytes') or b'')} ({ls}) [{ls_desc}]\n")
                    self.detail_text.insert(tk.END, f"- Reserved (29..31): {bytes_spaced_hex(f.get('zeros_29_31_bytes') or b'')}\n")
                    self.detail_text.insert(tk.END, f"- Limit Value: {bytes_spaced_hex(f.get('limit_value_bytes') or b'')} ({lv})\n")
                    self.detail_text.insert(tk.END, f"- Match Checked Only: {bytes_spaced_hex(f.get('match_checked_only_bytes') or b'')} ({mco}) [{'on' if mco == 1 else 'off' if mco is not None else ''}]\n")
                    self.detail_text.insert(tk.END, f"- Reverse Limit Sort: {bytes_spaced_hex(f.get('reverse_limit_sort_bytes') or b'')} ({rls}) [{'on' if rls == 1 else 'off' if rls is not None else ''}]\n\n")
                elif tv == 51:
                    # Smart Playlist Rules (SLst) – show header and per-rule summaries.
                    smart_id = f.get('smart_list_id_bytes') or b''
                    unk1 = f.get('unk1')
                    unk2 = f.get('unk2')
                    self.detail_text.insert(tk.END, f"- unk1: {bytes_spaced_hex(f.get('unk1_bytes') or b'')} ({unk1})\n")
                    self.detail_text.insert(tk.END, f"- unk2: {bytes_spaced_hex(f.get('unk2_bytes') or b'')} ({unk2})\n")
                    self.detail_text.insert(tk.END, f"- Smart List ID: {bytes_spaced_hex(smart_id)} ('{ascii_repr(smart_id)}')\n")

                    nr = f.get('number_of_rules')
                    nr_b = f.get('number_of_rules_bytes') or b''
                    rop = f.get('rules_operator')
                    rop_b = f.get('rules_operator_bytes') or b''
                    rop_desc = {0: 'Match All (AND)', 1: 'Match Any (OR)'}.get(rop, 'Unknown')
                    self.detail_text.insert(tk.END, f"- Number of Rules: {bytes_spaced_hex(nr_b)} ({nr})\n")
                    self.detail_text.insert(tk.END, f"- Rules Operator: {bytes_spaced_hex(rop_b)} ({rop}) [{rop_desc}]\n\n")

                    # Maps for fields and actions, derived from README documentation.
                    field_map = {
                        0x02: 'Song Name',
                        0x03: 'Album',
                        0x04: 'Artist',
                        0x05: 'Bitrate',
                        0x06: 'Sample Rate',
                        0x07: 'Year',
                        0x08: 'Genre',
                        0x09: 'Kind',
                        0x0A: 'Date Modified',
                        0x0B: 'Track Number',
                        0x0C: 'Size',
                        0x0D: 'Time',
                        0x0E: 'Comment',
                        0x10: 'Date Added',
                        0x12: 'Composer',
                        0x16: 'Play Count',
                        0x17: 'Last Played',
                        0x18: 'Disc Number',
                        0x19: 'Stars/Rating',
                        0x1F: 'Compilation',
                        0x23: 'BPM',
                        0x27: 'Grouping',
                        0x28: 'Playlist',
                        0x36: 'Description',
                        0x37: 'Category',
                        0x39: 'Podcast',
                        0x3C: 'Video Kind',
                        0x3E: 'TV Show',
                        0x3F: 'Season Number',
                        0x44: 'Skip Count',
                        0x45: 'Last Skipped',
                        0x47: 'Album Artist',
                    }
                    action_map = {
                        0x00000001: 'Is (Int / Is Set)',
                        0x00000010: 'Is Greater Than / After',
                        0x00000020: 'Is Greater Than Or Equal To',
                        0x00000040: 'Is Less Than / Before',
                        0x00000080: 'Is Less Than Or Equal To',
                        0x00000100: 'Is in the Range',
                        0x00000200: 'Is in the Last',
                        0x00000400: 'Is / Is Not (Binary AND)',
                        0x01000001: 'Is (String)',
                        0x01000002: 'Contains',
                        0x01000004: 'Starts With',
                        0x01000008: 'Ends With',
                        0x02000001: 'Is Not (Int / Not Set)',
                        0x02000010: 'Is Not Greater Than',
                        0x02000020: 'Is Not Greater Than Or Equal To',
                        0x02000040: 'Is Not Less Than',
                        0x02000080: 'Is Not Less Than Or Equal To',
                        0x02000100: 'Is Not in the Range',
                        0x02000200: 'Is Not in the Last',
                        0x03000001: 'Is Not',
                        0x03000002: 'Does Not Contain',
                        0x03000004: 'Does Not Start With',
                        0x03000008: 'Does Not End With',
                    }

                    rules = f.get('rules') or []
                    if rules:
                        sentinel_now = 0x2DAE2DAE2DAE2DAE
                        self.detail_text.insert(tk.END, "Rules:\n")
                        for idx, r in enumerate(rules, 1):
                            fid = r.get('field_id')
                            act = r.get('action')
                            is_string = r.get('is_string')
                            fname = field_map.get(fid, 'Unknown')
                            adesc = action_map.get(act, 'Unknown')
                            self.detail_text.insert(
                                tk.END,
                                f"  Rule #{idx}: Field 0x{fid:02X} [{fname}], Action 0x{act:08X} [{adesc}]\n"
                            )

                            if is_string:
                                s_val = r.get('string_text') or ''
                                slen_be = r.get('string_length')
                                self.detail_text.insert(
                                    tk.END,
                                    f"    String length: {slen_be} bytes\n"
                                )
                                if s_val:
                                    self.detail_text.insert(
                                        tk.END,
                                        f"    Value (UTF-16 BE): {s_val}\n"
                                    )
                            else:
                                fv = r.get('from_value')
                                fd = r.get('from_date')
                                fu = r.get('from_units')
                                tvv = r.get('to_value')
                                td = r.get('to_date')
                                tu = r.get('to_units')

                                def fmt_val(label: str, v: Optional[int]) -> str:
                                    if v is None:
                                        return f"{label}=None"
                                    return f"{label}={v} (0x{int(v) & ((1<<64)-1):016X})"

                                self.detail_text.insert(
                                    tk.END,
                                    "    " + ", ".join([
                                        fmt_val("from_value", fv),
                                        f"from_date={fd}",
                                        fmt_val("from_units", fu),
                                    ]) + "\n"
                                )
                                self.detail_text.insert(
                                    tk.END,
                                    "    " + ", ".join([
                                        fmt_val("to_value", tvv),
                                        f"to_date={td}",
                                        fmt_val("to_units", tu),
                                    ]) + "\n"
                                )

                                if fv == sentinel_now or tvv == sentinel_now:
                                    self.detail_text.insert(
                                        tk.END,
                                        "    Note: uses NOW sentinel (0x2dae2dae2dae2dae) in value fields.\n"
                                    )

                            self.detail_text.insert(tk.END, "\n")
                elif tv == 52:
                    # Library Playlist Index – index into mhit list.
                    self.detail_text.insert(tk.END, "- Library Playlist Index header:\n")
                    self.detail_text.insert(tk.END, f"  unk1: {bytes_spaced_hex(f.get('unk1_bytes') or b'')} ({f.get('unk1')})\n")
                    self.detail_text.insert(tk.END, f"  unk2: {bytes_spaced_hex(f.get('unk2_bytes') or b'')} ({f.get('unk2')})\n")
                    it = f.get('index_type')
                    it_b = f.get('index_type_bytes') or b''
                    count = f.get('count')
                    count_b = f.get('count_bytes') or b''
                    index_type_map = {
                        0x03: 'Title',
                        0x04: 'Album, then Disc/Track, then Title',
                        0x05: 'Artist, then Album, then Disc/Track, then Title',
                        0x07: 'Genre, then Artist, then Album, then Disc/Track, then Title',
                        0x12: 'Composer, then Title',
                        0x1D: 'TV Show (primary)',
                        0x1E: 'Season Number (primary)',
                        0x1F: 'Episode Number (primary)',
                        0x23: 'Unknown (observed in iTunes 7.3)',
                        0x24: 'Unknown (observed in iTunes 7.3)',
                    }
                    it_desc = index_type_map.get(it, 'Unknown')
                    self.detail_text.insert(tk.END, f"  Index Type: {bytes_spaced_hex(it_b)} ({it}) [{it_desc}]\n")
                    self.detail_text.insert(tk.END, f"  Entry Count: {bytes_spaced_hex(count_b)} ({count})\n\n")

                    entries = f.get('entries') or []
                    if entries:
                        max_preview = 64
                        preview = entries[:max_preview]
                        self.detail_text.insert(tk.END, "  First index entries (mhit indices):\n")
                        # Render in groups for readability
                        line = []
                        for i, val in enumerate(preview, 1):
                            line.append(str(val))
                            if i % 16 == 0:
                                self.detail_text.insert(tk.END, "    " + ", ".join(line) + "\n")
                                line = []
                        if line:
                            self.detail_text.insert(tk.END, "    " + ", ".join(line) + "\n")
                        if len(entries) > max_preview:
                            self.detail_text.insert(
                                tk.END,
                                f"    ... ({len(entries) - max_preview} more entries not shown)\n"
                            )
                        self.detail_text.insert(tk.END, "\n")
                elif tv == 53:
                    # Letter Jump Table – used for fast scrolling based on first letter.
                    self.detail_text.insert(tk.END, "- Letter Jump Table header:\n")
                    self.detail_text.insert(tk.END, f"  unk1: {bytes_spaced_hex(f.get('unk1_bytes') or b'')} ({f.get('unk1')})\n")
                    self.detail_text.insert(tk.END, f"  unk2: {bytes_spaced_hex(f.get('unk2_bytes') or b'')} ({f.get('unk2')})\n")
                    it = f.get('index_type')
                    it_b = f.get('index_type_bytes') or b''
                    count = f.get('count')
                    count_b = f.get('count_bytes') or b''
                    index_type_map = {
                        0x03: 'Title',
                        0x04: 'Album, then Disc/Track, then Title',
                        0x05: 'Artist, then Album, then Disc/Track, then Title',
                        0x07: 'Genre, then Artist, then Album, then Disc/Track, then Title',
                        0x12: 'Composer, then Title',
                        0x1D: 'TV Show (primary)',
                        0x1E: 'Season Number (primary)',
                        0x1F: 'Episode Number (primary)',
                        0x23: 'Unknown (observed in iTunes 7.3)',
                        0x24: 'Unknown (observed in iTunes 7.3)',
                    }
                    it_desc = index_type_map.get(it, 'Unknown')
                    self.detail_text.insert(tk.END, f"  Index Type: {bytes_spaced_hex(it_b)} ({it}) [{it_desc}]\n")
                    self.detail_text.insert(tk.END, f"  Entry Count: {bytes_spaced_hex(count_b)} ({count})\n\n")

                    entries = f.get('entries') or []
                    if entries:
                        self.detail_text.insert(tk.END, "  Letter entries (letter ⇒ first index, count):\n")
                        for e in entries:
                            letter_bytes = e.get('letter_bytes') or b''
                            letter_char = e.get('letter_char') or ''
                            first_index = e.get('first_index')
                            entry_count = e.get('entry_count')
                            self.detail_text.insert(
                                tk.END,
                                f"    {bytes_spaced_hex(letter_bytes)} "
                                f"('{letter_char}' if printable) ⇒ first={first_index}, count={entry_count}\n"
                            )
                        self.detail_text.insert(tk.END, "\n")
                else:
                    self.detail_text.insert(tk.END, f"- Position: {bytes_spaced_hex(pos_b)} ({pos})  [typically 1]\n")
                    self.detail_text.insert(tk.END, f"- String Length: {bytes_spaced_hex(slen_b)} ({slen}) bytes\n")
                    self.detail_text.insert(tk.END, f"- Unk13: {bytes_spaced_hex(u13_b)} ({u13})\n")
                    if s_b:
                        self.detail_text.insert(tk.END, f"- String bytes: {bytes_spaced_hex(s_b)}\n")
                        notes = []
                        if tv == 2 and isinstance(slen, int) and slen > 112:
                            notes.append("Location exceeds 112 bytes; iPod may skip playback")
                        if notes:
                            self.detail_text.insert(tk.END, "- Notes: " + "; ".join(notes) + "\n")
                        if s_txt:
                            self.detail_text.insert(tk.END, f"- String (decoded): {s_txt}\n\n")
                        else:
                            self.detail_text.insert(tk.END, "\n")
                    else:
                        self.detail_text.insert(tk.END, "- String bytes: (none)\n\n")

            self.detail_text.insert(tk.END, "Header preview (entire header):\n")
            self.detail_text.insert(tk.END, hex_preview(ch.raw_header, max_bytes=None))
        else:
            self.detail_title.config(text="Info")
            self.detail_text.insert(tk.END, "No details available.")

        self.detail_text.config(state='disabled')

    def _autosize_tree_columns(self):
        """Resize tree columns (#0 and data columns) to fit content."""
        try:
            self.update_idletasks()
            # Use default font metrics for measurement
            try:
                tv_font = tkfont.nametofont('TkDefaultFont')
            except Exception:
                tv_font = tkfont.Font()

            # Gather all items recursively
            def all_items(parent=''):
                items = []
                for iid in self.tree.get_children(parent):
                    items.append(iid)
                    items.extend(all_items(iid))
                return items

            items = all_items('')

            # Columns to measure: '#0' (tree text) and defined columns
            columns = ['#0'] + list(self.tree['columns'])
            # Minimum and maximum widths per column (pixels)
            min_widths = {'#0': 120, 'offset': 120, 'size': 80, 'endian': 60}
            max_width = 600

            for col in columns:
                # Start with heading text width
                heading_text = self.tree.heading(col, 'text') if col != '#0' else 'Name'
                width_px = tv_font.measure(heading_text) + 24
                # Check all item texts
                for iid in items:
                    if col == '#0':
                        text = self.tree.item(iid, 'text') or ''
                    else:
                        text = self.tree.set(iid, col) or ''
                    w = tv_font.measure(text) + 24
                    if w > width_px:
                        width_px = w
                width_px = max(width_px, min_widths.get(col, 60))
                width_px = min(width_px, max_width)
                self.tree.column(col, width=width_px)
        except Exception:
            # Fail silently to avoid disrupting UX on platform-specific quirks
            pass


def main():
    app = App()
    app.mainloop()


if __name__ == '__main__':
    main()
