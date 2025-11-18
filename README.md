# iTunesDB Explorer

iTunesDB Explorer is a Tkinter-based desktop tool and Python parser for
reverse-engineering the legacy iPod/iTunes database format (`iTunesDB`).
It lets you open an iTunesDB file, browse its internal tree of chunks
(`mhbd`, `mhsd`, `mhit`, `mhod`, playlists, albums, smart playlists, etc.),
inspect parsed fields and raw hex, and export the full parsed structure to
JSON for diffing and offline analysis.

**Goals**

- Provide a precise, self-contained reference for the iTunesDB on-device
  format, independent of any Apple tooling.
- Make it practical to compare different iTunesDB files (different devices,
  firmware, iTunes versions) to discover new fields and behaviors.
- Enable future work on *writing* iTunesDB files (e.g., rebuilding or
  editing libraries) by fully understanding the read layout first.
- Preserve enough low-level detail (offsets, sizes, raw hex) that the
  original on-disk structure can be reconstructed exactly.

The rest of this document captures the current understanding of the iTunesDB
format as implemented by `itunesdb_viewer.py`.  
All offsets are **relative to the start of the tag** (i.e. where the 4‑byte
4CC such as `mhbd` begins) and all multi‑byte integers are **little‑endian**
unless otherwise noted.

Many fields are still speculative; anything named `unk*` or described as
“unknown” is not yet fully understood and is preserved only so that the
original structure can be reconstructed or extended later.

---

## Common Conventions

- `u32` – 32‑bit unsigned integer (little‑endian).
- `u16` – 16‑bit unsigned integer (little‑endian).
- `u64` – 64‑bit unsigned integer (little‑endian).
- `byte` – 8‑bit unsigned integer.
- `bytes[N]` – raw byte array of length `N`.
- `HFS time` – seconds since 1904‑01‑01 UTC (converted by `hfs_to_iso()`).
- “header_length” – length of the header / fixed fields for a section.
- “total_length” – full length of the section, including header and children.

The parser always stores **raw bytes** and, where meaningful, decoded numeric
values as `fields[...]` on a `Chunk` object.

---

## Export & Analysis Workflow

`itunesdb_viewer.py` can export the fully parsed tree to a JSON file:

- Menu: **File → Export parsed tree…**
- Format:
  - Top-level object with:
    - `export_version` – currently `1`.
    - `source` – minimal metadata.
    - `tree` – list of root nodes (normally a single file node).
  - Each file node:
    - `{"kind": "file", "path", "size", "children": [...]}`.
  - Each chunk node:
    - `{"kind": "chunk", "tag", "offset", "size", "endian", "raw_header_hex", "fields", "children"}`.
    - `raw_header_hex` is the header bytes rendered as spaced hex (`"aa bb cc"`).
    - `fields` mirrors `Chunk.fields` from the parser, except:
      - All `bytes` values are converted to space-separated hex strings.
      - Nested dicts/lists are preserved; ints/strings remain as-is.

The export is designed so you can:

- Diff two JSON exports from different iPods/iTunes versions to spot field
  changes or new structures.
- Script further analysis in Python or another language without re-parsing
  the binary format each time.

## `mhbd` – Database Header

Parsed in `ITunesDBParser.parse_mhbd()`.

Layout (relative to `mhbd` tag, 0‑based):

| Offset | Size | Name                          | Type   | Notes                                                |
|--------|------|-------------------------------|--------|------------------------------------------------------|
| 0      | 4    | `tag_bytes`                   | bytes  | ASCII `"mhbd"`.                                      |
| 4      | 4    | `header_size`                 | u32    | Size of header region. Must cover all fields below.  |
| 8      | 4    | `total_file_size`             | u32    | Expected size of the whole DB file.                  |
| 12     | 4    | `unk1`                        | u32    | Unknown, often `1`.                                  |
| 16     | 4    | `database_version`            | u32    | Database version (exact semantics TBD).              |
| 20     | 4    | `num_mhsd_sets`               | u32    | Number of `mhsd` datasets.                           |
| 24     | 8    | `database_uuid_bytes`         | bytes8 | Some kind of database UUID.                          |
| 32     | 2    | `unk2`                        | u16    | Unknown constant.                                    |
| 34     | 10   | `stable_identifier_bytes`     | bytes10| Stable identifier (ASCII‑ish).                       |
| 44     | 2    | `language_bytes`              | bytes2 | ISO‑639‑1 language code (ASCII), e.g. `"en"`.        |
| 46     | 8    | `persistent_library_id_bytes` | bytes8 | Persistent library identifier (ASCII/hex‑like).      |
| 80     | 4    | `unk3`                        | u32    | Unknown.                                             |
| 84     | 4    | `unk4`                        | u32    | Unknown.                                             |
| 108    | 2    | `unk5`                        | u16    | Unknown.                                             |
| 110    | 2    | `unk6`                        | u16    | Unknown.                                             |
| 160    | 4    | `unk7`                        | u32    | Unknown.                                             |
| 164    | 2    | `unk8`                        | u16    | Unknown.                                             |
| 166    | 2    | `unk9`                        | u16    | Unknown.                                             |
| 0..`header_size` | `header_size` | (header bytes) | bytes | Captured as `raw_header` for inspection.         |

The parser requires `header_size >= 168` and `offset + header_size <= file_len`
for the layout to be considered valid. Otherwise an `mhbd` chunk is still
exposed but only with a short raw preview.

---

## `mhsd` – Dataset Section

Parsed in `ITunesDBParser.parse_mhsd()`.

Layout:

| Offset | Size | Name              | Type   | Notes                                   |
|--------|------|-------------------|--------|-----------------------------------------|
| 0      | 4    | `tag_bytes`       | bytes  | ASCII `"mhsd"`.                         |
| 4      | 4    | `header_length`   | u32    | Size of this header.                    |
| 8      | 4    | `total_length`    | u32    | Size of section including children.     |
| 12     | 4    | `type`            | u32    | Dataset type (see below).               |
| 16..HL | ?    | (header padding)  | bytes  | Usually zero padding.                   |

Children of an `mhsd` live in the range:

> `[offset + header_length, offset + total_length)`

Known `type` values (inferred by the UI):

- `1` – Track list (`mhlt`, containing `mhit` items).
- `2` – Playlist list (`mhlp` / `mhyp` / `mhip`).
- `3` – Podcast list (playlist‑like).
- `4` – Album list (`mhla` / `mhia`).
- `5` – “New Playlist List with Smart Playlists” (exact semantics TBD).

---

## `mhlt` – Track List

Parsed in `ITunesDBParser.parse_mhlt_in_range()`.

Layout:

| Offset | Size | Name                | Type | Notes                                   |
|--------|------|---------------------|------|-----------------------------------------|
| 0      | 4    | `tag_bytes`         | bytes| ASCII `"mhlt"`.                         |
| 4      | 4    | `header_length`     | u32  | Header size.                            |
| 8      | 4    | `number_of_songs`   | u32  | Number of `mhit` records in this list.  |
| 12..HL | ?    | (padding)           | bytes| Typically zero.                          |

Children region:

> `tracks: [offset + header_length, ?]` – scanned for `mhit` tags.

---

## `mhit` – Track Item

Parsed in `ITunesDBParser.parse_mhit_in_range()`.  
This is the heaviest structure; several offsets come from public reverse‑
engineering work and may vary with device/iTunes version.

Layout (known up to offset 260):

| Offset | Size | Name                        | Type   | Notes                                           |
|--------|------|-----------------------------|--------|-------------------------------------------------|
| 0      | 4    | `tag_bytes`                 | bytes  | ASCII `"mhit"`.                                 |
| 4      | 4    | `header_length`             | u32    | Header size.                                    |
| 8      | 4    | `total_length`              | u32    | Size of entire `mhit` including MHOD strings.   |
| 12     | 4    | `number_of_strings`         | u32    | Count of `mhod` children for this track.        |
| 16     | 4    | `unique_id`                 | u32    | Track ID / persistent track key.                |
| 20     | 4    | `visible`                   | u32    | Non‑zero if visible in UI (exact semantics TBD).|
| 24     | 4    | `filetype_bytes`            | bytes4 | Four‑char code (e.g. `"M4A "`, `"MP3 "`).       |
| 28     | 1    | `type1`                     | byte   | Track type flags (partial).                     |
| 29     | 1    | `type2`                     | byte   | Additional flags.                               |
| 30     | 1    | `compilation_flag`          | byte   | Non‑zero for compilations.                      |
| 31     | 1    | `rating`                    | byte   | 0–100 rating (or 0–255 scaled).                 |
| 32     | 4    | `last_modified_time`        | u32    | HFS time: last modified.                        |
| 36     | 4    | `size`                      | u32    | File size in bytes.                             |
| 40     | 4    | `length_ms`                 | u32    | Track length in milliseconds.                   |
| 44     | 4    | `track_number`              | u32    | 1‑based track number.                           |
| 48     | 4    | `total_tracks`              | u32    | Total tracks on album.                          |
| 52     | 4    | `year`                      | u32    | Year (e.g. 2007).                               |
| 56     | 4    | `bitrate`                   | u32    | kbps.                                           |
| 60     | 4    | `sample_rate_q16`           | u32    | 16.16 fixed‑point sample rate; use `q16_to_int`.|
| 64     | 4    | `volume`                    | u32    | Volume (format TBD, may be fixed‑point).        |
| 68     | 4    | `start_time`                | u32    | Start offset (ms).                              |
| 72     | 4    | `stop_time`                 | u32    | Stop offset (ms).                               |
| 76     | 4    | `soundcheck`                | u32    | Sound Check data (format TBD).                  |
| 80     | 4    | `play_count`                | u32    | Play count.                                     |
| 84     | 4    | `play_count2`               | u32    | Secondary play count / smart info.              |
| 88     | 4    | `last_played_time`          | u32    | HFS time.                                       |
| 92     | 4    | `disc_number`               | u32    | Disc number.                                    |
| 96     | 4    | `total_discs`               | u32    | Total discs.                                    |
| 100    | 4    | `user_id`                   | u32    | Unknown, possibly owner ID.                     |
| 104    | 4    | `date_added`                | u32    | HFS time when added to library.                 |
| 108    | 4    | `bookmark_time`             | u32    | Bookmark position in ms.                        |
| 112    | 8    | `dbid_bytes`                | bytes8 | Database ID (64‑bit).                           |
| 120    | 1    | `checked`                   | byte   | Checkbox state (0/1).                           |
| 121    | 1    | `app_rating`                | byte   | Rating used by device (vs. desktop).            |
| 122    | 2    | `bpm`                       | u16    | Beats per minute.                               |
| 124    | 2    | `artwork_count`             | u16    | Number of artworks.                             |
| 126    | 2    | `unk9`                      | u16    | Unknown.                                        |
| 128    | 4    | `artwork_size`              | u32    | Combined artwork size (bytes).                  |
| 132    | 4    | `unk11`                     | u32    | Unknown.                                        |
| 136    | 4    | `sample_rate_f_raw`         | u32    | Raw float sample rate; use `float_from_le_bytes`.|
| 140    | 4    | `date_released`             | u32    | HFS time.                                       |
| 144    | 2    | `unk14_1`                   | u16    | Unknown.                                        |
| 146    | 2    | `unk14_2`                   | u16    | Unknown.                                        |
| 148    | 4    | `unk15`                     | u32    | Unknown.                                        |
| 152    | 4    | `unk16`                     | u32    | Unknown.                                        |
| 156    | 4    | `skip_count`                | u32    | Number of skips.                                |
| 160    | 4    | `last_skipped`              | u32    | HFS time last skipped.                          |
| 164    | 1    | `has_artwork`               | byte   | Non‑zero if track has artwork.                  |
| 165    | 1    | `skip_when_shuffling`       | byte   | Boolean flag.                                   |
| 166    | 1    | `remember_playback_position`| byte   | Boolean flag.                                   |
| 167    | 1    | `flag7`                     | byte   | Unknown flag byte.                              |
| 168    | 8    | `dbid2_bytes`               | bytes8 | Secondary database ID.                          |
| 176    | 1    | `lyrics_flag`               | byte   | Non‑zero if lyrics present.                     |
| 177    | 1    | `movie_file_flag`           | byte   | Indicates video/movie file.                     |
| 178    | 1    | `played_mark`               | byte   | Play marker flag.                               |
| 179    | 1    | `unk17`                     | byte   | Unknown.                                        |
| 180    | 4    | `unk21`                     | u32    | Unknown.                                        |
| 184    | 4    | `pregap`                    | u32    | Pregap (samples or ms, TBD).                    |
| 188    | 8    | `sample_count`              | u64    | Total samples.                                  |
| 196    | 4    | `unk25`                     | u32    | Unknown.                                        |
| 200    | 4    | `postgap`                   | u32    | Postgap.                                        |
| 204    | 4    | `unk27`                     | u32    | Unknown.                                        |
| 208    | 4    | `media_type`                | u32    | Media type (audio/video/podcast etc.).          |
| 212    | 4    | `season_number`             | u32    | TV season number.                               |
| 216    | 4    | `episode_number`            | u32    | TV episode number.                              |
| 220    | 4    | `unk31`                     | u32    | Unknown.                                        |
| 224    | 4    | `unk32`                     | u32    | Unknown.                                        |
| 228    | 4    | `unk33`                     | u32    | Unknown.                                        |
| 232    | 4    | `unk34`                     | u32    | Unknown.                                        |
| 236    | 4    | `unk35`                     | u32    | Unknown.                                        |
| 240    | 4    | `unk36`                     | u32    | Unknown.                                        |
| 244    | 4    | `unk37`                     | u32    | Unknown.                                        |
| 248    | 4    | `gaplessData`               | u32    | Gapless playback metadata.                      |
| 252    | 4    | `unk38`                     | u32    | Unknown.                                        |
| 256    | 2    | `gaplessTrackFlag`          | u16    | Flag for track‑level gapless info.              |
| 258    | 2    | `gaplessAlbumFlag`          | u16    | Flag for album‑level gapless info.              |
| 260    | 20   | `unk39_bytes`               | bytes20| Unknown trailer fields.                          |

Children region for MHOD strings:

> `[offset + header_length, offset + total_length)` – scanned for `mhod`.

---

## `mhlp` – Playlist List

Parsed in `ITunesDBParser.parse_mhlp_in_range()` (via `_parse_generic_list_section`).

Layout (generic “list section”):

| Offset | Size | Name            | Type | Notes                                   |
|--------|------|-----------------|------|-----------------------------------------|
| 0      | 4    | `tag_bytes`     | bytes| ASCII `"mhlp"`.                         |
| 4      | 4    | `header_length` | u32  | Header size (≥ 12).                     |
| 8      | 4    | `total_length`  | u32  | Full section length.                    |
| 12..HL | ?    | (padding)       | bytes| May contain additional header data.     |

Additional fields parsed for playlist lists:

| Offset | Size | Name                      | Type | Notes                      |
|--------|------|---------------------------|------|----------------------------|
| 8      | 4    | `number_of_playlists`    | u32  | Count of playlists in list.|

Children region:

> `[offset + header_length, offset + total_length)` – scanned for `mhyp` (playlists).

---

## `mhyp` – Playlist Header

Parsed in `ITunesDBParser.parse_mhyp_in_range()`.

Layout:

| Offset | Size | Name                          | Type   | Notes                                |
|--------|------|-------------------------------|--------|--------------------------------------|
| 0      | 4    | `tag_bytes`                   | bytes  | ASCII `"mhyp"`.                      |
| 4      | 4    | `header_length`               | u32    | Header size.                         |
| 8      | 4    | `total_length`                | u32    | Total playlist section length.       |
| 12     | 4    | `data_object_child_count`     | u32    | Number of child `mhod` objects.      |
| 16     | 4    | `playlist_item_count`         | u32    | Number of `mhip` playlist items.     |
| 20     | 4    | `is_master_playlist`          | u32    | `1` for the main library playlist.   |
| 24     | 4    | `flags3`                      | u32    | Flag bits (semantics TBD).           |
| 28     | 4    | `timestamp`                   | u32    | HFS time for playlist updated/added. |
| 32     | 8    | `persistent_playlist_id_bytes`| bytes8 | Persistent playlist ID.              |
| 40     | 4    | `unk3`                        | u32    | Unknown.                              |
| 44     | 4    | `string_mhod_count`          | u32    | Number of string MHODs.              |
| 48     | 4    | `podcast_flag`               | u32    | Non‑zero if a podcast playlist.      |
| 52     | 4    | `list_sort_order`           | u32    | Sort order (ascending/descending etc.). |
| 56     | 4    | `list_sort_field`           | u32    | Which field the playlist is sorted by. |

Children:

- String `mhod` children and `mhip` playlist‑item records live in
  `[offset + header_length, offset + total_length)`.

---

## `mhip` – Playlist Item

Parsed in `ITunesDBParser.parse_mhip_in_range()`.

Layout:

| Offset | Size | Name                         | Type   | Notes                                   |
|--------|------|------------------------------|--------|-----------------------------------------|
| 0      | 4    | `tag_bytes`                  | bytes  | ASCII `"mhip"`.                         |
| 4      | 4    | `header_length`              | u32    | Header size.                            |
| 8      | 4    | `total_length`               | u32    | Full playlist‑item record length.       |
| 12     | 4    | `data_object_child_count`    | u32    | Child MHOD count.                       |
| 16     | 2    | `podcast_grouping_flag`      | u16    | For podcast grouping, if used.          |
| 18     | 1    | `unk4`                       | byte   | Unknown flag.                           |
| 19     | 1    | `unk5`                       | byte   | Unknown flag.                           |
| 20     | 4    | `group_id`                   | u32    | Group ID (podcast grouping etc.).       |
| 24     | 4    | `track_id`                   | u32    | Track unique ID (matches `mhit.unique_id`). |
| 28     | 4    | `timestamp`                  | u32    | HFS time related to playlist entry.     |
| 32     | 4    | `podcast_grouping_reference` | u32    | Reference back to podcast grouping.     |

Children:

- `mhod` data objects for this playlist item live in
  `[offset + header_length, offset + total_length)`.

---

## `mhla` – Album List

Parsed in `ITunesDBParser.parse_mhla_in_range()`.

Layout:

| Offset | Size | Name                     | Type | Notes                            |
|--------|------|--------------------------|------|----------------------------------|
| 0      | 4    | `tag_bytes`              | bytes| ASCII `"mhla"`.                  |
| 4      | 4    | `header_length`          | u32  | Header size.                     |
| 8      | 4    | `number_of_album_items`  | u32  | Count of `mhia` album entries.   |

Children:

- `mhia` album items live after the header within the containing `mhsd`.

---

## `mhia` – Album Item

Parsed in `ITunesDBParser.parse_mhia_in_range()`.

Layout:

| Offset | Size | Name                 | Type   | Notes                              |
|--------|------|----------------------|--------|------------------------------------|
| 0      | 4    | `tag_bytes`          | bytes  | ASCII `"mhia"`.                    |
| 4      | 4    | `header_length`      | u32    | Header size (≥ 40).                |
| 8      | 4    | `total_length`       | u32    | Full album‑item section length.    |
| 12     | 4    | `number_of_strings`  | u32    | Number of associated string MHODs. |
| 16     | 4    | `album_reference_id` | u32    | Album reference / ID.              |
| 20     | 8    | `unk10_bytes`        | bytes8 | Unknown.                           |
| 28     | 4    | `unk11`              | u32    | Unknown.                           |
| 32     | 8    | `unk12_bytes`        | bytes8 | Unknown.                           |

Children:

- Corresponding `mhod` strings (album title, artist, etc.) live in:

> `[offset + header_length, offset + total_length)`.

---

## `mhod` – Data Object (Strings and More)

Parsed in `ITunesDBParser.parse_mhod_in_range()`.  
These objects carry strings (title, artist, album, etc.) and some non‑string
payloads (e.g. smart playlist data).

### Generic String MHOD Layout

Used by most string MHOD types (title, artist, album, etc.):

| Offset | Size | Name              | Type   | Notes                                       |
|--------|------|-------------------|--------|---------------------------------------------|
| 0      | 4    | `tag_bytes`       | bytes  | ASCII `"mhod"`.                             |
| 4      | 4    | `header_length`   | u32    | Typically `0x18` (24) for string MHODs.     |
| 8      | 4    | `total_length`    | u32    | Full length of this MHOD.                   |
| 12     | 4    | `type`            | u32    | MHOD type (see table below).                |
| 16     | 4    | `unk1`            | u32    | Unknown / flags.                            |
| 20     | 4    | `unk2`            | u32    | Unknown / flags.                            |
| 24     | 4    | `position`        | u32    | Index of this string within parent.         |
| 28     | 4    | `string_length`   | u32    | Length of string for most types.            |
| 32     | 4    | `unk13`           | u32    | Unknown; may be flags.                      |
| 28..44 | 16   | `padding16_bytes` | bytes16| Raw bytes from 28–43 (overlaps fields).     |
| 40..N  | var  | `string_bytes`    | bytes  | Actual payload; not NUL terminated.         |

Effective string length:

- For these generic types, `string_length` gives the length, capped by
  `total_length`.

### Podcast URL MHODs (Types 15–16)

Introduced in database version `0x0d`.  
Types `15` and `16` hold the Podcast Enclosure URL and RSS URL respectively.

Layout (based on observed files and current parser behaviour):

| Offset | Size | Name              | Type   | Notes                                       |
|--------|------|-------------------|--------|---------------------------------------------|
| 0      | 4    | `tag_bytes`       | bytes  | `"mhod"`.                                   |
| 4      | 4    | `header_length`   | u32    | Always `0x18` (24) in known samples.        |
| 8      | 4    | `total_length`    | u32    | Header + URL string length.                 |
| 12     | 4    | `type`            | u32    | `15` = Enclosure URL, `16` = RSS URL.       |
| 16     | 4    | `unk1`            | u32    | Unknown (often `0`).                        |
| 20     | 4    | `unk2`            | u32    | Unknown (often `0`).                        |
| 24..HL | var  | (no extra fields) | —      | No `position` / `string_length` / `unk13`.  |
| HL..TL | var  | `string_bytes`    | bytes  | UTF‑8 URL; length = `total_length - header_length`. |

The parser treats types 15/16 as:

- String starts at `offset + header_length`.
- Effective length = `total_length - header_length`.
- String decoding is UTF‑8 (`errors='replace'`); observed URLs are ASCII‑only.

### Smart Playlist Data (Type 50)

Type `50` carries the non‑rule settings for a Smart Playlist: checkboxes and
limit configuration, not the rule list itself (which lives in type `51` MHODs).

Layout:

| Offset | Size | Name                 | Type   | Notes                                                  |
|--------|------|----------------------|--------|--------------------------------------------------------|
| 0      | 4    | `tag_bytes`          | bytes  | `"mhod"`.                                              |
| 4      | 4    | `header_length`      | u32    | Header size.                                           |
| 8      | 4    | `total_length`       | u32    | Total length of this MHOD.                             |
| 12     | 4    | `type`               | u32    | Always `50`.                                           |
| 16     | 4    | `unk1`               | u32    | Unknown.                                               |
| 20     | 4    | `unk2`               | u32    | Unknown.                                               |
| 24     | 1    | `live_update`        | byte   | `0x01` = on, `0x00` = off.                             |
| 25     | 1    | `check_rules`        | byte   | `0x01` = use rules from type‑51 MHOD, else ignore.     |
| 26     | 1    | `check_limits`       | byte   | `0x01` = apply limits below, `0x00` = ignore.          |
| 27     | 1    | `limit_type`         | byte   | See *Limit Types* table.                               |
| 28     | 1    | `limit_sort`         | byte   | See *Limit Sort Types* table.                          |
| 29     | 3    | `zeros_29_31_bytes`  | bytes3 | Always zero in known samples.                          |
| 32     | 4    | `limit_value`        | u32    | Numeric value used with `limit_type` (e.g., songs).    |
| 36     | 1    | `match_checked_only` | byte   | `0x01` = only include checked tracks; `0x00` = ignore. |
| 37     | 1    | `reverse_limit_sort` | byte   | `0x01` = reverse the limit sort order; `0x00` = normal.|
| 38..N  | —    | padding              | bytes  | Zero padding; often 58 zero bytes at end.             |

Limit Types (`limit_type`):

- `1` – Minutes  
- `2` – Megabytes  
- `3` – Songs  
- `4` – Hours  
- `5` – Gigabytes  

Limit Sort Types (`limit_sort`):

- `0x02` – Random  
- `0x03` – Song Name (alphabetical)  
- `0x04` – Album (alphabetical)  
- `0x05` – Artist (alphabetical)  
- `0x07` – Genre (alphabetical)  
- `0x10` – Most Recently Added  
- `0x14` – Most Often Played  
- `0x15` – Most Recently Played  
- `0x17` – Highest Rating  

When `reverse_limit_sort` is set, the chosen sort order is reversed before
applying the limit (e.g., “Most Recently Added” becomes “Least Recently Added”).

### Smart Playlist Rules (Type 51)

Type `51` carries the full rule set for a Smart Playlist.  
Each rule conceptually has three parts:

- **Field** – what is being tested (e.g., Rating, Year, Artist).  
- **Action** – the comparison operator (e.g., “is less than”).  
- **Value** – the value compared against (e.g., `3` stars ⇒ numeric `60` in DB).

Important endianness note:

- The MHOD header itself (tag, header length, total length, type, etc.) is still
  little‑endian as with other MHODs.
- Everything from the internal tag `"SLst"` to the end of the MHOD body is
  **big‑endian**. This affects the rule encodings, especially action/value
  numbers.

The exact binary layout of the `"SLst"` rule block is not yet implemented in
the parser, but the following **Rule Field Types** map is known and will be
used when decoding individual rules.

**Smart Playlist Rule Field Types**

These values identify which track/library field a rule operates on.

| Value | Description        | Expected comparison |
|-------|--------------------|---------------------|
| 0x02  | Song Name          | String              |
| 0x03  | Album              | String              |
| 0x04  | Artist             | String              |
| 0x05  | Bitrate            | Integer             |
| 0x06  | Sample Rate        | Integer             |
| 0x07  | Year               | Integer             |
| 0x08  | Genre              | String              |
| 0x09  | Kind               | String              |
| 0x0a  | Date Modified      | Timestamp           |
| 0x0b  | Track Number       | Integer             |
| 0x0c  | Size               | Integer             |
| 0x0d  | Time               | Integer             |
| 0x0e  | Comment            | String              |
| 0x10  | Date Added         | Timestamp           |
| 0x12  | Composer           | String              |
| 0x16  | Play Count         | Integer             |
| 0x17  | Last Played        | Timestamp           |
| 0x18  | Disc Number        | Integer             |
| 0x19  | Stars/Rating       | Integer (×20 for stars) |
| 0x1f  | Compilation        | Integer             |
| 0x23  | BPM                | Integer             |
| 0x27  | Grouping           | String (see note)   |
| 0x28  | Playlist           | Integer (playlist ID; see note) |
| 0x36  | Description        | String              |
| 0x37  | Category           | String              |
| 0x39  | Podcast            | Integer             |
| 0x3c  | Video Kind         | Logic integer (based on media type) |
| 0x3e  | TV Show            | String              |
| 0x3f  | Season Nr          | Integer             |
| 0x44  | Skip Count         | Integer             |
| 0x45  | Last Skipped       | Timestamp           |
| 0x47  | Album Artist       | String              |

Notes:

- Grouping (`0x27`) and Playlist (`0x28`) fields do not Live‑Update correctly
  on some older devices (e.g., 3rd gen iPods).
- When parsing rules, each Field ID will be paired with an Action and Value
  encoded in the big‑endian `"SLst"` payload.

**MHOD Layout – Smart Playlist Rules (type 51)**

The enclosing type‑51 MHOD has the following header, before the `"SLst"` rule
payload begins:

| Offset | Size | Name                      | Type   | Notes                                                                 |
|--------|------|---------------------------|--------|-----------------------------------------------------------------------|
| 0      | 4    | `tag_bytes`              | bytes  | `"mhod"`.                                                             |
| 4      | 4    | `header_length`          | u32 LE | Size of the MHOD header.                                             |
| 8      | 4    | `total_length`           | u32 LE | Header + rules payload length.                                       |
| 12     | 4    | `type`                   | u32 LE | Always `51` for Smart Playlist Rules.                                |
| 16     | 4    | `unk1`                   | u32 LE | Unknown.                                                             |
| 20     | 4    | `unk2`                   | u32 LE | Unknown.                                                             |
| 24     | 4    | `smart_list_id`         | bytes  | ASCII `"SLst"` – **endianness switches to big‑endian from here on**. |
| 28     | 4    | `unk5`                   | u32 BE | Unknown (big‑endian).                                                |
| 32     | 4    | `number_of_rules`       | u32 BE | Count of rules in the `"SLst"` payload.                              |
| 36     | 4    | `rules_operator`        | u32 BE | `0` = AND (“Match All”), `1` = OR (“Match Any”).                     |
| 40     | 120  | `padding`               | bytes  | Zero padding.                                                        |
| 160    | var  | `rules`                 | bytes  | Concatenated SPLRule records (string and/or non‑string formats).     |

The MHOD is **not** zero‑padded at the end; it ends exactly after the last
rule record, and `total_length` reflects the combined header + rules size.

**Smart Playlist Rule Actions**

Each rule includes a 4‑byte **Action** value that encodes:

- whether the comparison is against a string or a non‑string value, and  
- which operator is being applied (is, contains, begins with, etc.), and  
- whether the logic is negated (“is” vs “is not”, “contains” vs “does not contain”).

The 4‑byte Action is bitmapped:

- **High byte (bits 8–15)** – type / negate
  - Bit 0: set ⇒ comparison is against a **string**; clear ⇒ non‑string.
  - Bit 1: `NOT` flag; when set, negates the rule (e.g., *is* → *is not*).
- **Low 2 bytes (bits 0–15)** – operator
  - Bit 0: simple “is” comparison.
  - Bit 1: contains.
  - Bit 2: begins with.
  - Bit 3: ends with.
  - Bit 4: greater than.
  - Bit 5: greater than or equal to.
  - Bit 6: less than.
  - Bit 7: less than or equal to.
  - Bit 8: is in the range.
  - Bit 9: in the last.
  - Bit 10: is / is not (binary AND; used for “Video Kind” so far).

In practice, iTunes and the iPod use a fixed set of combined values.  
These are the commonly observed composite Action values:

| Value       | Action description                                        |
|------------:|-----------------------------------------------------------|
| 0x00000001  | Is Int (also “Is Set” in iTunes)                          |
| 0x00000010  | Is Greater Than (also “Is After” in iTunes)               |
| 0x00000020  | Is Greater Than Or Equal To (not exposed in iTunes UI)    |
| 0x00000040  | Is Less Than (also “Is Before” in iTunes)                 |
| 0x00000080  | Is Less Than Or Equal To (not exposed in iTunes UI)       |
| 0x00000100  | Is in the Range                                           |
| 0x00000200  | Is in the Last                                            |
| 0x00000400  | Is / Is Not (binary AND; used for media type)            |
| 0x01000001  | Is String                                                 |
| 0x01000002  | Contains                                                  |
| 0x01000004  | Starts With                                               |
| 0x01000008  | Ends With                                                 |
| 0x02000001  | Is Not Int (also “Is Not Set” in iTunes)                  |
| 0x02000010  | Is Not Greater Than (not exposed in iTunes UI)            |
| 0x02000020  | Is Not Greater Than Or Equal To (not in iTunes UI)        |
| 0x02000040  | Is Not Less Than (not in iTunes UI)                       |
| 0x02000080  | Is Not Less Than Or Equal To (not in iTunes UI)           |
| 0x02000100  | Is Not in the Range (not in iTunes UI)                    |
| 0x02000200  | Is Not in the Last                                        |
| 0x03000001  | Is Not                                                    |
| 0x03000002  | Does Not Contain                                          |
| 0x03000004  | Does Not Start With (not in iTunes UI)                    |
| 0x03000008  | Does Not End With (not in iTunes UI)                      |

When the type‑51 parser is implemented, these values can be decoded directly
from the big‑endian Action field to drive human‑readable rule strings in the UI.

**Smart Playlist Rule Values**

Rule **Values** are encoded differently depending on whether the rule compares
against a string (e.g., “Artist contains …”) or a non‑string (integers and
timestamps such as “Play Count is greater than …” or “Last Played is in the last …”).

There are therefore two major rule formats inside the `"SLst"` payload:

#### SPLRule String Format

Used when the Field’s expected comparison is a string (e.g., Song Name, Album).

All multi‑byte values from the start of the rule are **big‑endian**.

| Offset | Size | Name    | Type   | Notes                                                      |
|--------|------|---------|--------|------------------------------------------------------------|
| 0      | 4    | field   | u32 BE | Rule Field Type (see table above).                         |
| 4      | 4    | action  | u32 BE | Rule Action (bitmapped, see Actions table).                |
| 8      | 44   | padding | bytes  | Zero padding.                                              |
| 52     | 4    | length  | u32 BE | String length in bytes (max 255).                          |
| 56     | var  | string  | bytes  | UTF‑16 string (`length` bytes, 2 bytes per character).     |

String rules are **not** zero‑padded at the end; the next rule (if any) starts
immediately after the last UTF‑16 byte.

#### SPLRule Non‑String Format

Used for Integer and Timestamp comparisons, including “In the Last …” rules
which require a units value.  
Again, all multi‑byte values are **big‑endian**.

| Offset | Size | Name        | Type       | Notes                                                  |
|--------|------|-------------|------------|--------------------------------------------------------|
| 0      | 4    | field       | u32 BE     | Rule Field Type.                                      |
| 4      | 4    | action      | u32 BE     | Rule Action (bitmapped).                              |
| 8      | 44   | padding     | bytes      | Zero padding.                                         |
| 52     | 4    | length      | u32 BE     | Always `0x44` for non‑string rules.                   |
| 56     | 8    | from_value  | u64 BE     | “From” value (unsigned).                              |
| 64     | 8    | from_date   | i64 BE     | “From” date (signed).                                 |
| 72     | 8    | from_units  | u64 BE     | “From” units (unsigned).                              |
| 80     | 8    | to_value    | u64 BE     | “To” value (unsigned).                                |
| 88     | 8    | to_date     | i64 BE     | “To” date (signed).                                   |
| 96     | 8    | to_units    | u64 BE     | “To” units (unsigned).                                |
| 104    | 20   | unknown     | bytes      | Unknown; present for all field types.                 |

Non‑string rules are **not** zero‑padded at the end; the next rule (if any)
starts immediately after the last “unknown” byte.

For simple integer‑type rules (e.g., “Play Count is greater than N”):

- `from_value` and `to_value` contain the numeric bounds of interest.
- `from_date` / `to_date` are typically `0`.
- `from_units` / `to_units` are typically `1`.

Examples:

- **BPM is less than 150**  
  - Field = `0x23` (BPM)  
  - Action = `0x00000040` (“Is Less Than”)  
  - `from_value` = 150, `to_value` = 150  
  - `from_date`/`to_date` = 0  
  - `from_units`/`to_units` = 1  

- **BPM is in the range 70 to 150**  
  - Field = `0x23` (BPM)  
  - Action = `0x00000100` (“Is in the Range”)  
  - `from_value` = 70, `to_value` = 150  
  - `from_date`/`to_date` = 0  
  - `from_units`/`to_units` = 1  

For **binary‑AND rules** (Action `0x00000400`, e.g. “Video Kind is …”), the
important pieces are still `from_value` / `to_value`, with dates 0 and units 1.

Examples:

- **Video Kind is TV‑Show**  
  - Field = `0x3c` (Video Kind / `media_type`)  
  - Action = `0x00000400` (“Is / Is Not”, binary AND)  
  - `from_value` = `0x0040`, `to_value` = `0x0040`  
  - Dates = 0, Units = 1  

- **Video Kind is not TV‑Show**  
  - Field = `0x3c` (Video Kind / `media_type`)  
  - Action = `0x00000400` (“Is / Is Not”, binary AND)  
  - `from_value` = `0x0e22`, `to_value` = `0x0e22`  
  - Dates = 0, Units = 1  

Timestamp‑type rules (e.g. Date Added / Last Played) use the same integer
layout; the values are HFS timestamps (seconds since 1904‑01‑01).

Example:

- **Date Added is in the range 2004‑06‑19 to 2004‑06‑20**  
  - Field = `0x10` (Date Added)  
  - Action = `0x00000100` (“Is in the Range”)  
  - `from_value` = `0xbcfa83ff` (2004‑06‑19)  
  - `to_value` = `0xbcfbd57f` (2004‑06‑20)  
  - Dates = 0, Units = 1  

For “**In the Last**” rules (Action `0x00000200`), the **value** and **units**
fields work together:

- `from_value` / `to_value` = constant `0x2dae2dae2dae2dae`.  
- `from_date` encodes the number of periods back from “now” (often negative).  
- `from_units` encodes the size of the period (e.g., seconds in a week).  
- `to_value` = same sentinel, `to_date` = 0, `to_units` = 1.

Example:

- **Last Played is in the last 2 weeks**  
  - Field = `0x17` (Last Played)  
  - Action = `0x00000200` (“Is in the Last”)  
  - `from_value` = `0x2dae2dae2dae2dae`  
  - `from_date` = −2  
  - `from_units` = 604800 (seconds per week)  
  - `to_value` = `0x2dae2dae2dae2dae`, `to_date` = 0, `to_units` = 1  

Conceptually, comparisons work as:

- For integer/timestamp rules, compare the field against `(value + date * units)`.  
- If `value == 0x2dae2dae2dae2dae`, treat it as “now” and substitute the
  current timestamp before applying the formula.

### MHOD Type Map

The UI currently uses the following mapping (used when labelling nodes):

- `1` – Title  
- `2` – Location (file path / URL)  
- `3` – Album  
- `4` – Artist  
- `5` – Genre  
- `6` – Filetype (string form)  
- `7` – EQ Setting  
- `8` – Comment  
- `9` – Category  
- `12` – Composer  
- `13` – Grouping  
- `14` – Description  
- `15` – Enclosure URL  
- `16` – RSS URL  
- `17` – Chapter data  
- `18` – Subtitle  
- `19` – Show  
- `20` – Episode #  
- `21` – TV Network  
- `22` – Album Artist  
- `23` – Artist (sort)  
- `24` – Keywords  
- `25` – Locale  
- `27` – Title (sort)  
- `28` – Album (sort)  
- `29` – Album‑Artist (sort)  
- `30` – Composer (sort)  
- `31` – TV‑Show (sort)  
- `32` – Binary payload (non‑string)  
- `50` – Smart Playlist Data  
- `51` – Smart Playlist Rules  
- `52` – Library Playlist Index  
- `53` – Unknown (52‑like)  
- `100` – Playlist Order Entry / Order indicator  
- `200` – Album (album list context)  
- `201` – Artist (album list context)  
- `202` – Artist (sort, album list)  
- `203` – Podcast URL (album list)  
- `204` – TV Show (album list)  

The payload encoding (UTF‑8 vs UTF‑16LE vs local encoding) is not yet enforced;
the viewer currently displays raw bytes in ASCII with non‑printable bytes
mapped to `.`.

---

## Relationships Between Tags

High‑level containment relationships, as modeled by the viewer:

- `mhbd` – root database header; points to one or more `mhsd` datasets.
- `mhsd(type = 1)` – contains one `mhlt` (track list), which contains `mhit` track items and their `mhod` strings.
- `mhsd(type = 2/3)` – contains `mhlp` playlist list; this in turn contains `mhyp` playlist headers and `mhip` playlist items, each with `mhod` children.
- `mhsd(type = 4)` – contains `mhla` (album list) and `mhia` album items, each with string `mhod` children.

All offsets recorded in the parser are sufficient to rebuild the tree and, in
future, to support writing back a modified iTunesDB file.

---

## Notes and Open Questions

- Some `unk*` fields likely represent flags, counters, or padding that vary
  with iPod model and iTunes version.
- String encodings and exact charset handling are not yet fully specified.
- Smart playlist MHODs (`50`, `51`, `52`, `53`) are currently treated as opaque
  binary payloads.

As you expand the parser or confirm hypotheses with real devices, this README
can be updated with:

- Additional type maps and enumerations (e.g. `media_type` values).
- Proven field semantics replacing `unk*` names.
- Encoding rules for string payloads in `mhod` objects.
