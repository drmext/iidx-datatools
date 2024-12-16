# beatmania IIDX omnimix converter/creator

## Supported Versions
- 27 HEROIC VERSE
- 28 BISTROVER
- 29 CastHour
- 30 RESIDENT
- 31 EPOLIS
- 32 PINKY CRUSH

*Standalone [music database editor](musicdata_tool.py) supports 20<->32+

## Usage
1. `pip install -U -r requirements.txt`
2. Copy required files to this root directory: (WARNING: deleted when done!)
- (NEW VERSION BASE `bm2dx.dll`, `mdata.ifs`, `music_artist_yomi.xml`, `music_data.bin`, `music_title_yomi.xml`, `video_music_list.xml`)
- (OLD VERSION OMNI `mdato.ifs`, `music_omni.bin`)
3. Run `python build_omnimix.py`
4. Copy the resulting output/`data` to game contents
- [BemaniPatcher scripts](https://github.com/drmext/BemaniPatcher/tree/master/docs) and [mempatch_hook script](mem_patch.py) are deprecated. Fix it yourself for 31+.
5. Copy dummied sound and movie files from old base data

## Extras
[parse_webui_strings.py](parse_webui_strings.py) outputs debug info in bm2dx.dll to json

- qpro part real titles (removed in version 31+)
- sd9 system sound real titles
- region names (Japanese and truncated English)
- setting names (notes, frame, explosion, turntable, fullcombo, keybeam, judgestring, lanecover, categoryvoice, musicselectbgm, kokokara start)

[parse_chart_notecounts.py](parse_chart_notecounts.py) outputs json for score grade calculation

- supports .ifs files directly and loose .1 files in directories

[ida_mdb_limit_patch_finder.py](ida_mdb_limit_patch_finder.py) hex-rays IDA py script finds hex edits for bm2dx.dll to increase the music_data.bin size limit

- new required for version 32+. extend this to do the entire omni patch set yourself! glhf!
