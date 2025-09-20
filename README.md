# beatmania IIDX omnimix converter/creator

## Supported Versions
- 27 HEROIC VERSE
- 28 BISTROVER
- 29 CastHour
- 30 RESIDENT
- 31 EPOLIS
- 32 Pinky Crush
- 33 Sparkle Shower

*Standalone [music database editor](musicdata_tool.py) supports 20<->33+

## Usage
1. `pip install -U -r requirements.txt`
2. Copy required files to this root directory: (WARNING: deleted when done!)
- (NEW VERSION BASE `music_data.bin`, `mdata.ifs`, `music_artist_yomi.xml`, `music_title_yomi.xml`, `video_music_list.xml`)
- (OLD VERSION OMNI `music_omni.bin`, `mdato.ifs`)
3. Run `python build_omnimix.py`
4. Copy the resulting output/`data` to game contents ([ifs_hook.dll](https://github.com/mon/ifs_layeredfs) is recommended)
- Use [omnifix.dll](https://github.com/aixxe/omnifix) hook to automatically apply necessary patches to the game
5. Copy dummied graphic/movie/sound files (256 bytes) from old base data
