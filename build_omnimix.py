import json
import shutil
from pathlib import Path

import ifstools

import create_texturelist
import mem_patch
import musicdata_tool
import yomi_xml

required = [
    "mdata.ifs",
    "mdato.ifs",
    "music_artist_yomi.xml",
    "music_data.bin",
    "music_omni.bin",
    "music_title_yomi.xml",
    "video_music_list.xml",
]
missing = []
for file in required:
    if not Path(file).exists():
        missing.append(file)
if missing:
    raise SystemExit("MISSING REQUIRED FILES:\n" + "\n".join(map(str, missing)))

output = "output"
if Path(output).exists():
    raise SystemExit(f"DELETE OR MOVE OLD OUTPUT FOLDER: {output}/")

musicdata_tool.extract_file("music_omni.bin", "music_omni.json")
musicdata_tool.extract_file("music_data.bin", "music_data.json")

with open("music_omni.json", "r", encoding="utf-8") as f:
    music_omni = json.load(f)
with open("music_data.json", "r", encoding="utf-8") as f:
    music_data = json.load(f)

game_version = music_data["data_ver"]

ver = "0" if game_version % 2 == 0 else "1"

Path(output, "data", "info", ver).mkdir(parents=True, exist_ok=True)
Path(output, "data", "graphic", ver).mkdir(parents=True, exist_ok=True)

if Path("bm2dx.dll").exists():
    if game_version < 31:
        print("Processing bm2dx.dll patches")
        mem_patch.create_patch(
            "bm2dx.dll", Path(output, f"iidx_omnimix_{game_version}.txt")
        )
    else:
        print(f"Skipping bm2dx.dll version {game_version} patches")
    Path("bm2dx.dll").unlink()

print(f"Processing music_omni_{game_version-1} json")
music_omni.update({"data_ver": game_version})

new_entries = {}
new_titles = []
for i in music_data["data"]:
    new_entries[i["song_id"]] = i
    new_titles.append(i["title"])

delete_entries = [22091, 27004]
for old_entry in music_omni["data"]:
    if old_entry["song_id"] in new_entries.keys():
        new_entry = new_entries[old_entry["song_id"]]
        # new or revived leggendaria
        for i in ["SPL_level", "DPL_level"]:
            if old_entry[i] < new_entry[i]:
                delete_entries.append(old_entry["song_id"])
            if (
                old_entry[i] != 0
                and new_entry[i] != 0
                and old_entry["SPL_ident"] != new_entry["SPL_ident"]
                and old_entry["DPL_ident"] != new_entry["DPL_ident"]
            ):
                delete_entries.append(old_entry["song_id"])

        # new beginner
        for i in ["SPB_level", "DPB_level"]:
            if old_entry[i] == 0 and new_entry[i] != 0:
                delete_entries.append(old_entry["song_id"])

        # difficulty changes
        for i in [
            "SPN_level",
            "SPH_level",
            "SPA_level",
            "DPN_level",
            "DPH_level",
            "DPA_level",
        ]:
            if (
                old_entry[i] == 0
                and old_entry[i] != new_entry[i]
                or old_entry[i] - new_entry[i] == 1
                or new_entry[i] - old_entry[i] == 1
            ):
                delete_entries.append(old_entry["song_id"])

    # revivals
    if (
        old_entry["song_id"] not in new_entries.keys()
        and old_entry["title"] in new_titles
    ):
        delete_entries.append(old_entry["song_id"])

    # match original
    # this breaks automating new or revived leggendaria
    # if using the resulting music_omni.bin in the future
    def fix_ident(difficulty):
        if old_entry[difficulty] == 0:
            old_entry.update({difficulty: 48})

    # fix_ident('SPB_ident')
    # fix_ident('SPL_ident')
    # fix_ident('DPB_ident')
    # fix_ident('DPL_ident')

    # new old overlays
    if game_version < 30:
        if old_entry["song_id"] in [
            1001,
            1008,
            2003,
            2008,
            2011,
            2201,
            2203,
            2209,
            3011,
            3012,
        ]:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "3030000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] in [
            1000,
            1002,
            1005,
            1006,
            1007,
            1009,
            1010,
            1011,
            1012,
            1015,
            1018,
            1019,
            1020,
            1204,
            1208,
            1212,
            1213,
            2001,
            2004,
            2007,
            2009,
            2010,
            2012,
            2014,
            2016,
            2205,
            3001,
            3016,
            3018,
            3203,
            3209,
            4015,
            4016,
            4021,
            4203,
            5001,
            5002,
            5203,
            6004,
            6011,
            6201,
            6203,
            7007,
            7009,
            7014,
            7030,
            7032,
            7035,
        ]:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "3030000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3032000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] in [
            3000,
            3003,
            3005,
            4017,
            5008,
            5015,
            5025,
            6009,
            6022,
            7017,
            7018,
            7026,
            12032,
            13020,
            13036,
            13042,
            16012,
            17018,
        ]:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "3030000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3032000000000000000000000000000000000000000000000000000000000000",
                        "3033000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] in [
            1003,
            1016,
            1207,
            1214,
            1216,
            2000,
            2002,
            2005,
            2006,
            3002,
            3008,
            3013,
            3015,
            3208,
            4018,
            5011,
            5013,
            5020,
            5026,
            6026,
            6027,
            7002,
            7010,
            7037,
            7039,
            12024,
            12048,
            13004,
            13007,
            15034,
        ]:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "3030000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3032000000000000000000000000000000000000000000000000000000000000",
                        "3033000000000000000000000000000000000000000000000000000000000000",
                        "3034000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] == 4011:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3032000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] in [3213, 4010, 11001]:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3032000000000000000000000000000000000000000000000000000000000000",
                        "3033000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] in [4208, 9040]:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3032000000000000000000000000000000000000000000000000000000000000",
                        "3033000000000000000000000000000000000000000000000000000000000000",
                        "3034000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )
        
        elif old_entry["song_id"] == 11042:
            old_entry.update({"afp_flag": 2})
            old_entry.update(
                {
                    "afp_data": [
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "3031000000000000000000000000000000000000000000000000000000000000",
                        "3033000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    ],
                }
            )

music_omni["data"][:] = [
    entry
    for entry in music_omni["data"]
    if entry["song_id"] not in sorted(list(set(delete_entries)))
]

json.dump(
    music_omni,
    open("music_omni.json", "w", encoding="utf8"),
    indent=4,
    ensure_ascii=False,
)


print(f"Processing music_omni_{game_version} bin")
musicdata_tool.create_file(
    "music_omni.json", Path(output, "data", "info", ver, "music_omni.bin"), game_version
)

Path("music_data.json").unlink()

if Path("uminf.json").exists():
    musicdata_tool.create_file("uminf.json", "uminf.bin", game_version)
    musicdata_tool.merge_files(
        "uminf.bin",
        Path(output, "data", "info", ver, "music_omni.bin"),
        Path(output, "data", "info", ver, "music_omni.bin"),
    )
    Path("uminf.bin").unlink()

musicdata_tool.merge_files(
    "music_data.bin",
    Path(output, "data", "info", ver, "music_omni.bin"),
    Path(output, "data", "info", ver, "music_omni.bin"),
)

musicdata_tool.merge_files(
    Path(output, "data", "info", ver, "music_omni.bin"),
    "music_data.bin",
    "music_data.bin",
    True,
)

Path("music_data_diff.bin").replace(Path(output, "data", "info", ver, "music_diff.bin"))


print("Processing video flags and yomigana xml")
yomi_xml.process(
    "video_music_list.xml",
    "music_title_yomi.xml",
    "music_artist_yomi.xml",
    str(Path(output, "data", "info", ver, "music_diff.bin")),
)


def convert_to_crlf(input_filename, output_filename):
    with open(input_filename, "rb") as input:
        with open(output_filename, "wb") as output:
            output.write(input.read().replace(b"\n", b"\r\n"))


# convert_to_crlf(
#    "video_music_omni.xml", Path(output, "data", "info", ver, "video_music_omni.xml")
# )
convert_to_crlf(
    "music_title_omni.xml", Path(output, "data", "info", ver, "music_title_omni.xml")
)
convert_to_crlf(
    "music_artist_omni.xml", Path(output, "data", "info", ver, "music_artist_omni.xml")
)

Path("video_music_omni.xml").replace(
    Path(output, "data", "info", ver, "video_music_omni.xml")
)
Path("music_title_omni.xml").unlink()
Path("music_artist_omni.xml").unlink()

Path("music_omni.bin").unlink()
Path("music_data.bin").unlink()
Path("music_omni.json").unlink()

Path("video_music_list.xml").unlink()
Path("music_title_yomi.xml").unlink()
Path("music_artist_yomi.xml").unlink()


print("Processing mdata ifs")


def extract_ifs(file):
    ifs = ifstools.IFS(file)
    ifs.extract(progress=False, recurse=False, path="mdato")
    ifs.close()


extract_ifs("mdato.ifs")
extract_ifs("mdata.ifs")

Path("mdato.ifs").unlink()
Path("mdata.ifs").unlink()

create_texturelist.create_texturelist(
    Path("mdato", "tex"), Path("mdato", "tex", "texturelist.xml")
)

ifstools.IFS("mdato").repack(
    progress=False,
    use_cache=True,
    path=Path(output, "data", "graphic", ver, "mdato.ifs"),
)
# memory patch for mdat`o` broke
# shutil.copy(
#    str(Path(output, "data", "graphic", ver, "mdato.ifs")),
#    str(Path(output, "data", "graphic", ver, "mdata.ifs")),
# )

shutil.rmtree("mdato")


print()
print("DONE!")
