''' RoomStageDungeon '''
# Auto-generated (Phase 4a) from RoomStageDungeonPacket: LoadMissionPanel, ClearMissionPanel
from script_api import *

mode = add_byte("mode")
if mode == 0:  # LoadMissionPanel
    add_int("dungeonId")
    add_byte("unknown (stored at DungeonMissionPanel+0x28, no known reads)")
    add_bool("abandonEnabled")
    add_int("dungeonId")
elif mode == 1:  # ClearMissionPanel
    add_int("dungeonId")
