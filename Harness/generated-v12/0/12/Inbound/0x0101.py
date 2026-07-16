''' RoomStageDungeon '''
# Auto-generated (Phase 4a/4b) from RoomStageDungeonPacket: LoadMissionPanel, ClearMissionPanel
from script_api import *

mode = add_byte("mode")
if mode == 0:  # LoadMissionPanel
    add_int("dungeonId")
    add_byte("Unknown")
    add_bool("abandonEnabled")
    add_int("dungeonId")
elif mode == 1:  # ClearMissionPanel
    add_int("dungeonId")
