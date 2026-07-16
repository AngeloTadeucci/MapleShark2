''' DungeonMission '''
# Auto-generated (Phase 4a/4b) from DungeonMissionPacket: Load, Update, Sync, SetAbandon, Giveup
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_int("missions.Count")
    for i0 in range(count):
        add_int("Id")
        add_short("Score")
        add_short("Counter")
elif mode == 1:  # Update
    count = add_int("missions.Length")
    for i0 in range(count):
        add_int("Id")
        add_short("Score")
        add_short("Counter")
elif mode == 2:  # Sync
    count = add_int("missions.Length")
    for i0 in range(count):
        add_int("Id")
        add_short("Score")
        add_short("Counter")
elif mode == 4:  # SetAbandon
    add_bool("enable")
elif mode == 5:  # Giveup
    pass
