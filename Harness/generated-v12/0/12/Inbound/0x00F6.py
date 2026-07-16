''' LegionBattle '''
# Auto-generated (Phase 4a/4b) from LegionBattlePacket: Load, Update
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_short("bosses.Count")
    for i0 in range(count):
        add_int("metadata.Id")
        add_int("metadata.NpcIds.Length > 0 ? metadata.NpcIds[0]")
        add_long("WorldBossUtil.ComputeNextSpawnTimestamp(metadata")
elif mode == 1:  # Update
    add_int("eventId")
    add_int("npcId")
    add_long("nextSpawnTimestamp")
