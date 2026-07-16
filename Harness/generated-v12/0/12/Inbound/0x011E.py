''' Prestige '''
# Auto-generated (Phase 4a/4b) from PrestigePacket: Load, AddExp, LevelUp, ClaimReward, UpdateMissions, LoadMissions
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_long("account.PrestigeCurrentExp")
    add_int("account.PrestigeLevel - account.PrestigeLevelsGa")
    add_long("account.PrestigeExp")
    count = add_int("account.PrestigeRewardsClaimed.Count")
    for i0 in range(count):
        add_int("level")
elif mode == 1:  # AddExp
    add_long("currentExp")
    add_long("gainedExp")
elif mode == 2:  # LevelUp
    add_int("playerObjectId")
    add_int("level")
elif mode == 4:  # ClaimReward
    add_byte("1")
    add_int("1")
    add_int("level")
elif mode == 6:  # UpdateMissions
    add_bool("true")
    count = add_int("account.PrestigeMissions.Count")
    for i0 in range(count):
        add_long("Id")
        add_long("GainedLevels")
        add_bool("Awarded")
elif mode == 7:  # LoadMissions
    count = add_int("account.PrestigeMissions.Count")
    for i0 in range(count):
        add_long("Id")
        add_long("GainedLevels")
        add_bool("Awarded")
