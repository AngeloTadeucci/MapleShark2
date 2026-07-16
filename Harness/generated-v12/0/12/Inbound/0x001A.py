''' RoomDungeon '''
# Auto-generated (Phase 4a/4b) from DungeonRoomPacket: Load, Update, Modify, DungeonResult, Error, RankRewards
from script_api import *

mode = add_byte("mode")
if mode == 5:  # Load
    count = add_int("records.Count")
    for i0 in range(count):
        add_int("dungeonId")
        add_int("DungeonId")
        add_long("UnionCooldownTimestamp")
        add_byte("UnionClears")
        add_byte("UnionSubClears")
        add_long("UnionSubCooldownTimestamp")
        add_byte("ExtraSubClears")
        add_byte("ExtraClears")
        add_long("ClearTimestamp")
        add_int("TotalClears")
        add_short("LifetimeRecord")
        add_long("CooldownTimestamp")
        add_short("CurrentRecord")
        add_byte("Flag")
elif mode == 6:  # Update
    add_int("DungeonId")
    add_long("UnionCooldownTimestamp")
    add_byte("UnionClears")
    add_byte("UnionSubClears")
    add_long("UnionSubCooldownTimestamp")
    add_byte("ExtraSubClears")
    add_byte("ExtraClears")
    add_long("ClearTimestamp")
    add_int("TotalClears")
    add_short("LifetimeRecord")
    add_long("CooldownTimestamp")
    add_short("CurrentRecord")
    add_byte("Flag")
elif mode == 7:  # Modify
    add_byte("modifyType")
    add_int("dungeonId")
elif mode == 11:  # DungeonResult
    add_byte("result")
    count = add_int("statistics.Count")
    for i0 in range(count):
        add_long("userResult.CharacterId")
        add_int("userResult.MissionRank")
        add_int("userResult.RecordType")
        add_int("userResult.Value")
elif mode == 19:  # Error
    add_int("error")
    add_int("arg")
elif mode == 20:  # RankRewards
    count = add_int("rankRewards.Count")
    for i0 in range(count):
        add_int("id")
        add_int("Id")
        add_int("RankClaimed")
        add_long("UpdatedTimestamp")
