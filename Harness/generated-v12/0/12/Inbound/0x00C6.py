''' Fishing '''
# Auto-generated (Phase 4a/4b) from FishingPacket: Prepare, Stop, Error, IncreaseMastery, LoadTiles, CatchItem, PrizeFish, LoadAlbum, CatchFish, Start, Auto, Simulate
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Prepare
    add_long("rodUid")
elif mode == 1:  # Stop
    pass
elif mode == 2:  # Error
    add_short("error")
elif mode == 3:  # IncreaseMastery
    add_int("fishId")
    add_int("exp")
    add_short("fishType")
    add_short("level")
elif mode == 4:  # LoadTiles
    add_byte("Unknown")
    count = add_int("tiles.Count")
    for i0 in range(count):
        add_field("Position", 4)
        add_int("FishId")
        add_int("Unknown1")
        add_int("BoreTime")
        add_short("Unknown2")
elif mode == 5:  # CatchItem
    count = add_int("rewards.Count")
    for i0 in range(count):
        add_int("item.Id")
        add_int("item.Amount")
elif mode == 6:  # PrizeFish
    add_unicode_str("playerName")
    add_int("fishId")
    add_int("Unknown")
elif mode == 7:  # LoadAlbum
    count = add_int("fishAlbum.Count")
    for i0 in range(count):
        add_int("Id")
        add_int("TotalCaught")
        add_int("TotalPrizeFish")
        add_int("LargestSize")
elif mode == 8:  # CatchFish
    add_int("id")
    add_int("size")
    add_bool("fish != null")
    add_bool("autoFish")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 9:  # Start
    add_bool("miniGame")
    add_int("durationTick")
elif mode == 10:  # Auto
    add_bool("autoFish")
elif mode == 11:  # Simulate
    count = add_int("results.Count")
    for i0 in range(count):
        add_int("result.FishId")
        add_int("result.PickCount")
        add_int("result.CatchCount")
        add_int("result.SmallCount")
        add_int("result.MediumCount")
        add_int("result.BigCount")
        add_int("result.PrizeCount")
