''' UserMaid '''
# Auto-generated (Phase 4a/4b) from MaidPacket: Load, Add, Update, OpenDialog
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    # --- layout truncated: loop body unresolved (Maid: loop without a preceding scalar count) (no wire-safe continuation) ---
    pass
elif mode == 1:  # Add
    add_byte("Mode")
    add_long("MaidUid")
    add_long("ItemUid")
    add_long("MoodTimestamp")
    add_long("ClosenessTimestamp")
    add_long("AccountId")
    add_int("MaidId")
    add_int("NpcId")
    add_bool("IsDeployed")
    add_int("Mood")
    add_int("Closeness")
    add_int("ClosenessExp")
    add_long("ExpirationTimestamp")
    count = add_int("Items.Count")
    for i0 in range(count):
        add_long("item")
    # --- layout truncated: Maid: loop without a preceding scalar count (no wire-safe continuation) ---
elif mode == 3:  # Update
    add_byte("Mode")
    add_long("MaidUid")
    add_long("ItemUid")
    add_long("MoodTimestamp")
    add_long("ClosenessTimestamp")
    add_long("AccountId")
    add_int("MaidId")
    add_int("NpcId")
    add_bool("IsDeployed")
    add_int("Mood")
    add_int("Closeness")
    add_int("ClosenessExp")
    add_long("ExpirationTimestamp")
    count = add_int("Items.Count")
    for i0 in range(count):
        add_long("item")
    # --- layout truncated: Maid: loop without a preceding scalar count (no wire-safe continuation) ---
elif mode == 4:  # OpenDialog
    add_int("playerObjectId")
