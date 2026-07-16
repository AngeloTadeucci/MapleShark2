''' ItemRepackage '''
# Auto-generated (Phase 4a/4b) from ItemRepackPacket: Open, Commit, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Open
    add_long("itemUid")
elif mode == 2:  # Commit
    add_short("Unknown")
    add_long("item.Uid")
    add_int("Amount")
    add_int("Unknown")
    add_int("-1")
    add_long("CreationTime")
    add_long("ExpiryTime")
    add_long("Unknown")
    add_int("TimeChangedOption")
    add_int("RemainUses")
    add_bool("IsLocked")
    add_long("UnlockTime")
    add_short("GlamorForges")
    add_bool("false")
    add_int("GachaDismantleId")
    add_field("Color", 20)
    add_byte("Unknown")
    # --- layout truncated: Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT' (no wire-safe continuation) ---
elif mode == 3:  # Error
    add_byte("Unknown")
    add_int("error")
