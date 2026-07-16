''' FurnishingStorage '''
# Auto-generated (Phase 4a/4b) from FurnishingStoragePacket: StartList, Count, Add, Remove, Purchase, Update, EndList
from script_api import *

mode = add_byte("mode")
if mode == 1:  # StartList
    pass
elif mode == 2:  # Count
    add_int("count")
elif mode == 3:  # Add
    add_int("item.Id")
    add_long("item.Uid")
    add_byte("item.Rarity")
    add_int("item.Slot")
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
elif mode == 4:  # Remove
    add_long("itemUid")
elif mode == 5:  # Purchase
    add_long("itemUid")
    add_int("amount")
elif mode == 7:  # Update
    add_long("itemUid")
    add_int("amount")
elif mode == 8:  # EndList
    pass
