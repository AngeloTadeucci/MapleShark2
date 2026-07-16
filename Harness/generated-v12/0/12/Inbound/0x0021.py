''' ItemInventory '''
# Auto-generated (Phase 4a/4b) from ItemInventoryPacket: Add, Remove, UpdateAmount, Move, Load, NotifyNew, LoadTab, ExpandComplete, Reset, ExpandCount, Error, UpdateItem
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_int("item.Id")
    add_long("item.Uid")
    add_short("item.Slot")
    add_int("item.Rarity")
    add_unicode_str("Unknown")
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
elif mode == 1:  # Remove
    add_long("uid")
elif mode == 2:  # UpdateAmount
    add_long("uid")
    add_int("amount")
elif mode == 3:  # Move
    add_long("srcUid")
    add_short("srcSlot")
    add_long("dstUid")
    add_short("dstSlot")
elif mode == 7:  # Load
    # --- layout truncated: loop body unresolved (Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
    pass
elif mode == 8:  # NotifyNew
    add_long("uid")
    add_int("amount")
    add_unicode_str("Unknown")
elif mode == 10:  # LoadTab
    add_int("type")
    # --- layout truncated: loop body unresolved (Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
elif mode == 12:  # ExpandComplete
    pass
elif mode == 13:  # Reset
    add_int("type")
elif mode == 14:  # ExpandCount
    add_byte("type")
    add_int("expansion")
elif mode == 15:  # Error
    add_int("error")
elif mode == 16:  # UpdateItem
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
