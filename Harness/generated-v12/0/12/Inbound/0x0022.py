''' StorageInventory '''
# Auto-generated (Phase 4a/4b) from StorageInventoryPacket: Add, Remove, Move, UpdateMesos, SlotsUsed, Load, Reload, Update, Reset, SlotsExpanded, OpenDialog, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_long("Unknown")
    add_int("item.Id")
    add_long("item.Uid")
    add_short("item.Slot")
    add_int("item.Rarity")
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
    add_long("Unknown")
    add_long("uid")
elif mode == 2:  # Move
    add_long("Unknown")
    add_long("dstUid")
    add_short("srcSlot")
    add_long("srcUid")
    add_short("dstSlot")
elif mode == 3:  # UpdateMesos
    add_long("mesos")
elif mode == 4:  # SlotsUsed
    add_long("Unknown")
    add_short("slotsUsed")
elif mode == 5:  # Load
    add_long("Unknown")
    # --- layout truncated: loop body unresolved (Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
elif mode == 8:  # Reload
    add_long("Unknown")
    # --- layout truncated: loop body unresolved (Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
elif mode == 9:  # Update
    add_long("Unknown")
    add_long("uid")
    add_int("remaining")
elif mode == 11:  # Reset
    pass
elif mode == 13:  # SlotsExpanded
    add_int("expansion")
elif mode == 14:  # OpenDialog
    pass
elif mode == 16:  # Error
    add_int("error")
