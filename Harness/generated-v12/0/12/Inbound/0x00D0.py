''' PetInventory '''
# Auto-generated (Phase 4a/4b) from PetInventoryPacket: Add, Remove, Update, Move, Load, Reset
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
elif mode == 2:  # Update
    add_long("uid")
    add_int("amount")
elif mode == 3:  # Move
    add_long("dstUid")
    add_short("srcSlot")
    add_long("srcUid")
    add_short("dstSlot")
elif mode == 4:  # Load
    # --- layout truncated: loop body unresolved (Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
    pass
elif mode == 6:  # Reset
    pass
