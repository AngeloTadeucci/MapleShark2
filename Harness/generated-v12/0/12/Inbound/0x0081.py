''' BadgeEquip '''
# Auto-generated (Phase 4a/4b) from EquipPacket: EquipBadge, UnequipBadge
from script_api import *

mode = add_byte("mode")
if mode == 0:  # EquipBadge
    add_int("player.ObjectId")
    add_int("item.Id")
    add_long("item.Uid")
    add_int("item.Rarity")
    add_byte("item.Badge?.Type ?? BadgeType.None")
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
elif mode == 1:  # UnequipBadge
    add_int("player.ObjectId")
    add_byte("slot")
