''' ItemPutOn '''
# Auto-generated (Phase 4a/4b) from EquipPacket: EquipItem
from script_api import *

add_int("player.ObjectId")
add_int("item.Id")
add_long("item.Uid")
add_unicode_str("item.EquipSlot().ToString()")
add_int("item.Rarity")
add_byte("type")
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
