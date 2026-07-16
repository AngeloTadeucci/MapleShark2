''' Wardrobe '''
# Auto-generated (Phase 4a/4b) from WardrobePacket: Load
from script_api import *

add_byte("mode")
add_int("index")
add_int("Type")
add_int("KeyId")
add_unicode_str("Name")
count = add_int("Equips.Count")
for i0 in range(count):
    add_long("equip.ItemUid")
    add_int("equip.ItemId")
    add_int("equip.EquipSlot - 1")
    add_int("equip.Rarity")
