''' ItemScript '''
# Auto-generated (Phase 4a/4b) from ItemScriptPacket: LulluBox, TreasureChest, Gacha
from script_api import *

mode = add_byte("mode")
if mode == 0:  # LulluBox
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.Id")
        add_int("item.Amount")
        add_int("item.Rarity")
        add_bool("true")
elif mode == 4:  # TreasureChest
    add_int("itemId")
elif mode == 5:  # Gacha
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.Id")
        add_int("item.Amount")
        add_int("item.Rarity")
        add_bool("true")
