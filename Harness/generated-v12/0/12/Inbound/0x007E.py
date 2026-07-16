''' BonusGame '''
# Auto-generated (Phase 4a/4b) from BonusGamePacket: Load, Spin
from script_api import *

mode = add_byte("mode")
if mode == 1:  # Load
    add_byte("Unknown")
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_byte("item.Rarity")
        add_int("item.Amount")
    add_int("Unknown")
elif mode == 2:  # Spin
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.Value")
        add_int("item.Key.Id")
        add_int("item.Key.Amount")
        add_short("item.Key.Rarity")
