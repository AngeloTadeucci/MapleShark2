''' Lapenshard '''
# Auto-generated (Phase 4a/4b) from LapenshardPacket: Load, Equip, Unequip, Preview, Upgrade
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("slot")
        add_int("id")
elif mode == 1:  # Equip
    add_int("slot")
    add_int("id")
elif mode == 2:  # Unequip
    add_int("slot")
elif mode == 4:  # Preview
    add_int("10000")
elif mode == 5:  # Upgrade
    add_long("uid")
    add_int("id")
    add_int("slot")
    add_bool("success")
