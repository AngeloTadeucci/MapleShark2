''' SystemShop '''
# Auto-generated (Phase 4a/4b) from SystemShopPacket: Arena, Fishing, Mentee, Mentor, Item
from script_api import *

mode = add_byte("mode")
if mode == 3:  # Arena
    add_bool("true")
elif mode == 4:  # Fishing
    add_bool("true")
elif mode == 6:  # Mentee
    add_bool("true")
elif mode == 7:  # Mentor
    add_bool("true")
elif mode == 10:  # Item
    add_bool("true")
