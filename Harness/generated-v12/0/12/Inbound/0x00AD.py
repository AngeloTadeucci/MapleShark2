''' ItemUse '''
# Auto-generated (Phase 4a/4b) from ItemUsePacket: ExpandInventory, MaxInventory, CharacterSlotAdded, MaxCharacterSlots, QuestScroll, BeautyCoupon
from script_api import *

mode = add_byte("mode")
if mode == 0:  # ExpandInventory
    pass
elif mode == 1:  # MaxInventory
    pass
elif mode == 2:  # CharacterSlotAdded
    pass
elif mode == 3:  # MaxCharacterSlots
    pass
elif mode == 4:  # QuestScroll
    add_int("itemId")
elif mode == 6:  # BeautyCoupon
    add_int("playerObjectId")
    add_long("itemUid")
