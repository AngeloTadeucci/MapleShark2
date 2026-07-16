''' Mastery '''
# Auto-generated (Phase 4a/4b) from MasteryPacket: UpdateMastery, ClaimReward, GetCraftedItem, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # UpdateMastery
    add_byte("type")
    add_int("currentValue")
    add_int("maxValue")
elif mode == 1:  # ClaimReward
    add_int("rewardBoxDetails")
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_short("item.Rarity")
elif mode == 2:  # GetCraftedItem
    add_short("type")
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_short("item.Rarity")
elif mode == 3:  # Error
    add_short("error")
