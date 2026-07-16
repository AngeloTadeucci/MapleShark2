''' DarkStream '''
# Auto-generated (Phase 4a/4b) from DarkStreamPacket: OpenScore, SetScore, Results
from script_api import *

mode = add_byte("mode")
if mode == 0:  # OpenScore
    pass
elif mode == 1:  # SetScore
    add_int("score")
elif mode == 2:  # Results
    add_int("score")
    add_int("result2")
    add_int("exp")
    add_int("meso")
    add_int("havi")
    count = add_byte("items.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_short("item.Rarity")
        add_int("item.Amount")
        add_bool("item.TradableCountDeduction")
        add_bool("item.RepackingLimitCountDeduction")
        add_bool("item.BindCharacter")
        add_bool("item.DisableBreak")
