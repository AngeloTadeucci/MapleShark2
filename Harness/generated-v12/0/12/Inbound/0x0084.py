''' Trade '''
# Auto-generated (Phase 4a/4b) from TradePacket: Request, Error, Acknowledge, Decline, StartTrade, EndTrade, AddItem, RemoveItem, SetMesos, Finalize, UnFinalize, Complete, AlreadyRequest
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Request
    add_unicode_str("player.Character.Name")
    add_long("player.Character.Id")
elif mode == 1:  # Error
    add_byte("error")
    add_unicode_str("name")
    add_int("itemId")
    add_int("level")
elif mode == 2:  # Acknowledge
    pass
elif mode == 4:  # Decline
    add_unicode_str("name")
elif mode == 5:  # StartTrade
    add_long("characterId")
elif mode == 6:  # EndTrade
    add_bool("success")
elif mode == 8:  # AddItem
    add_bool("isSelf")
    add_int("item.Id")
    add_long("item.Uid")
    add_int("item.Rarity")
    add_int("item.Slot")
    add_int("item.Amount")
    add_int("item.Slot")
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
elif mode == 9:  # RemoveItem
    add_bool("isSelf")
    add_int("tradeSlot")
    add_long("itemUid")
elif mode == 10:  # SetMesos
    add_bool("isSelf")
    add_long("mesos")
elif mode == 11:  # Finalize
    add_bool("isSelf")
elif mode == 12:  # UnFinalize
    add_bool("isSelf")
elif mode == 13:  # Complete
    add_bool("isSelf")
elif mode == 14:  # AlreadyRequest
    pass
