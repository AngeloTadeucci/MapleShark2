''' ItemEnchant '''
# Auto-generated (Phase 4a/4b) from ItemEnchantPacket: StageItem, UpdateExp, UpdateCharges, UpdateFodder, Refund, Success, Failure, Error, UpdateItem, AutoAddIngredients
from script_api import *

mode = add_byte("mode")
if mode == 5:  # StageItem
    add_short("type")
    add_long("item.Uid")
    count = add_byte("catalysts.Count")
    for i0 in range(count):
        add_field("catalyst", 12)
    add_short("EnchantFailType.None")
    count = add_int("statDeltas.Count")
    for i0 in range(count):
        add_short("attribute")
        add_field("delta", 8)
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 6:  # UpdateExp
    add_long("itemUid")
    add_int("exp")
elif mode == 7:  # UpdateCharges
    add_int("charges")
    add_int("fodderWeight")
    count = add_int("fodder.Count")
    for i0 in range(count):
        add_long("itemUid")
    add_float("Success")
    add_float("Unknown")
    add_float("Unknown")
    add_float("Fodder")
    add_float("Charge")
elif mode == 8:  # UpdateFodder
    add_int("fodder.Count")
    count = add_int("fodder.Count")
    for i0 in range(count):
        add_long("ingredient")
elif mode == 9:  # Refund
    pass
elif mode == 10:  # Success
    add_long("item.Uid")
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
elif mode == 11:  # Failure
    add_long("item.Uid")
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
elif mode == 12:  # Error
    add_short("error")
elif mode == 15:  # UpdateItem
    add_long("item.Uid")
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
elif mode == 16:  # AutoAddIngredients
    pass
