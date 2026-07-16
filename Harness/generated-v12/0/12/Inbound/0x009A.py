''' BlackMarket '''
# Auto-generated (Phase 4a/4b) from BlackMarketPacket: Error, MyListings, Add, Remove, Search, Purchase, PurchaseResponse, Preview
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Error
    add_byte("Unknown")
    add_int("error")
    add_long("Unknown")
    add_int("arg1")
    add_int("arg2")
elif mode == 1:  # MyListings
    # --- layout truncated: loop body unresolved (BlackMarketListing: Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
    pass
elif mode == 2:  # Add
    add_long("Id")
    add_long("CreationTime")
    add_long("CreationTime")
    add_long("ExpiryTime")
    add_int("Item.Amount")
    add_int("Unknown")
    add_long("Price")
    add_bool("false")
    add_long("Item.Uid")
    add_int("Item.Id")
    add_byte("Item.Rarity")
    add_long("AccountId")
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
    # --- layout truncated: BlackMarketListing: Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT' (no wire-safe continuation) ---
elif mode == 3:  # Remove
    add_long("listingId")
    add_byte("Unknown")
elif mode == 4:  # Search
    # --- layout truncated: loop body unresolved (BlackMarketListing: Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
    pass
elif mode == 5:  # Purchase
    add_long("listingId")
    add_int("amount")
elif mode == 7:  # PurchaseResponse
    pass
elif mode == 8:  # Preview
    add_int("itemId")
    add_int("rarity")
    add_long("npcPrice")
