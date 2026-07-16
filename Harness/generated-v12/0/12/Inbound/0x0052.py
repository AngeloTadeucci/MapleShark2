''' Shop '''
# Auto-generated (Phase 4a/4b) from ShopPacket: Open, LoadItems, Update, Buy, BuyBackItemCount, LoadBuyBackItem, RemoveBuyBackItem, InstantRestock, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Open
    add_int("npcId")
    add_int("Id")
    add_long("RestockTime")
    add_int("Unknown")
    add_short("Items.Count")
    add_int("Metadata.CategoryId")
    add_bool("Metadata.OpenWallet")
    add_bool("Metadata.IsOnlySell")
    add_bool("Metadata.EnableReset")
    add_bool("Metadata.DisableDisplayOrderSort")
    add_byte("Metadata.FrameType")
    add_bool("Metadata.DisplayOnlyUsable")
    add_bool("Metadata.HideStats")
    add_bool("false")
    add_bool("Metadata.DisplayNew")
    add_str("Metadata.Name")
    # --- layout truncated: Shop: if (no wire-safe continuation) ---
elif mode == 1:  # LoadItems
    # --- layout truncated: loop body unresolved (ShopItem: if) (no wire-safe continuation) ---
    pass
elif mode == 2:  # Update
    add_int("id")
    add_int("totalQuantityPurchased")
elif mode == 4:  # Buy
    add_int("shopItem.Metadata.ItemId")
    add_int("totalItems")
    add_int("totalPrice")
    add_byte("shopItem.Metadata.Rarity")
    add_bool("toGuildStorage")
elif mode == 6:  # BuyBackItemCount
    add_short("itemCount")
elif mode == 7:  # LoadBuyBackItem
    # --- layout truncated: loop body unresolved (BuyBackItem: Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
    pass
elif mode == 8:  # RemoveBuyBackItem
    add_int("buyBackId")
elif mode == 9:  # InstantRestock
    add_bool("unknown")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 15:  # Error
    add_int("error")
    add_byte("arg1")
    add_int("arg2")
