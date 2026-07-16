''' Beauty '''
# Auto-generated (Phase 4a/4b) from BeautyPacket: BeautyShop, DyeShop, SaveShop, Error, Voucher, RandomHair, RandomHairResult, StartList, ListCount, ListHair, SaveHair, DeleteHair, SaveSlots, ApplySavedHair
from script_api import *

mode = add_byte("mode")
if mode == 0:  # BeautyShop
    add_byte("Type")
    add_int("Id")
    add_int("Metadata.Category")
    add_int("Metadata.CouponId")
    add_byte("Unknown")
    add_int("Metadata.ReturnCouponId")
    add_int("Metadata.SubType")
    add_byte("Unknown")
    add_byte("Metadata.CurrencyType")
    add_int("Metadata.PaymentItemId")
    add_int("Metadata.Price")
    add_str("Metadata.Icon")
    add_byte("Metadata.CurrencyType")
    add_int("Metadata.PaymentItemId")
    add_int("Metadata.Price")
    add_str("Metadata.Icon")
    # --- layout truncated: pWriter.WriteBeautyShopItems (opaque write) (no wire-safe continuation) ---
elif mode == 1:  # DyeShop
    add_byte("Type")
    add_int("Id")
    add_int("Metadata.Category")
    add_int("Metadata.CouponId")
    add_byte("Unknown")
    add_int("Metadata.ReturnCouponId")
    add_int("Metadata.SubType")
    add_byte("Unknown")
    add_byte("Metadata.CurrencyType")
    add_int("Metadata.PaymentItemId")
    add_int("Metadata.Price")
    add_str("Metadata.Icon")
    add_byte("Metadata.CurrencyType")
    add_int("Metadata.PaymentItemId")
    add_int("Metadata.Price")
    add_str("Metadata.Icon")
elif mode == 2:  # SaveShop
    add_byte("Type")
    add_int("Id")
    add_int("Metadata.Category")
    add_int("Metadata.CouponId")
    add_byte("Unknown")
    add_int("Metadata.ReturnCouponId")
    add_int("Metadata.SubType")
    add_byte("Unknown")
    add_byte("Metadata.CurrencyType")
    add_int("Metadata.PaymentItemId")
    add_int("Metadata.Price")
    add_str("Metadata.Icon")
    add_byte("Metadata.CurrencyType")
    add_int("Metadata.PaymentItemId")
    add_int("Metadata.Price")
    add_str("Metadata.Icon")
elif mode == 8:  # Error
    add_int("error")
elif mode == 9:  # Voucher
    add_int("itemId")
    add_int("amount")
elif mode == 11:  # RandomHair
    add_int("prevHairId")
    add_int("newHairId")
elif mode == 12:  # RandomHairResult
    add_int("voucherItemId")
    add_bool("error")
elif mode == 13:  # StartList
    pass
elif mode == 14:  # ListCount
    add_short("count")
elif mode == 15:  # ListHair
    add_short("hairs.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 16:  # SaveHair
    add_long("currentHair.Uid")
    add_long("hairCopy.Uid")
    add_byte("Unknown")
    add_long("hairCopy.CreationTime")
elif mode == 18:  # DeleteHair
    add_long("uid")
elif mode == 20:  # SaveSlots
    add_byte("Unknown")
    add_short("extraSlots")
elif mode == 21:  # ApplySavedHair
    pass
