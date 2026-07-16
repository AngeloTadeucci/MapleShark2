''' MesoMarket '''
# Auto-generated (Phase 4a/4b) from MesoMarketPacket: Error, Load, Quota, MyListings, Create, Cancel, Search, Purchase
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Error
    add_int("error")
elif mode == 1:  # Load
    add_float("Constant.MesoMarketTaxRate")
    add_float("Constant.MesoMarketRangeRate")
    add_long("averagePrice")
    add_int("Constant.MesoMarketListLimit")
    add_int("Constant.MesoMarketListLimitDay")
    add_int("Constant.MesoMarketPurchaseLimitMonth")
    add_int("Constant.MesoMarketSellEndDay")
    add_int("Constant.MesoMarketPageSize")
    add_int("Constant.MesoMarketMinToken")
    add_int("Constant.MesoMarketMaxToken")
elif mode == 2:  # Quota
    add_int("dailyListed")
    add_int("monthlyPurchased")
elif mode == 4:  # MyListings
    count = add_int("listings.Count")
    for i0 in range(count):
        add_long("listing.Id")
        add_long("Id")
        add_long("Amount")
        add_long("Price")
        add_long("CreationTime")
        add_long("ExpiryTime")
        add_bool("true")
elif mode == 5:  # Create
    add_long("Id")
    add_long("Amount")
    add_long("Price")
    add_long("CreationTime")
    add_long("ExpiryTime")
    add_bool("true")
    add_int("1")
elif mode == 6:  # Cancel
    add_int("error")
    add_long("listingId")
elif mode == 7:  # Search
    count = add_int("listings.Count")
    for i0 in range(count):
        add_long("Id")
        add_long("Amount")
        add_long("Price")
        add_long("CreationTime")
        add_long("ExpiryTime")
        add_bool("listing.AccountId == accountId")
elif mode == 8:  # Purchase
    add_int("error")
    add_long("listingId")
    add_int("1")
