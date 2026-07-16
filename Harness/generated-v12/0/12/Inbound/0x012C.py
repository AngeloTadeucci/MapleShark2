''' WeddingBillboard '''
# Auto-generated (Phase 4a/4b) from WeddingBillboardPacket: Load
from script_api import *

add_byte("mode")
count = add_int("halls.Count")
for i0 in range(count):
    add_long("hall.MarriageId")
    add_long("Id")
    add_int("PackageId")
    add_int("PackageHallId")
    add_long("CeremonyTime")
    add_bool("Public")
    add_long("ReserverAccountId")
    add_long("ReserverCharacterId")
    add_unicode_str("ReserverName")
    add_unicode_str("PartnerName")
    add_long("Unknown")
    add_long("Unknown")
    add_long("Unknown")
    add_long("Unknown")
    add_long("Unknown")
    add_int("GuestList.Count")
