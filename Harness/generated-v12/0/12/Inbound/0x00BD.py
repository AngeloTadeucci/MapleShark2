''' PartySearch '''
# Auto-generated (Phase 4a/4b) from PartySearchPacket: Add, Remove, Load, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_long("Id")
    add_int("PartyId")
    add_int("Unknown")
    add_int("Unknown")
    add_unicode_str("Name")
    add_bool("AllowAutoJoin")
    add_int("MemberCount")
    add_int("Size")
    add_long("LeaderAccountId")
    add_long("LeaderCharacterId")
    add_unicode_str("LeaderName")
    add_long("CreationTime")
elif mode == 1:  # Remove
    add_long("partySearchId")
elif mode == 2:  # Load
    count = add_int("entries.Count")
    for i0 in range(count):
        add_bool("true")
        add_long("Id")
        add_int("PartyId")
        add_int("Unknown")
        add_int("Unknown")
        add_unicode_str("Name")
        add_bool("AllowAutoJoin")
        add_int("MemberCount")
        add_int("Size")
        add_long("LeaderAccountId")
        add_long("LeaderCharacterId")
        add_unicode_str("LeaderName")
        add_long("CreationTime")
elif mode == 4:  # Error
    add_int("category")
    add_int("error")
