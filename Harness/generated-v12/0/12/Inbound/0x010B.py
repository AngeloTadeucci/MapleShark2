''' DungeonHelp '''
# Auto-generated (Phase 4a) from DungeonHelperPacket: FindHelper, FindMember
from script_api import *

mode = add_byte("mode")
if mode == 0:  # FindHelper
    add_int("helpRequestId")
    add_unicode_str("characterName")
    add_long("accountId")
    add_long("characterId")
    add_int("dungeonId")
    add_byte("partySize")
elif mode == 1:  # FindMember
    add_byte("rookieCount")
    add_byte("expertCount")
    add_int("helpRequestId")
    add_unicode_str("characterName")
    add_long("accountId")
    add_long("characterId")
    add_int("dungeonId")
    add_byte("partySize")
