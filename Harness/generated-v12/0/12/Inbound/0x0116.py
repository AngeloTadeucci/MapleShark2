''' Microgame '''
# Auto-generated (Phase 4a/4b) from MicrogamePacket: RpsInvite, RpsRequest, RpsDecline, RpsCancel, RpsInteractCancel, Unknown5, RpsResult, AddRewardItems, NpcInteractStart, RpsAccepted, CoupleDanceInvite, CoupleDanceRequest, CoupleDanceDecline, CoupleDanceAccepted, CoupleDanceCancel, CraftUpdate, Unknown19, CoupleDanceResult, CraftAnimation
from script_api import *

mode = add_short("mode")
if mode == 0:  # RpsInvite
    pass
elif mode == 1:  # RpsRequest
    add_long("characterId")
elif mode == 2:  # RpsDecline
    add_long("characterId")
elif mode == 3:  # RpsCancel
    add_long("characterId")
elif mode == 4:  # RpsInteractCancel
    pass
elif mode == 5:  # Unknown5
    add_long("characterId")
elif mode == 6:  # RpsResult
    add_long("characterId")
    add_byte("result")
elif mode == 10:  # AddRewardItems
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("itemId")
        add_short("rarity")
elif mode == 11:  # NpcInteractStart
    add_byte("unknown1")
    add_byte("unknown2")
    add_byte("unknown3")
elif mode == 12:  # RpsAccepted
    add_long("characterId")
elif mode == 13:  # CoupleDanceInvite
    add_int("unknown")
elif mode == 14:  # CoupleDanceRequest
    add_int("unknown")
    add_long("characterId")
elif mode == 15:  # CoupleDanceDecline
    add_int("unknown")
    add_long("characterId")
elif mode == 16:  # CoupleDanceAccepted
    add_int("unknown")
    add_long("characterId")
elif mode == 17:  # CoupleDanceCancel
    add_int("unknown")
    add_long("characterId")
elif mode == 18:  # CraftUpdate
    add_int("unknown")
    # --- layout truncated: loop count 'unknown' not wire-linked to 'values' (no wire-safe continuation) ---
elif mode == 19:  # Unknown19
    add_int("unknown")
    add_long("characterId")
elif mode == 20:  # CoupleDanceResult
    add_int("unknown")
    add_long("characterId")
    add_byte("result")
elif mode == 22:  # CraftAnimation
    add_int("unknown")
    add_byte("step")
    add_bool("flag")
    add_short("value1")
    add_short("value2")
