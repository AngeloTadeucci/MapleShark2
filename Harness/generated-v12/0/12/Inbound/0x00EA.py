''' NpcNotice '''
# Auto-generated (Phase 4a) from NpcNoticePacket: Announce, TargetEffect, Animation, SidePopup
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Announce
    add_unicode_str("message")
    add_int("duration")
elif mode == 1:  # TargetEffect
    add_int("targetId")
    add_unicode_str("effect")
elif mode == 2:  # Animation
    add_int("objectId")
    add_unicode_str("sequence")
elif mode == 3:  # SidePopup
    add_byte("type")
    add_int("duration")
    add_str("Unknown")
    add_str("illustration")
    add_str("voice")
    add_str("sound")
    add_unicode_str("script")
