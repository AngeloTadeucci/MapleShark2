''' RecallScroll '''
# Auto-generated (Phase 4a/4b) from RecallScrollPacket: Close, Open
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Close
    add_byte("scrollType")
elif mode == 1:  # Open
    add_byte("scrollType")
    add_unicode_str("playerName")
    add_int("Unknown")
    add_int("mapId")
    add_int("portalId")
    add_long("expiresAt")
