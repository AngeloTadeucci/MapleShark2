''' BuddyBadge '''
# Auto-generated (Phase 4a) from BuddyBadgePacket: Start, Stop
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Start
    add_long("characterId")
elif mode == 1:  # Stop
    add_long("characterId")
