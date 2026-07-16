''' SuperWorldChat '''
# Auto-generated (Phase 4a/4b) from SuperChatPacket: Select, Deselect
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Select
    add_int("objectId")
    add_int("itemId")
elif mode == 1:  # Deselect
    add_int("objectId")
