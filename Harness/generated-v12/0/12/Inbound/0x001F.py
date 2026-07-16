''' Emote '''
# Auto-generated (Phase 4a/4b) from EmotePacket: Load, Learn, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_int("emotes.Count")
    for i0 in range(count):
        add_field("emote", 16)
elif mode == 1:  # Learn
    add_field("emote", 16)
elif mode == 3:  # Error
    add_byte("error")
