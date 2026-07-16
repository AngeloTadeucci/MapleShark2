''' GameEventUserValue '''
# Auto-generated (Phase 4a/4b) from GameEventUserValuePacket: Load, Update
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_byte("Unknown")
    count = add_int("userValues.Count")
    for i0 in range(count):
        add_int("Type")
        add_int("EventId")
        add_unicode_str("Value")
        add_long("ExpirationTime")
elif mode == 1:  # Update
    add_byte("Unknown")
    add_int("Type")
    add_int("EventId")
    add_unicode_str("Value")
    add_long("ExpirationTime")
