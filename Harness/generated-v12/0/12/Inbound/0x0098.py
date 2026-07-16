''' ItemDismantle '''
# Auto-generated (Phase 4a/4b) from ItemDismantlePacket: Stage, Remove, Result, Preview
from script_api import *

mode = add_byte("mode")
if mode == 1:  # Stage
    add_long("itemUid")
    add_short("slot")
    add_int("amount")
elif mode == 2:  # Remove
    add_long("itemUid")
elif mode == 3:  # Result
    add_byte("mode")
    count = add_int("rewards.Count")
    for i0 in range(count):
        add_int("id")
        add_int("amount")
elif mode == 5:  # Preview
    count = add_int("rewards.Count")
    for i0 in range(count):
        add_int("id")
        add_int("min")
        add_int("max")
