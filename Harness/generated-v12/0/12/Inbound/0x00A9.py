''' DynamicChannel '''
# Auto-generated (Phase 4a/4b) from ChannelPacket: Load, Update
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_short("10")
    add_short("100")
    add_short("100")
    add_short("100")
    add_short("100")
    add_short("10")
    add_short("10")
    add_short("10")
elif mode == 1:  # Update
    count = add_short("channels.Count")
    for i0 in range(count):
        add_short("channel")
