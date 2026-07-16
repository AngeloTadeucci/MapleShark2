''' ItemSocketScroll '''
# Auto-generated (Phase 4a/4b) from ItemSocketScrollPacket: UseScroll, Unlock, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # UseScroll
    add_long("scroll.Uid")
    add_int("10000")
    add_byte("metadata.SocketCount")
elif mode == 2:  # Unlock
    add_bool("success")
    add_long("item.Uid")
    add_byte("Unknown")
    add_int("10000")
    add_byte("MaxSlots")
    add_byte("UnlockSlots")
    # --- layout truncated: ItemSocket: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 3:  # Error
    add_bool("false")
    add_int("error")
