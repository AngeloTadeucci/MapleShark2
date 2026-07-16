''' ItemExchange '''
# Auto-generated (Phase 4a/4b) from ItemExchangeScrollPacket: Unknown0, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Unknown0
    add_long("Unknown")
    add_long("Unknown")
    add_bool("unk")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 2:  # Error
    add_short("error")
