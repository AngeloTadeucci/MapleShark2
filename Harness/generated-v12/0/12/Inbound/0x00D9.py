''' SmartPush '''
# Auto-generated (Phase 4a/4b) from SmartPushPacket: Error, ActivateEffect
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Error
    add_bool("insufficientMeret")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 1:  # ActivateEffect
    add_int("smartPushId")
    add_int("param")
