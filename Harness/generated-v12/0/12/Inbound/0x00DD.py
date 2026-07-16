''' ItemLock '''
# Auto-generated (Phase 4a/4b) from ItemLockPacket: Stage, Unstage, Commit, Error
from script_api import *

mode = add_byte("mode")
if mode == 1:  # Stage
    add_long("itemUid")
    add_short("slot")
elif mode == 2:  # Unstage
    add_long("itemUid")
elif mode == 3:  # Commit
    # --- layout truncated: loop body unresolved (Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT') (no wire-safe continuation) ---
    pass
elif mode == 4:  # Error
    add_int("errorCode")
