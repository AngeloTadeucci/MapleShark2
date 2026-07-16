''' GlamourAnvil '''
# Auto-generated (Phase 4a/4b) from ItemExtractionPacket: Extract, FullInventory, InsufficientAnvils
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Extract
    add_long("sourceUid")
    add_long("item.Uid")
    add_short("Unknown")
    add_field("item.Appearance?.Color ?? default", 20)
    add_int("Flag")
    add_bool("false")
    add_int("RemainTrades")
    add_int("RepackageCount")
    add_byte("Unknown")
    add_bool("true")
    add_bool("Binding != null")
    # --- layout truncated: ItemTransfer: if (no wire-safe continuation) ---
elif mode == 1:  # FullInventory
    pass
elif mode == 2:  # InsufficientAnvils
    pass
