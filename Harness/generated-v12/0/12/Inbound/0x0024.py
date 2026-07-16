''' FurnishingInventory '''
# Auto-generated (Phase 4a/4b) from FurnishingInventoryPacket: StartList, Add, Remove, Update, EndList
from script_api import *

mode = add_byte("mode")
if mode == 0:  # StartList
    pass
elif mode == 1:  # Add
    # --- layout truncated: model PlotCube has no traceable WriteTo (no wire-safe continuation) ---
    pass
elif mode == 2:  # Remove
    add_long("itemUid")
elif mode == 3:  # Update
    add_long("itemUid")
    add_int("amount")
elif mode == 4:  # EndList
    pass
