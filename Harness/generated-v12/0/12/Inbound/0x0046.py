''' AttributePoint '''
# Auto-generated (Phase 4a/4b) from AttributePointPacket: Sources, Allocation
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Sources
    add_int("statAttributes.TotalPoints")
    # --- layout truncated: model StatAttributes.PointSources has no traceable WriteTo (no wire-safe continuation) ---
elif mode == 1:  # Allocation
    add_int("statAttributes.TotalPoints")
    # --- layout truncated: model StatAttributes.PointAllocation has no traceable WriteTo (no wire-safe continuation) ---
