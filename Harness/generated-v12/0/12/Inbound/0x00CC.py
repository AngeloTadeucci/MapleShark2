''' FieldProperty '''
# Auto-generated (Phase 4a/4b) from FieldPropertyPacket: Load, Add, Remove
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    # --- layout truncated: loop body unresolved (model IFieldProperty has no traceable WriteTo) (no wire-safe continuation) ---
    pass
elif mode == 1:  # Add
    # --- layout truncated: model IFieldProperty has no traceable WriteTo (no wire-safe continuation) ---
    pass
elif mode == 2:  # Remove
    add_byte("property")
