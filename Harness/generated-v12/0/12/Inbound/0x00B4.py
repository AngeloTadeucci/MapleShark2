''' GameEvent '''
# Auto-generated (Phase 4a/4b) from GameEventPacket: Load, Add, Remove, Reload
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    # --- layout truncated: loop body unresolved (GameEvent: switch) (no wire-safe continuation) ---
    pass
elif mode == 1:  # Add
    # --- layout truncated: loop body unresolved (GameEvent: switch) (no wire-safe continuation) ---
    pass
elif mode == 2:  # Remove
    count = add_int("eventIds.Length")
    for i0 in range(count):
        add_int("value")
elif mode == 3:  # Reload
    # --- layout truncated: loop body unresolved (GameEvent: switch) (no wire-safe continuation) ---
    pass
