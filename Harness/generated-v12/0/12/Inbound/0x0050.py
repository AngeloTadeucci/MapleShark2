''' Breakable '''
# Auto-generated (Phase 4a/4b) from BreakablePacket: Update, Update
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Update
    add_int("breakables.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 1:  # Update
    add_str("breakable.EntityId")
    add_byte("breakable.State")
    add_bool("breakable.Visible")
    # --- layout truncated: if (no wire-safe continuation) ---
