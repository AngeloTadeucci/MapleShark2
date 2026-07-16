''' Buff '''
# Auto-generated (Phase 4a/4b) from BuffPacket: Add, Remove, Update
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_int("buff.Owner.ObjectId")
    add_int("buff.ObjectId")
    add_int("buff.Caster.ObjectId")
    # --- layout truncated: Buff: writer used in non-write statement (no wire-safe continuation) ---
elif mode == 1:  # Remove
    add_int("buff.Owner.ObjectId")
    add_int("buff.ObjectId")
    add_int("buff.Caster.ObjectId")
elif mode == 2:  # Update
    add_int("buff.Owner.ObjectId")
    add_int("buff.ObjectId")
    add_int("buff.Caster.ObjectId")
    add_int("flag")
    # --- layout truncated: if (no wire-safe continuation) ---
