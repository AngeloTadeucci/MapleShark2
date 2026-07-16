''' FieldEntrance '''
# Auto-generated (Phase 4a/4b) from FieldEntrancePacket: Load, Admin, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    # --- layout truncated: loop body unresolved (Write<> unresolved) (no wire-safe continuation) ---
    pass
elif mode == 1:  # Admin
    pass
elif mode == 2:  # Error
    add_byte("limit")
    # --- layout truncated: Write<> unresolved (no wire-safe continuation) ---
