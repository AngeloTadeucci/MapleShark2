''' InteractObject '''
# Auto-generated (Phase 4a/4b) from InteractObjectPacket: Update, Interact, SetState, SetStateAll, Load, Add, Remove, Result, Announce, Hold
from script_api import *

mode = add_byte("mode")
if mode == 4:  # Update
    add_str("interact.EntityId")
    add_byte("interact.State")
    add_byte("interact.Type")
elif mode == 5:  # Interact
    add_str("interact.EntityId")
    add_byte("interact.Type")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 6:  # SetState
    add_int("interact.Value.Id")
    add_byte("interact.State")
elif mode == 7:  # SetStateAll
    add_byte("state")
elif mode == 8:  # Load
    add_int("interacts.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 9:  # Add
    # --- layout truncated: model IInteractObject has no traceable WriteTo (no wire-safe continuation) ---
    pass
elif mode == 10:  # Remove
    add_str("entityId")
    add_unicode_str("effect")
elif mode == 13:  # Result
    add_byte("result")
    add_str("interact.EntityId")
    add_byte("interact.Type")
elif mode == 14:  # Announce
    add_short("channelId")
    add_int("mapId")
    add_int("interactId")
    add_unicode_str("formatArg")
elif mode == 15:  # Hold
    add_int("objectId")
    add_int("itemId")
