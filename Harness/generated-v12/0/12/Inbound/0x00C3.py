''' GlobalPortal '''
# Auto-generated (Phase 4a/4b) from GlobalPortalPacket: Announce, Close
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Announce
    add_int("portal.Id")
    add_int("uid")
    add_unicode_str("portal.PopupMessage")
    add_unicode_str("portal.SoundId")
    # --- layout truncated: loop without a preceding scalar count (no wire-safe continuation) ---
elif mode == 1:  # Close
    add_int("id")
