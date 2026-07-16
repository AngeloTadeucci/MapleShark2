''' ShadowExpedition '''
# Auto-generated (Phase 4a) from ShadowExpeditionPacket: Open, UpdateGauge, Close
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Open
    add_byte("uiType")
    add_unicode_str("title")
    add_int("currentPoints")
    add_int("maxPoints")
elif mode == 1:  # UpdateGauge
    add_int("points")
elif mode == 2:  # Close
    pass
