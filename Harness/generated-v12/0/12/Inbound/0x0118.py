''' SurvivalEvent '''
# Auto-generated (Phase 4a/4b) from SurvivalEventPacket: CreateStorm, UpdateStorm, RemoveStorm, ClearAllStorms, ShowPlayerCountdown, CreateDamageStorm, UpdateSafeZone
from script_api import *

mode = add_byte("mode")
if mode == 0:  # CreateStorm
    add_short("500")
    add_short("3000")
    add_short("1000")
    add_field("StormCenter", 12)
    add_short("1000")
    add_field("SafeZoneCenter", 12)
elif mode == 1:  # UpdateStorm
    add_short("id")
    add_float("radius")
    add_field("position", 12)
elif mode == 2:  # RemoveStorm
    add_short("id")
elif mode == 3:  # ClearAllStorms
    pass
elif mode == 4:  # ShowPlayerCountdown
    add_short("count")
elif mode == 5:  # CreateDamageStorm
    pass
elif mode == 6:  # UpdateSafeZone
    add_short("id")
