''' HomeCommand '''
# Auto-generated (Phase 4a) from HomeCommandPacket: LoadHome, UpdateArchitectScore
from script_api import *

mode = add_byte("mode")
if mode == 0:  # LoadHome
    add_long("accountId")
    add_long("last time player nominated home")
elif mode == 1:  # UpdateArchitectScore
    add_int("ownerObjectId")
    add_long("DateTimeOffset.UtcNow.ToUnixTimeSeconds()")
    add_int("architectScoreCurrent")
    add_int("architectScoreTotal")
