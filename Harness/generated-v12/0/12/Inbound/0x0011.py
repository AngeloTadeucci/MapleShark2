''' ResponseTimeSync '''
# Auto-generated (Phase 4a/4b) from TimeSyncPacket: Response, Reset, Request, Set
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Response
    add_int("Environment.TickCount")
    add_long("time.ToUnixTimeSeconds()")
    add_int("time.Offset.Seconds")
    add_byte("Unknown")
    add_int("key")
elif mode == 1:  # Reset
    add_int("Environment.TickCount")
    add_long("time.ToUnixTimeSeconds()")
    add_int("time.Offset.Seconds")
    add_byte("Unknown")
elif mode == 2:  # Request
    pass
elif mode == 3:  # Set
    add_long("time.ToUnixTimeSeconds()")
