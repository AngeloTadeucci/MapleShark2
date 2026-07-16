''' ServerList '''
# Auto-generated (Phase 4a/4b) from ServerListPacket: Error, Load
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Error
    pass
elif mode == 1:  # Load
    add_int("1")
    add_unicode_str("serverName")
    add_byte("4")
    count = 0  # non-scalar count 'serverIps.Count'
    for i0 in range(count):
        add_unicode_str("endpoint.Address.ToString()")
        add_field("endpoint.Port", 2)
    add_int("100")
    count = 0  # non-scalar count 'channels.Count'
    for i0 in range(count):
        add_short("channel")
