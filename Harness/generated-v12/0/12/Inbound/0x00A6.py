''' Attendance '''
# Auto-generated (Phase 4a/4b) from AttendancePacket: Unknown5, Unknown6, Unknown7, Error
from script_api import *

mode = add_byte("mode")
if mode == 5:  # Unknown5
    pass
elif mode == 6:  # Unknown6
    add_int("Unknown")
elif mode == 7:  # Unknown7
    add_int("Unknown")
elif mode == 9:  # Error
    add_byte("error")
