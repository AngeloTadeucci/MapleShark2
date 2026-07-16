''' RoomTimer '''
# Auto-generated (Phase 4a/4b) from RoomTimerPacket: Start, Modify, StartGauge, SetWidgetData, Stop, Expire
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Start
    add_byte("timer.Type")
    add_int("timer.StartTick.Truncate32()")
    add_int("timer.Duration")
    add_int("timer.TimeOffsetSeconds")
elif mode == 1:  # Modify
    add_int("timer.StartTick.Truncate32()")
    add_int("timer.Duration")
    add_int("notification")
    add_int("notificationValueMs")
elif mode == 2:  # StartGauge
    add_byte("timer.Type")
    add_int("timer.StartTick.Truncate32()")
    add_int("timer.Duration")
    add_int("timer.TimeOffsetSeconds")
elif mode == 3:  # SetWidgetData
    count = add_int("widgets.Count")
    for i0 in range(count):
        add_int("id")
        add_int("time")
elif mode == 4:  # Stop
    pass
elif mode == 5:  # Expire
    pass
