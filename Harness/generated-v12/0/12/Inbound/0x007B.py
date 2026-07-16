''' ResponseRide '''
# Auto-generated (Phase 4a/4b) from RidePacket: Start, Stop, Change, Join, Leave, ChangeShared
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Start
    add_int("ride.OwnerId")
    add_byte("Type")
    add_int("RideId")
    add_int("ObjectId")
elif mode == 1:  # Stop
    add_int("ownerId")
    add_byte("type")
    add_bool("forced")
elif mode == 2:  # Change
    add_int("ownerId")
    add_int("rideId")
    add_long("itemUid")
elif mode == 3:  # Join
    add_int("ownerId")
    add_int("joinerId")
    add_field("index", 1)
elif mode == 4:  # Leave
    add_int("ownerId")
    add_int("leaverId")
elif mode == 5:  # ChangeShared
    add_int("objectId")
