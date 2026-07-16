''' Vibrate '''
# Auto-generated (Phase 4a/4b) from VibratePacket: Add, Stop
from script_api import *

mode = add_byte("mode")
if mode == 1:  # Add
    add_str("entityId")
    add_long("damage.SkillUid")
    add_int("damage.SkillId")
    add_short("damage.Level")
    add_byte("damage.MotionPoint")
    add_byte("damage.AttackPoint")
    add_field("damage.Position", 6)
    add_int("Environment.TickCount")
    add_str("Unknown")
    add_byte("Unknown")
elif mode == 2:  # Stop
    add_str("entityId")
    add_str("Unknown")
    add_byte("Unknown")
