''' ExpUp '''
# Auto-generated (Phase 4a) from ExperienceUpPacket: Add, SetRestExp
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_long("gainedExp")
    add_short("message")
    add_long("totalExp")
    add_long("restExp")
    add_int("parameter")
    add_bool("additional")
elif mode == 1:  # SetRestExp
    add_long("restExp")
