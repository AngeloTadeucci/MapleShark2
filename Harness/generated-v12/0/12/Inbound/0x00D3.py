''' SkillMacro '''
# Auto-generated (Phase 4a/4b) from SkillMacroPacket: Load, Init
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_int("skillMacros.Count")
    for i0 in range(count):
        add_unicode_str("Name")
        add_long("KeyId")
        count = add_int("Skills.Count")
        for i1 in range(count):
            add_int("skillId")
elif mode == 2:  # Init
    count = add_int("skillMacros.Count")
    for i0 in range(count):
        add_unicode_str("Name")
        add_long("KeyId")
        count = add_int("Skills.Count")
        for i1 in range(count):
            add_int("skillId")
