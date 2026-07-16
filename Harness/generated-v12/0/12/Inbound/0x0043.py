''' SkillCooldown '''
# Auto-generated (Phase 4a/4b) from SkillPacket: Cooldown
from script_api import *

count = add_byte("cooldowns.Length")
for i0 in range(count):
    add_int("SkillId")
    add_int("GroupId")
    add_int("EndTick.Truncate32()")
    add_int("Charges")
