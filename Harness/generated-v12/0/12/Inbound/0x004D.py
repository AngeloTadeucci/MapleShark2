''' RegionSkill '''
# Auto-generated (Phase 4a/4b) from RegionSkillPacket: Add, Remove
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_int("fieldSkill.ObjectId")
    add_int("fieldSkill.Caster.ObjectId")
    add_int("fieldSkill.NextTick.Truncate32()")
    count = add_byte("fieldSkill.Points.Length")
    for i0 in range(count):
        add_field("point", 12)
    add_int("fieldSkill.Value.Id")
    add_short("fieldSkill.Value.Level")
    add_float("fieldSkill.UseDirection ? fieldSkill.Rotation.Z")
    add_float("Unknown")
elif mode == 1:  # Remove
    add_int("objectId")
