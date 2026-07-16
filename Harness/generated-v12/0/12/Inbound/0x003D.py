''' SkillUse '''
# Auto-generated (Phase 4a/4b) from SkillPacket: Use
from script_api import *

add_long("skill.CastUid")
add_int("skill.ServerTick")
add_int("skill.Caster.ObjectId")
add_int("skill.SkillId")
add_short("skill.Level")
add_byte("skill.MotionPoint")
add_field("skill.Position", 6)
add_field("skill.Direction", 12)
add_field("skill.Rotation", 12)
add_short("(skill.Rotate2Z * 10)")
add_bool("skill.IsRideOff")
add_bool("skill.IsHold")
# --- layout truncated: if (no wire-safe continuation) ---
