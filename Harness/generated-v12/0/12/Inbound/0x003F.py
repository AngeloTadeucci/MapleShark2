''' SkillSync '''
# Auto-generated (Phase 4a/4b) from SkillPacket: Sync
from script_api import *

add_long("skill.CastUid")
add_int("skill.Caster.ObjectId")
add_int("skill.SkillId")
add_short("skill.Level")
add_byte("skill.MotionPoint")
add_field("skill.Position", 12)
add_field("skill.Direction", 12)
add_field("skill.Velocity", 12)
add_field("skill.Rotation", 12)
add_bool("skill.IsCharge")
add_bool("skill.IsRelease")
add_int("skill.SyncClientTick")
