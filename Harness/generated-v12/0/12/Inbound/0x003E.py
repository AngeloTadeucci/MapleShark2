''' SkillDamage '''
# Auto-generated (Phase 4a/4b) from SkillDamagePacket: Target, Damage, DotDamage, Heal, Region, Tile, DestroyBreakable, React
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Target
    add_long("record.CastUid")
    add_int("record.Caster.ObjectId")
    add_int("record.SkillId")
    add_short("record.Level")
    add_byte("record.MotionPoint")
    add_byte("record.AttackPoint")
    add_field("record.Position", 6)
    add_field("record.Direction", 12)
    add_bool("true")
    add_int("record.ServerTick")
    count = add_byte("targets.Count")
    for i0 in range(count):
        add_long("PrevUid")
        add_long("Uid")
        add_int("TargetId")
        add_byte("Unknown")
        add_byte("Index")
elif mode == 1:  # Damage
    add_long("record.SkillUid")
    add_long("record.TargetUid")
    add_int("record.CasterId")
    add_int("record.SkillId")
    add_short("record.Level")
    add_byte("record.MotionPoint")
    add_byte("record.AttackPoint")
    add_field("record.Position", 6)
    add_field("record.Direction", 6)
    count = add_byte("targets.Length")
    for i0 in range(count):
        add_int("target.ObjectId")
        count = add_byte("target.Damage.Count")
        for i1 in range(count):
            add_byte("type")
            add_long("-amount")
elif mode == 3:  # DotDamage
    add_int("record.Caster.ObjectId")
    add_int("record.Target.ObjectId")
    add_int("record.ProcCount")
    add_byte("record.Type")
    add_int("record.HpAmount")
elif mode == 4:  # Heal
    add_int("Caster.ObjectId")
    add_int("Target.ObjectId")
    add_int("OwnerId")
    add_int("HpAmount")
    add_int("SpAmount")
    add_int("EpAmount")
    add_bool("animate")
elif mode == 5:  # Region
    add_long("record.SkillUid")
    add_int("record.CasterId")
    add_int("record.OwnerId")
    add_byte("record.AttackPoint")
    # --- layout truncated: loop body unresolved (loop without a preceding scalar count) (no wire-safe continuation) ---
elif mode == 6:  # Tile
    add_long("record.SkillUid")
    add_int("record.SkillId")
    add_short("record.Level")
    # --- layout truncated: loop body unresolved (loop without a preceding scalar count) (no wire-safe continuation) ---
elif mode == 7:  # DestroyBreakable
    add_int("triggerId")
    count = add_int("breakables.Count")
    for i0 in range(count):
        add_int("breakable.ObjectId")
elif mode == 8:  # React
    pass
