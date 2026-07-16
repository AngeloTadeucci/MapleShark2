''' Liftable '''
# Auto-generated (Phase 4a/4b) from LiftablePacket: Update, Update, Add, Remove
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Update
    count = add_int("liftables.Count")
    for i0 in range(count):
        add_str("liftable.EntityId")
        add_byte("1")
        add_int("liftable.Count")
        add_byte("liftable.State")
        add_unicode_str("liftable.Value.MaskQuestId")
        add_unicode_str("liftable.Value.MaskQuestState")
        add_unicode_str("liftable.Value.EffectQuestId")
        add_unicode_str("liftable.Value.EffectQuestState")
        add_bool("liftable.Value.ReactEffect")
elif mode == 2:  # Update
    add_str("liftable.EntityId")
    add_byte("1")
    add_int("liftable.Count")
    add_byte("liftable.State")
elif mode == 3:  # Add
    add_str("liftable.EntityId")
    add_int("liftable.Count")
    add_unicode_str("liftable.Value.MaskQuestId")
    add_unicode_str("liftable.Value.MaskQuestState")
    add_unicode_str("liftable.Value.EffectQuestId")
    add_unicode_str("liftable.Value.EffectQuestState")
    add_bool("liftable.Value.ReactEffect")
elif mode == 4:  # Remove
    add_str("entityId")
