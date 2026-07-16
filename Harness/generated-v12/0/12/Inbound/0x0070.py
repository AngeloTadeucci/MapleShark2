''' GuideObject '''
# Auto-generated (Phase 4a/4b) from GuideObjectPacket: Create, Remove
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Create
    add_short("Value.Type")
    add_int("ObjectId")
    add_long("CharacterId")
    add_field("Position", 12)
    add_field("Rotation", 12)
    # --- layout truncated: FieldGuideObject: model IGuideObject has no traceable WriteTo (no wire-safe continuation) ---
elif mode == 1:  # Remove
    add_int("guideObject.ObjectId")
    add_long("guideObject.CharacterId")
