''' FieldPortal '''
# Auto-generated (Phase 4a/4b) from PortalPacket: Add, Remove, Update, Move
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Add
    add_int("portal.Id")
    add_bool("fieldPortal.Visible")
    add_bool("fieldPortal.Enabled")
    add_field("fieldPortal.Position", 12)
    add_field("fieldPortal.Rotation", 12)
    add_field("portal.Dimension", 12)
    add_unicode_str("fieldPortal.Model")
    add_int("portal.TargetMapId")
    add_int("fieldPortal.ObjectId")
    add_int("portal.ActionType")
    add_bool("fieldPortal.MinimapVisible")
    add_long("fieldPortal.HomeId")
    add_byte("portal.Type")
    add_int("fieldPortal.EndTick.Truncate32()")
    add_short("Unknown")
    add_int("fieldPortal.StartTick.Truncate32()")
    add_bool("!string.IsNullOrEmpty(fieldPortal.Password)")
    add_unicode_str("fieldPortal.OwnerName")
    add_unicode_str("Unknown")
    add_unicode_str("Unknown")
elif mode == 1:  # Remove
    add_int("portalId")
elif mode == 2:  # Update
    add_int("fieldPortal.Value.Id")
    add_bool("fieldPortal.Visible")
    add_bool("fieldPortal.Enabled")
    add_bool("fieldPortal.MinimapVisible")
    add_short("Unknown")
elif mode == 3:  # Move
    add_int("fieldPortal.Value.Id")
    add_field("fieldPortal.Position", 12)
    add_field("fieldPortal.Rotation", 12)
