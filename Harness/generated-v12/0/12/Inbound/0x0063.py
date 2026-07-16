''' Buddy '''
# Auto-generated (Phase 4a/4b) from BuddyPacket: Load, Invite, Accept, Decline, Block, Unblock, Remove, UpdateInfo, Append, UpdateBlock, NotifyAccept, NotifyBlock, NotifyRemove, NotifyOnline, StartList, Cancel, Forbidden, EndList, SyncAutoAccept
from script_api import *

mode = add_byte("mode")
if mode == 1:  # Load
    count = add_int("buddies.Count + blocked.Count")
    for i0 in range(count):
        add_long("Id")
        add_long("Info.CharacterId")
        add_long("Info.AccountId")
        add_unicode_str("Info.Name")
        add_unicode_str("Type != BuddyType.Blocked ? Message : ''")
        add_short("Info.Channel")
        add_int("Info.MapId")
        add_int("Info.Job.Code()")
        add_int("Info.Job")
        add_short("Info.Level")
        add_bool("Type.HasFlag(BuddyType.InRequest)")
        add_bool("Type.HasFlag(BuddyType.OutRequest)")
        add_bool("Type.HasFlag(BuddyType.Blocked)")
        add_bool("Info.Online")
        add_bool("false")
        add_long("LastModified")
        add_unicode_str("Info.Picture")
        add_unicode_str("Info.Motto")
        add_unicode_str("Type == BuddyType.Blocked ? Message : ''")
        add_int("Info.PlotMapId")
        add_int("Info.PlotNumber")
        add_int("Info.ApartmentNumber")
        add_unicode_str("Info.HomeName")
        add_long("Info.PlotExpiryTime")
        add_field("Info.AchievementInfo", 12)
    # --- layout truncated: loop without a preceding scalar count (no wire-safe continuation) ---
elif mode == 2:  # Invite
    add_byte("error")
    add_unicode_str("name")
    add_unicode_str("message")
elif mode == 3:  # Accept
    add_byte("BuddyError.ok")
    add_long("buddy.Id")
    add_long("buddy.Info.CharacterId")
    add_long("buddy.Info.AccountId")
    add_unicode_str("buddy.Info.Name")
elif mode == 4:  # Decline
    add_byte("BuddyError.ok")
    add_long("buddy.Id")
elif mode == 5:  # Block
    add_byte("error")
    add_long("entryId")
    add_unicode_str("name")
    add_unicode_str("message")
elif mode == 6:  # Unblock
    add_byte("BuddyError.ok")
    add_long("buddy.Id")
elif mode == 7:  # Remove
    add_byte("BuddyError.ok")
    add_long("buddy.Id")
    add_long("buddy.Info.CharacterId")
    add_long("buddy.Info.AccountId")
    add_unicode_str("buddy.Info.Name")
elif mode == 8:  # UpdateInfo
    add_long("Id")
    add_long("Info.CharacterId")
    add_long("Info.AccountId")
    add_unicode_str("Info.Name")
    add_unicode_str("Type != BuddyType.Blocked ? Message : ''")
    add_short("Info.Channel")
    add_int("Info.MapId")
    add_int("Info.Job.Code()")
    add_int("Info.Job")
    add_short("Info.Level")
    add_bool("Type.HasFlag(BuddyType.InRequest)")
    add_bool("Type.HasFlag(BuddyType.OutRequest)")
    add_bool("Type.HasFlag(BuddyType.Blocked)")
    add_bool("Info.Online")
    add_bool("false")
    add_long("LastModified")
    add_unicode_str("Info.Picture")
    add_unicode_str("Info.Motto")
    add_unicode_str("Type == BuddyType.Blocked ? Message : ''")
    add_int("Info.PlotMapId")
    add_int("Info.PlotNumber")
    add_int("Info.ApartmentNumber")
    add_unicode_str("Info.HomeName")
    add_long("Info.PlotExpiryTime")
    add_field("Info.AchievementInfo", 12)
elif mode == 9:  # Append
    add_long("Id")
    add_long("Info.CharacterId")
    add_long("Info.AccountId")
    add_unicode_str("Info.Name")
    add_unicode_str("Type != BuddyType.Blocked ? Message : ''")
    add_short("Info.Channel")
    add_int("Info.MapId")
    add_int("Info.Job.Code()")
    add_int("Info.Job")
    add_short("Info.Level")
    add_bool("Type.HasFlag(BuddyType.InRequest)")
    add_bool("Type.HasFlag(BuddyType.OutRequest)")
    add_bool("Type.HasFlag(BuddyType.Blocked)")
    add_bool("Info.Online")
    add_bool("false")
    add_long("LastModified")
    add_unicode_str("Info.Picture")
    add_unicode_str("Info.Motto")
    add_unicode_str("Type == BuddyType.Blocked ? Message : ''")
    add_int("Info.PlotMapId")
    add_int("Info.PlotNumber")
    add_int("Info.ApartmentNumber")
    add_unicode_str("Info.HomeName")
    add_long("Info.PlotExpiryTime")
    add_field("Info.AchievementInfo", 12)
elif mode == 10:  # UpdateBlock
    add_byte("error")
    add_long("entryId")
    add_unicode_str("name")
    add_unicode_str("message")
elif mode == 11:  # NotifyAccept
    add_long("buddy.Id")
elif mode == 12:  # NotifyBlock
    add_byte("error")
    add_unicode_str("name")
elif mode == 13:  # NotifyRemove
    add_int("Unknown")
    add_unicode_str("buddy.Info.Name")
    add_unicode_str("action")
    add_long("buddy.Id")
elif mode == 14:  # NotifyOnline
    add_bool("!buddy.Info.Online")
    add_long("buddy.Id")
    add_unicode_str("buddy.Info.Name")
elif mode == 15:  # StartList
    pass
elif mode == 17:  # Cancel
    add_byte("BuddyError.ok")
    add_long("buddy.Id")
elif mode == 18:  # Forbidden
    pass
elif mode == 19:  # EndList
    add_int("count")
elif mode == 20:  # SyncAutoAccept
    pass
