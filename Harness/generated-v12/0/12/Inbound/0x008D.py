''' GroupChat '''
# Auto-generated (Phase 4a/4b) from GroupChatPacket: Load, Create, Invite, Join, Leave, AddMember, RemoveMember, LoginNotice, LogoutNotice, Chat, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_int("groupChat.Id")
    # --- layout truncated: loop body unresolved (PlayerInfo: loop body has control flow / unknown write) (no wire-safe continuation) ---
elif mode == 1:  # Create
    add_int("groupChatId")
elif mode == 2:  # Invite
    add_unicode_str("memberName")
    add_unicode_str("targetName")
    add_int("groupChatId")
elif mode == 3:  # Join
    add_unicode_str("senderMemberName")
    add_unicode_str("receiverTargetName")
    add_int("groupChatId")
elif mode == 4:  # Leave
    add_int("groupChatId")
elif mode == 6:  # AddMember
    add_int("groupChatId")
    add_unicode_str("inviterName")
    add_bool("true")
    add_long("AccountId")
    add_long("CharacterId")
    add_unicode_str("Name")
    add_byte("Gender")
    add_byte("1")
    add_long("AccountId")
    add_int("1")
    add_int("MapId")
    add_int("MapId")
    add_int("PlotMapId")
    add_short("Level")
    add_short("Channel")
    add_int("Job.Code()")
    add_int("Job")
    add_int("TotalHp")
    add_int("CurrentHp")
    add_short("DeathState")
    add_long("Unknown")
    add_long("Unknown")
    add_long("Unknown")
    add_int("Unknown")
    add_field("default", 12)
    add_int("GearScore")
    add_field("default", 8)
    add_long("Unknown")
    add_field("default", 12)
    add_long("GuildId")
    add_unicode_str("GuildName")
    add_unicode_str("Motto")
    add_unicode_str("Picture")
    add_byte("ClubIds.Count")
    # --- layout truncated: PlayerInfo: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 7:  # RemoveMember
    add_int("groupChatId")
    add_bool("false")
    add_unicode_str("memberName")
elif mode == 8:  # LoginNotice
    add_int("groupChatId")
    add_unicode_str("memberName")
elif mode == 9:  # LogoutNotice
    add_int("groupChatId")
    add_unicode_str("memberName")
elif mode == 10:  # Chat
    add_int("groupChatId")
    add_unicode_str("memberName")
    add_unicode_str("message")
elif mode == 13:  # Error
    add_byte("2")
    add_int("error")
    add_unicode_str("memberName")
    add_unicode_str("targetName")
