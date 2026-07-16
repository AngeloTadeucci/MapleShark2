''' Club '''
# Auto-generated (Phase 4a/4b) from ClubPacket: Update, Establish, Create, DeleteStagedClub, Invited, Invite, AcceptInvite, InviteNotification, UpdateMember, Rename, Leave, StagedClubInviteReply, Disband, NotifyAcceptInvite, LeaveNotice, NotifyLogin, NotifyLogout, UpdateLeader, UpdateMemberMap, UpdateMemberName, ChangeBuff, ChangeBuffNotification, Error, Join
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Update
    add_long("Id")
    add_unicode_str("Name")
    add_long("Leader.Info.AccountId")
    add_long("Leader.Info.CharacterId")
    add_unicode_str("Leader.Info.Name")
    add_long("CreationTime")
    add_byte("State")
    add_int("AdditionalEffectId")
    add_int("AdditionalEffectLevel")
    add_long("NameChangeCooldown")
    # --- layout truncated: loop body unresolved (ClubMember: writer used in non-write statement) (no wire-safe continuation) ---
elif mode == 1:  # Establish
    add_long("club.Id")
    add_unicode_str("club.Name")
elif mode == 2:  # Create
    add_long("Id")
    add_unicode_str("Name")
    add_long("Leader.Info.AccountId")
    add_long("Leader.Info.CharacterId")
    add_unicode_str("Leader.Info.Name")
    add_long("CreationTime")
    add_byte("State")
    add_int("AdditionalEffectId")
    add_int("AdditionalEffectLevel")
    add_long("NameChangeCooldown")
    # --- layout truncated: loop body unresolved (ClubMember: writer used in non-write statement) (no wire-safe continuation) ---
elif mode == 5:  # DeleteStagedClub
    add_long("clubId")
    add_int("reply")
elif mode == 6:  # Invited
    add_long("clubId")
    add_unicode_str("playerName")
elif mode == 7:  # Invite
    add_long("ClubId")
    add_unicode_str("Name")
    add_unicode_str("LeaderName")
    add_unicode_str("Invitee")
elif mode == 8:  # AcceptInvite
    add_long("ClubId")
    add_unicode_str("Name")
    add_unicode_str("LeaderName")
    add_unicode_str("Invitee")
    add_int("Unknown")
elif mode == 9:  # InviteNotification
    add_long("clubId")
    add_unicode_str("invitee")
    add_bool("accept")
    add_byte("Unknown")
elif mode == 10:  # Leave
    add_long("clubId")
    add_unicode_str("playerName")
elif mode == 13:  # ChangeBuffNotification
    add_long("clubId")
    add_int("additionalEffectId")
    add_int("additionalEffectLevel")
    add_unicode_str("memberName")
elif mode == 15:  # StagedClubInviteReply
    add_long("clubId")
    add_int("reply")
    add_unicode_str("name")
elif mode == 16:  # Disband
    add_long("clubId")
    add_unicode_str("leaderName")
    add_int("ClubResponse.Disband")
elif mode == 17:  # NotifyAcceptInvite
    add_long("member.ClubId")
    add_unicode_str("leaderName")
    add_byte("TYPE")
    add_long("ClubId")
    # --- layout truncated: ClubMember: writer used in non-write statement (no wire-safe continuation) ---
elif mode == 18:  # LeaveNotice
    add_long("clubId")
    add_unicode_str("playerName")
elif mode == 19:  # NotifyLogin
    add_long("clubId")
    add_unicode_str("memberName")
elif mode == 20:  # NotifyLogout
    add_long("clubId")
    add_unicode_str("memberName")
    add_long("lastLoginTime")
elif mode == 21:  # UpdateLeader
    add_long("clubId")
    add_unicode_str("oldLeader")
    add_unicode_str("newLeader")
    add_bool("true")
elif mode == 22:  # ChangeBuff
    add_long("clubId")
    add_int("additionalEffectId")
    add_int("additionalEffectLevel")
elif mode == 23:  # UpdateMemberMap
    add_long("clubId")
    add_unicode_str("memberName")
    add_int("mapId")
elif mode == 24:  # UpdateMember
    add_long("member.ClubId")
    add_unicode_str("member.Name")
    # --- layout truncated: pWriter used in non-write statement (no wire-safe continuation) ---
elif mode == 26:  # Rename
    add_long("clubId")
    add_unicode_str("clubName")
    add_long("timestamp")
elif mode == 27:  # UpdateMemberName
    add_unicode_str("oldName")
    add_unicode_str("newName")
elif mode == 29:  # Error
    add_byte("1")
    add_int("error")
elif mode == 30:  # Join
    add_long("member.ClubId")
    add_unicode_str("member.Name")
    add_unicode_str("clubName")
