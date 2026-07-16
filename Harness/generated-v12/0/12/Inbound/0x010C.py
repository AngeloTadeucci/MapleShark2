''' Mentor '''
# Auto-generated (Phase 4a/4b) from MentorPacket: UpdateRole, MenteeInvitations, MyList, AssignReturningUser, MenteeInvite, AcceptMentorInvite, DeclineMentorInvite, AssignMentor, Load, LoginPoints, DailyPoints, PairMode, ReceiveMenteeInvite, UpdateOnlineStatus, ReturningUserStatus
from script_api import *

mode = add_byte("mode")
if mode == 1:  # UpdateRole
    add_byte("role")
    add_int("objectId")
elif mode == 2:  # MenteeInvitations
    add_int("invitations.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 3:  # MyList
    add_int("entries.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 4:  # AssignReturningUser
    pass
elif mode == 5:  # MenteeInvite
    add_long("characterId")
    add_unicode_str("name")
elif mode == 6:  # AcceptMentorInvite
    add_long("characterId")
elif mode == 7:  # DeclineMentorInvite
    add_long("characterId")
elif mode == 8:  # AssignMentor
    pass
elif mode == 9:  # Load
    pass
elif mode == 10:  # LoginPoints
    add_int("points")
    add_long("timestamp")
elif mode == 11:  # DailyPoints
    add_int("maxDaily")
    add_int("currentMenteePoints")
    add_long("resetTimestamp")
elif mode == 12:  # PairMode
    add_long("pairedCharacterId1")
    add_long("pairedCharacterId2")
elif mode == 14:  # ReceiveMenteeInvite
    add_unicode_str("inviterName")
    # --- layout truncated: pWriter used in non-write statement (no wire-safe continuation) ---
elif mode == 15:  # UpdateOnlineStatus
    count = add_int("updates.Count")
    for i0 in range(count):
        add_long("characterId")
        add_byte("online ? (byte) 1 : (byte) 0")
elif mode == 16:  # ReturningUserStatus
    add_bool("isReturningUser")
    add_int("param")
