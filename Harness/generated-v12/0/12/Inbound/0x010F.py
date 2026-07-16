''' BuddyEmote '''
# Auto-generated (Phase 4a/4b) from BuddyEmotePacket: Invite, InviteConfirm, Error, Accept, Decline, Start, Cancel
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Invite
    add_int("emoteId")
    add_long("sender.Character.Id")
    add_unicode_str("sender.Character.Name")
elif mode == 1:  # InviteConfirm
    add_long("receiverId")
elif mode == 2:  # Error
    add_byte("error")
elif mode == 3:  # Accept
    add_int("emoteId")
    add_long("receiverId")
elif mode == 4:  # Decline
    add_int("emoteId")
    add_long("receiverId")
elif mode == 5:  # Start
    add_int("emoteId")
    add_long("senderId")
    add_long("receiverId")
    add_field("senderPosition", 12)
    add_field("senderRotation", 12)
    add_int("Unknown")
elif mode == 6:  # Cancel
    add_int("emoteId")
    add_long("characterId")
