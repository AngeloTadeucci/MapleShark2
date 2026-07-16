''' Party '''
# Auto-generated (Phase 4a/4b) from PartyPacket: Error, Joined, Leave, Kicked, NotifyLogin, NotifyLogout, Disband, NotifyUpdateLeader, Load, Invite, Update, UpdateDungeonInfo, UpdateGearScore, Tombstone, UpdateStats, PartyNotice, InterfaceNotice, DungeonReset, LoadPartySearchListing, PartySearch, PartySearchDungeon, RandomDungeonLockout, HelperBroadcast, DungeonHelperCooldown, JoinRequest, StartVote, ReadyCheck, EndVote, SurvivalPartySearch
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Error
    add_byte("error")
    add_unicode_str("targetName")
elif mode == 2:  # Joined
    # --- layout truncated: model  has no traceable WriteTo (no wire-safe continuation) ---
    pass
elif mode == 3:  # Leave
    add_long("targetCharacterId")
    add_bool("isSelf")
elif mode == 4:  # Kicked
    add_long("targetCharacterId")
elif mode == 5:  # NotifyLogin
    # --- layout truncated: model  has no traceable WriteTo (no wire-safe continuation) ---
    pass
elif mode == 6:  # NotifyLogout
    add_long("targetCharacterId")
elif mode == 7:  # Disband
    pass
elif mode == 8:  # NotifyUpdateLeader
    add_long("newLeaderCharacterId")
elif mode == 9:  # Load
    add_bool("joinNotify")
    add_int("party.Id")
    add_long("party.LeaderCharacterId")
    add_byte("party.Members.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 11:  # Invite
    add_unicode_str("name")
    add_int("partyId")
elif mode == 12:  # Update
    add_long("member.CharacterId")
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
    # --- layout truncated: PartyMember: PlayerInfo: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 14:  # UpdateDungeonInfo
    add_long("member.CharacterId")
    # --- layout truncated: pWriter used in non-write statement (no wire-safe continuation) ---
elif mode == 15:  # UpdateGearScore
    add_long("characterId")
    add_int("gearScore")
elif mode == 18:  # Tombstone
    add_long("characterId")
    add_bool("isDarkTomb")
elif mode == 19:  # UpdateStats
    add_long("member.CharacterId")
    add_long("member.AccountId")
    add_int("member.Info.TotalHp")
    add_int("member.Info.CurrentHp")
    add_short("member.Info.DeathState")
elif mode == 20:  # PartyNotice
    add_unicode_str("message.ToString()")
    add_unicode_str("fieldEvent")
    add_unicode_str("arg")
elif mode == 21:  # InterfaceNotice
    add_bool("isLocalized")
    add_int("group")
    # --- layout truncated: InterfaceText: if (no wire-safe continuation) ---
elif mode == 25:  # DungeonReset
    add_bool("dungeonSet")
    add_int("dungeonId")
elif mode == 26:  # LoadPartySearchListing
    add_bool("party.Search != null")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 30:  # PartySearch
    add_byte("type")
    add_bool("searching")
    add_bool("notify")
    add_byte("dungeonMatchFlags")
elif mode == 31:  # PartySearchDungeon
    add_long("dungeonUid")
elif mode == 35:  # RandomDungeonLockout
    add_long("expiryTimestamp")
elif mode == 37:  # HelperBroadcast
    add_long("senderId")
    add_unicode_str("senderName")
    add_bool("isLocalized")
    add_int("group")
    # --- layout truncated: InterfaceText: if (no wire-safe continuation) ---
elif mode == 40:  # DungeonHelperCooldown
    add_int("cooldownMs")
elif mode == 44:  # JoinRequest
    add_unicode_str("name")
elif mode == 47:  # StartVote
    add_byte("Type")
    add_int("Unknown")
    add_long("DateTimeOffset.UtcNow.ToUnixTimeSeconds()")
    count = add_int("Voters.Count")
    for i0 in range(count):
        add_long("characterId")
    count = add_int("Approvals.Count")
    for i0 in range(count):
        add_long("characterId")
    count = add_int("Disapprovals.Count")
    for i0 in range(count):
        add_long("characterId")
    # --- layout truncated: PartyVote: if (no wire-safe continuation) ---
elif mode == 48:  # ReadyCheck
    add_long("characterId")
    add_bool("isReady")
elif mode == 49:  # EndVote
    pass
elif mode == 54:  # SurvivalPartySearch
    add_bool("searching")
    add_bool("notify")
