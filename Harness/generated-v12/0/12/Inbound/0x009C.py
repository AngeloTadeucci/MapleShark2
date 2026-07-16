''' TeamPvp '''
# Auto-generated (Phase 4a/4b) from TeamPvpPacket: UpdateRound, MatchResult
from script_api import *

mode = add_byte("mode")
if mode == 115:  # UpdateRound
    add_int("round")
    add_int("timerEndTick")
    add_int("0")
    count = add_int("fighterCharacterIds.Count")
    for i0 in range(count):
        add_long("characterId")
    add_long("teamA.GuildId")
    add_int("teamA.Wins")
    add_long("teamB.GuildId")
    add_int("teamB.Wins")
elif mode == 116:  # MatchResult
    add_long("winningGuildId")
