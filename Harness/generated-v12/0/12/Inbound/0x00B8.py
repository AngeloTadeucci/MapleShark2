''' Pvp '''
# Auto-generated (Phase 4a/4b) from PvpPacket: GuildPvpOpen, IndividualPvpQueueStart, IndividualPvpQueueCancel, IndividualPvpMatchProposed, KillLog, DuelPvpQueueStart, DuelPvpQueueCancel, DuelPvpMatchProposed, NotifyCannotApply, Result, ToggleInvincible, UpdateRating, BattleStats, ObserveNotification, Fight, RoundDisplay, RoundWin, RoundLose, Draw, Perfect, PlayerState, ResetScoreboard, UpdatePlayer, UpdateRoundTimer, ShowKillNotification, ScoreboardAddPlayer, UpdateTeamScores, UpdatePlayerKillStats, TeamResult, UpdateFlagGauge, ShowTeamNotification, ShowFlagCapture, GuildTeamTopUi, GuildTeamResult
from script_api import *

mode = add_byte("mode")
if mode == 4:  # GuildPvpOpen
    add_long("guildId")
    add_unicode_str("guildName")
elif mode == 9:  # IndividualPvpQueueStart
    add_int("type")
elif mode == 10:  # IndividualPvpQueueCancel
    pass
elif mode == 11:  # IndividualPvpMatchProposed
    add_int("type")
elif mode == 12:  # KillLog
    count = add_byte("killPairs.Count")
    for i0 in range(count):
        add_int("killerObjectId")
        add_int("victimObjectId")
elif mode == 14:  # DuelPvpQueueStart
    pass
elif mode == 15:  # DuelPvpQueueCancel
    pass
elif mode == 16:  # DuelPvpMatchProposed
    add_bool("found")
elif mode == 17:  # NotifyCannotApply
    add_int("0")
elif mode == 18:  # Result
    add_long("characterId")
    add_unicode_str("name")
    add_long("characterId")
    add_int("roundsWon")
    add_int("newElo")
    add_int("eloChange")
    add_int("valorTokens")
    add_unicode_str("opponentName")
    add_long("opponentCharacterId")
    add_int("opponentRoundsWon")
    add_int("opponentNewElo")
    add_int("opponentEloChange")
    add_int("opponentValorTokens")
elif mode == 19:  # ToggleInvincible
    add_bool("enabled")
elif mode == 22:  # UpdateRating
    add_int("seasonId")
    add_int("currentElo")
    add_int("highestScore")
    add_int("weeklyValor")
elif mode == 23:  # BattleStats
    count = add_int("vsClassStats.Count")
    for i0 in range(count):
        add_int("jobId")
        add_int("record.Wins")
        add_int("record.Losses")
elif mode == 25:  # ObserveNotification
    pass
elif mode == 26:  # Fight
    add_int("duration")
elif mode == 27:  # RoundDisplay
    add_int("delay")
    add_int("round")
elif mode == 28:  # RoundWin
    add_int("delay")
elif mode == 29:  # RoundLose
    add_int("delay")
elif mode == 30:  # Draw
    add_int("delay")
elif mode == 31:  # Perfect
    add_int("delay")
elif mode == 100:  # PlayerState
    add_int("objectId")
    add_int("TeamId")
    add_byte("KillCount")
    add_byte("ModeType")
elif mode == 102:  # ResetScoreboard
    pass
elif mode == 103:  # UpdatePlayer
    add_long("characterId")
    add_int("kills")
    add_int("deaths")
    add_int("score")
elif mode == 104:  # UpdateRoundTimer
    add_int("roundTimeSeconds")
elif mode == 105:  # ShowKillNotification
    add_int("stringTableId")
    add_unicode_str("killerName")
elif mode == 106:  # ScoreboardAddPlayer
    add_long("characterId")
    add_int("killCount")
elif mode == 108:  # UpdateTeamScores
    add_int("team1Score")
    add_int("team2Score")
elif mode == 109:  # UpdatePlayerKillStats
    add_long("characterId")
    add_int("kills")
    add_int("deaths")
    add_int("score")
elif mode == 110:  # TeamResult
    add_int("team1Score")
    add_int("team2Score")
elif mode == 111:  # UpdateFlagGauge
    add_int("unk")
    add_int("gaugeValue")
elif mode == 112:  # ShowTeamNotification
    add_int("team")
    add_int("result")
elif mode == 113:  # ShowFlagCapture
    add_unicode_str("playerName")
    add_byte("team")
elif mode == 114:  # GuildTeamTopUi
    add_long("teamA.GuildId")
    add_unicode_str("teamA.GuildName")
    add_unicode_str("teamA.Emblem")
    add_long("teamB.GuildId")
    add_unicode_str("teamB.GuildName")
    add_unicode_str("teamB.Emblem")
elif mode == 117:  # GuildTeamResult
    add_unicode_str("GuildName")
    add_long("GuildId")
    add_int("Wins")
    add_int("Rating")
    add_int("DeltaRating")
    add_unicode_str("Emblem")
    add_unicode_str("GuildName")
    add_long("GuildId")
    add_int("Wins")
    add_int("Rating")
    add_int("DeltaRating")
    add_unicode_str("Emblem")
    add_int("valorTokenAmount")
