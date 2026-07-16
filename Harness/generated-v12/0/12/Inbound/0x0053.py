''' Quest '''
# Auto-generated (Phase 4a/4b) from QuestPacket: Error, Talk, Start, Update, Complete, AbandonResult, Abandon, Expired, SetTracking, SummonPortal, Initialize, LoadQuestStates, LoadQuests, CleanupExpiredQuests, UpdateExplorationMilestone, ClearDailyFieldQuests, DailyReputationMissions, WeeklyReputationMissions, AllianceAccept, AllianceComplete, ClearWeddingMissions
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Error
    add_int("error")
elif mode == 1:  # Talk
    add_int("npc.ObjectId")
    count = add_int("quests.Count")
    for i0 in range(count):
        add_int("quest.Id")
elif mode == 2:  # Start
    add_int("quest.Id")
    add_long("quest.StartTime")
    add_bool("quest.Track")
    count = add_int("quest.Conditions.Count")
    for i0 in range(count):
        add_int("condition.Counter")
elif mode == 3:  # Update
    add_int("quest.Id")
    count = add_int("quest.Conditions.Count")
    for i0 in range(count):
        add_int("condition.Counter")
elif mode == 4:  # Complete
    add_int("quest.Id")
    add_int("rewardIndex")
    add_long("quest.EndTime")
elif mode == 5:  # AbandonResult
    add_int("questId")
    add_int("result")
elif mode == 6:  # Abandon
    add_int("questId")
elif mode == 7:  # Expired
    count = add_int("questIds.Count")
    for i0 in range(count):
        add_int("questId")
elif mode == 9:  # SetTracking
    add_int("questId")
    add_bool("tracked")
elif mode == 18:  # SummonPortal
    add_int("npcObjectId")
    add_int("portalId")
    add_int("startTick")
elif mode == 21:  # Initialize
    add_int("explorationMilestone")
    add_int("missionAttackUsedCount")
elif mode == 22:  # LoadQuestStates
    count = add_int("quests.Count")
    for i0 in range(count):
        add_int("Id")
        add_int("State")
        add_int("CompletionCount")
        add_long("StartTime")
        add_long("EndTime")
        add_bool("Track")
        count = add_int("Conditions.Count")
        for i1 in range(count):
            add_int("condition.Counter")
elif mode == 23:  # LoadQuests
    count = add_int("questIds.Count")
    for i0 in range(count):
        add_int("questId")
elif mode == 25:  # CleanupExpiredQuests
    add_long("serverTime")
elif mode == 26:  # UpdateExplorationMilestone
    add_int("explorationMilestone")
elif mode == 30:  # ClearDailyFieldQuests
    pass
elif mode == 31:  # DailyReputationMissions
    add_bool("freshPick")
    count = add_int("questIds.Count")
    for i0 in range(count):
        add_int("questId")
elif mode == 32:  # WeeklyReputationMissions
    add_bool("freshPick")
    count = add_int("questIds.Count")
    for i0 in range(count):
        add_int("questId")
elif mode == 34:  # AllianceAccept
    add_short("type")
elif mode == 35:  # AllianceComplete
    add_short("type")
elif mode == 38:  # ClearWeddingMissions
    pass
