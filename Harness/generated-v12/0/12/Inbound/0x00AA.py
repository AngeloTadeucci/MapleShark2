''' UserEnv '''
# Auto-generated (Phase 4a/4b) from UserEnvPacket: AddTitle, UpdateTitle, LoadTitles, ItemCollects, InteractedObjects, GatheringCounts, LoadClaimedRewards, Reputation, UpdateReputation, LoadFame, UpdateFame
from script_api import *

mode = add_byte("mode")
if mode == 0:  # AddTitle
    add_int("titleId")
elif mode == 1:  # UpdateTitle
    add_int("objectId")
    add_int("titleId")
elif mode == 2:  # LoadTitles
    count = add_int("titles.Count")
    for i0 in range(count):
        add_int("title")
elif mode == 3:  # ItemCollects
    count = add_int("itemCollects.Count")
    for i0 in range(count):
        add_int("itemId")
        add_byte("quantity")
elif mode == 4:  # InteractedObjects
    count = add_int("interactedObjects.Count")
    for i0 in range(count):
        add_int("id")
elif mode == 8:  # GatheringCounts
    count = add_int("gatheringCounts.Count")
    for i0 in range(count):
        add_int("recipeId")
        add_int("count")
    count = add_int("homeGatheringCounts.Count")
    for i0 in range(count):
        add_int("recipeId")
        add_int("count")
elif mode == 9:  # LoadClaimedRewards
    count = add_int("claimedRewards.Count")
    for i0 in range(count):
        add_int("rewardId")
        add_bool("isClaimed")
elif mode == 10:  # Reputation
    count = add_int("reputations.Count")
    for i0 in range(count):
        add_short("type")
        add_int("amount")
elif mode == 11:  # UpdateReputation
    add_short("type")
    add_int("amount")
elif mode == 12:  # LoadFame
    count = add_int("famePoints.Count")
    for i0 in range(count):
        add_int("id")
        add_long("value")
elif mode == 13:  # UpdateFame
    add_int("id")
    add_long("value")
