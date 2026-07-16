''' DungeonReward '''
# Auto-generated (Phase 4a/4b) from DungeonRewardPacket: Dungeon, MiniGame, Unknown2, Unknown3
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Dungeon
    add_bool("IsDungeonSuccess")
    add_int("DungeonId")
    add_bool("WithParty")
    add_int("TotalSeconds")
    add_int("HighestScore")
    add_int("Score")
    add_int("BonusFlag")
    count = add_int("Rewards.Count")
    for i0 in range(count):
        add_byte("type")
        add_int("value")
    count = add_int("RewardItems.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_int("item.Amount")
        add_int("item.Rarity")
        add_bool("item.TradableCountDeduction")
        add_bool("item.RepackingLimitCountDeduction")
        add_bool("item.DisableBreak")
    count = add_int("BonusRewards.Count")
    for i0 in range(count):
        add_byte("type")
        add_int("value")
    count = add_int("BonusRewardItems.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_int("item.Amount")
        add_int("item.Rarity")
        add_bool("item.TradableCountDeduction")
        add_bool("item.RepackingLimitCountDeduction")
        add_bool("item.DisableBreak")
elif mode == 1:  # MiniGame
    add_int("ClearedRounds")
    add_int("TotalRounds")
    count = add_int("Rewards.Count")
    for i0 in range(count):
        add_byte("type")
        add_int("value")
    count = add_int("RewardItems.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_int("item.Rarity")
        add_int("item.Amount")
        add_bool("item.TradableCountDeduction")
        add_bool("item.RepackingLimitCountDeduction")
        add_bool("item.DisableBreak")
elif mode == 2:  # Unknown2
    count = add_int("rewards.Count")
    for i0 in range(count):
        add_byte("type")
        add_int("value")
    count = add_int("rewardItems.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_int("item.Rarity")
        add_int("item.Amount")
        add_bool("item.TradableCountDeduction")
        add_bool("item.RepackingLimitCountDeduction")
        add_bool("item.DisableBreak")
elif mode == 3:  # Unknown3
    add_bool("unknown")
    count = add_int("rewards.Count")
    for i0 in range(count):
        add_byte("type")
        add_int("value")
    count = add_int("rewardItems.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_int("item.Rarity")
        add_int("item.Amount")
        add_bool("item.TradableCountDeduction")
        add_bool("item.RepackingLimitCountDeduction")
        add_bool("item.DisableBreak")
