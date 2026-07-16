''' EventReward '''
# Auto-generated (Phase 4a/4b) from EventRewardPacket: Unknown1, ClaimTimeRunFinalReward, ClaimTimeRunStepReward, FlipGalleryCard, ClaimGalleryReward, SnowmanDailyReward, SnowmanAccumReward, OpenBingo, UpdateBingo, ClaimBingoReward
from script_api import *

mode = add_byte("mode")
if mode == 1:  # Unknown1
    count = add_int("items.Count")
    for i0 in range(count):
        add_int("item.ItemId")
        add_short("item.Rarity")
elif mode == 3:  # ClaimTimeRunFinalReward
    add_int("rewardItem.ItemId")
    add_short("rewardItem.Rarity")
elif mode == 4:  # ClaimTimeRunStepReward
    add_int("rewardItem.ItemId")
    add_short("rewardItem.Rarity")
elif mode == 7:  # FlipGalleryCard
    add_byte("index")
elif mode == 9:  # ClaimGalleryReward
    count = add_int("rewardItems.Length")
    for i0 in range(count):
        add_int("rewardItem.ItemId")
        add_short("rewardItem.Rarity")
elif mode == 11:  # SnowmanDailyReward
    count = add_int("rewardItems.Length")
    for i0 in range(count):
        add_int("rewardItem.ItemId")
        add_short("rewardItem.Rarity")
elif mode == 12:  # SnowmanAccumReward
    count = add_int("rewardItems.Length")
    for i0 in range(count):
        add_int("rewardItem.ItemId")
        add_short("rewardItem.Rarity")
elif mode == 20:  # OpenBingo
    add_int("uid")
    add_unicode_str("checkedNumbers")
    add_unicode_str("rewardsClaimed")
    count = add_int("bingoNumbers.Length")
    for i0 in range(count):
        add_int("number")
elif mode == 21:  # UpdateBingo
    add_unicode_str("checkedNumbers")
    add_unicode_str("rewardsClaimed")
elif mode == 23:  # ClaimBingoReward
    count = add_int("rewards.Length")
    for i0 in range(count):
        add_int("reward.ItemId")
        add_short("reward.Rarity")
