''' Achieve '''
# Auto-generated (Phase 4a/4b) from AchievementPacket: Initialize, Load, Update, Favorite
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Initialize
    pass
elif mode == 1:  # Load
    count = add_int("achievements.Count")
    for i0 in range(count):
        add_int("achievement.Id")
        add_int("achievement.CurrentGrade")
        add_byte("Status")
        add_int("Completed ? 1 : 0")
        add_int("CurrentGrade")
        add_int("RewardGrade")
        add_bool("Favorite")
        add_long("Counter")
        count = add_int("Grades.Count")
        for i1 in range(count):
            add_int("grade")
            add_long("timeAcquired")
elif mode == 2:  # Update
    add_int("achievement.Id")
    add_byte("Status")
    add_int("Completed ? 1 : 0")
    add_int("CurrentGrade")
    add_int("RewardGrade")
    add_bool("Favorite")
    add_long("Counter")
    count = add_int("Grades.Count")
    for i0 in range(count):
        add_int("grade")
        add_long("timeAcquired")
elif mode == 4:  # Favorite
    add_int("achievement.Id")
    add_bool("achievement.Favorite")
