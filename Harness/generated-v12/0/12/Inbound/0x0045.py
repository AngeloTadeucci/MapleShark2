''' SkillPoint '''
# Auto-generated (Phase 4a/4b) from SkillPointPacket: Sources
from script_api import *

add_int("TotalPoints")
count = add_int("Points.Count")
for i0 in range(count):
    add_int("source")
    count = add_int("Ranks.Count")
    for i1 in range(count):
        add_short("rank")
        add_int("points")
