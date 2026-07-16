''' SkillBookTree '''
# Auto-generated (Phase 4a/4b) from SkillBookPacket: Load, Save, Rename, Expand
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_int("skillBook.MaxSkillTabs")
    add_long("skillBook.ActiveSkillTabId")
    count = add_int("skillBook.SkillTabs.Count")
    for i0 in range(count):
        add_long("Id")
        add_unicode_str("Name")
        count = add_int("Skills.Count")
        for i1 in range(count):
            add_int("skillId")
            add_int("points")
elif mode == 1:  # Save
    add_long("skillBook.ActiveSkillTabId")
    add_long("savedTabId")
    add_int("ranksSaved")
elif mode == 2:  # Rename
    add_long("skillTab.Id")
    add_unicode_str("skillTab.Name")
    add_bool("error")
elif mode == 4:  # Expand
    add_int("skillBook.MaxSkillTabs")
