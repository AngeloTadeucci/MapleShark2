''' CharacterAbility '''
# Auto-generated (Phase 4a/4b) from CharacterAbilityPacket: Load, Learn
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_int("LearnedAbilities.Count")
    for i0 in range(count):
        add_int("ability")
    add_long("ResetTimestamp")
    add_int("BonusPoints")
elif mode == 2:  # Learn
    add_int("abilityId")
