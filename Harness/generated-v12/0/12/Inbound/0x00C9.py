''' PlayInstrument '''
# Auto-generated (Phase 4a/4b) from InstrumentPacket: StartImprovise, Improvise, StopImprovise, StartScore, StopScore, LeaveEnsemble, ComposeScore, RemainUses, ViewScore, Fireworks, Unknown
from script_api import *

mode = add_byte("mode")
if mode == 0:  # StartImprovise
    add_int("instrument.ObjectId")
    add_int("instrument.OwnerId")
    add_field("instrument.Position", 12)
    add_int("instrument.Value.MidiId")
    add_int("instrument.Value.PercussionId")
elif mode == 1:  # Improvise
    add_int("instrument.ObjectId")
    add_int("instrument.OwnerId")
    # --- layout truncated: Write<InstrumentHandler.MidiMessage> unresolved (no wire-safe continuation) ---
elif mode == 2:  # StopImprovise
    add_int("instrument.ObjectId")
    add_int("instrument.OwnerId")
elif mode == 3:  # StartScore
    add_bool("score.Music != null")
    add_int("instrument.ObjectId")
    add_int("instrument.OwnerId")
    add_field("instrument.Position", 12)
    add_int("instrument.StartTick.Truncate32()")
    add_int("instrument.Value.MidiId")
    add_int("instrument.Value.PercussionId")
    add_bool("instrument.Ensemble")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 4:  # StopScore
    add_int("instrument.ObjectId")
    add_int("instrument.OwnerId")
elif mode == 6:  # LeaveEnsemble
    pass
elif mode == 8:  # ComposeScore
    add_long("item.Uid")
    add_int("Amount")
    add_int("Unknown")
    add_int("-1")
    add_long("CreationTime")
    add_long("ExpiryTime")
    add_long("Unknown")
    add_int("TimeChangedOption")
    add_int("RemainUses")
    add_bool("IsLocked")
    add_long("UnlockTime")
    add_short("GlamorForges")
    add_bool("false")
    add_int("GachaDismantleId")
    add_field("Color", 20)
    add_byte("Unknown")
    # --- layout truncated: Item: ItemStats: loop count 'Unknown' not wire-linked to 'TYPE_COUNT' (no wire-safe continuation) ---
elif mode == 9:  # RemainUses
    add_long("scoreUid")
    add_int("remainUses")
elif mode == 10:  # ViewScore
    add_long("itemUid")
    add_str("mml")
elif mode == 14:  # Fireworks
    add_int("objectId")
elif mode == 17:  # Unknown
    add_byte("value")
