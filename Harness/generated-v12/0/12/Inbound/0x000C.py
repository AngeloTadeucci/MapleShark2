''' CharacterList '''
# Auto-generated (Phase 4a/4b) from CharacterListPacket: AddEntries, AppendEntry, DeleteEntry, BeginDelete, CancelDelete, NameChanged, StartList, EndList
from script_api import *

mode = add_byte("mode")
if mode == 0:  # AddEntries
    add_byte("entry.Count")
    # --- layout truncated: loop body has control flow / unknown write (no wire-safe continuation) ---
elif mode == 1:  # AppendEntry
    # --- layout truncated: pWriter.WriteEntry (opaque write) (no wire-safe continuation) ---
    pass
elif mode == 2:  # DeleteEntry
    add_int("error")
    add_long("characterId")
elif mode == 3:  # StartList
    pass
elif mode == 4:  # EndList
    add_bool("false")
elif mode == 5:  # BeginDelete
    add_long("characterId")
    add_int("error")
    add_long("deleteTime")
elif mode == 6:  # CancelDelete
    add_long("characterId")
    add_int("error")
elif mode == 7:  # NameChanged
    add_int("1")
    add_long("characterId")
    add_unicode_str("characterName")
