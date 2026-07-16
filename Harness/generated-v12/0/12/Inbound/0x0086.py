''' Worldmap '''
# Auto-generated (Phase 4a/4b) from WorldMapPacket: Load, Population
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    # --- layout truncated: pWriter.WriteWorldBosses (opaque write) (no wire-safe continuation) ---
    pass
elif mode == 1:  # Population
    add_byte("3")
    count = add_int("populations.Count")
    for i0 in range(count):
        add_field("population", 10)
