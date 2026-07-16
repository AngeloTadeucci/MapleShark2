''' LoadCubes '''
# Auto-generated (Phase 4a/4b) from LoadCubesPacket: Load, PlotState, PlotOwners, PlotExpiry
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_bool("false")
    # --- layout truncated: loop body unresolved (model PlotCube has no traceable WriteTo) (no wire-safe continuation) ---
elif mode == 1:  # PlotState
    count = add_int("plots.Count")
    for i0 in range(count):
        add_int("plot.Number")
        add_bool("plot.State is Maple2.Model.Enum.PlotState.Taken")
elif mode == 2:  # PlotOwners
    count = add_int("plots.Count")
    for i0 in range(count):
        add_int("plot.Number")
        add_int("plot.ApartmentNumber")
        add_unicode_str("plot.Name")
        add_long("plot.OwnerId")
elif mode == 3:  # PlotExpiry
    count = add_int("plots.Count")
    for i0 in range(count):
        add_int("plot.Number")
        add_int("plot.ApartmentNumber")
        add_byte("plot.State")
        add_long("plot.ExpiryTime")
