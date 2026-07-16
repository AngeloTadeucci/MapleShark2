''' FieldAddPet '''
# Auto-generated (Phase 4a/4b) from FieldPacket: AddPet
from script_api import *

add_int("pet.ObjectId")
add_int("pet.SkinId")
add_int("pet.Value.Id")
add_field("pet.Position", 12)
add_field("pet.Rotation", 12)
add_float("pet.Scale")
add_int("pet.OwnerId")
# --- layout truncated: pWriter.WriteNpcStats (opaque write) (no wire-safe continuation) ---
