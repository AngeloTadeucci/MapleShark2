''' ResponsePet '''
# Auto-generated (Phase 4a/4b) from PetPacket: Summon, UnSummon, Unknown2, Rename, UpdatePotionConfig, UpdateLootConfig, LoadCollection, AddCollection, Load, Fusion, LevelUp, FusionCount, IsSummoned, PetInfo, Evolve, EvolvePoints, Error, MasterSnare, Unknown21
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Summon
    add_int("pet.OwnerId")
    add_int("pet.ObjectId")
    # --- layout truncated: pWriter.WritePetItem (opaque write) (no wire-safe continuation) ---
elif mode == 1:  # UnSummon
    add_int("pet.OwnerId")
    add_long("pet.Pet.Uid")
elif mode == 2:  # Unknown2
    add_int("ownerId")
elif mode == 4:  # Rename
    add_int("ownerId")
    # --- layout truncated: pWriter.WriteProfile (opaque write) (no wire-safe continuation) ---
elif mode == 5:  # UpdatePotionConfig
    add_int("ownerId")
    count = add_byte("potionConfigs.Length")
    for i0 in range(count):
        add_field("config", 12)
elif mode == 6:  # UpdateLootConfig
    add_int("ownerId")
    add_field("lootConfig", 13)
elif mode == 7:  # LoadCollection
    count = add_int("collection.Count")
    for i0 in range(count):
        add_int("petId")
        add_short("rarity")
elif mode == 8:  # AddCollection
    add_int("petId")
    add_short("rarity")
elif mode == 9:  # Load
    add_int("ownerId")
    # --- layout truncated: pWriter.WriteProfile (opaque write) (no wire-safe continuation) ---
elif mode == 10:  # Fusion
    add_int("pet.OwnerId")
    add_long("pet.Pet.Pet?.Exp ?? 0")
    add_long("pet.Pet.Uid")
elif mode == 11:  # LevelUp
    add_int("pet.OwnerId")
    add_int("pet.Pet.Pet?.Level ?? 1")
    add_long("pet.Pet.Uid")
elif mode == 12:  # FusionCount
    add_int("count")
elif mode == 15:  # IsSummoned
    add_bool("isSummoned")
elif mode == 16:  # PetInfo
    add_int("ownerId")
    add_int("pet.Id")
    add_long("pet.Uid")
    add_int("pet.Rarity")
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
elif mode == 17:  # Evolve
    add_int("ownerId")
    add_long("pet.Uid")
    add_byte("pet.Rarity")
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
elif mode == 18:  # EvolvePoints
    add_int("ownerId")
    add_int("pet.Pet?.EvolvePoints ?? 0")
    add_long("pet.Uid")
elif mode == 19:  # Error
    add_int("error")
elif mode == 20:  # MasterSnare
    add_int("itemId")
elif mode == 21:  # Unknown21
    add_int("ownerId")
    # --- layout truncated: pWriter.WritePetItem (opaque write) (no wire-safe continuation) ---
