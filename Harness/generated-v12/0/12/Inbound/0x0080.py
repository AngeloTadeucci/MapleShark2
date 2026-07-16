''' ProxyGameObj '''
# Auto-generated (Phase 4a/4b) from ProxyObjectPacket: AddPlayer, RemovePlayer, UpdatePlayer, AddNpc, RemoveNpc, UpdateNpc, AddPet, RemovePet, UpdatePet
from script_api import *

mode = add_byte("mode")
if mode == 3:  # AddPlayer
    add_int("fieldPlayer.ObjectId")
    add_long("player.Character.Id")
    add_long("player.Account.Id")
    add_unicode_str("player.Character.Name")
    add_unicode_str("player.Character.Picture")
    add_unicode_str("player.Character.Motto")
    add_bool("fieldPlayer.IsDead")
    add_field("fieldPlayer.Position", 12)
    add_short("player.Character.Level")
    add_short("player.Character.Job.Code()")
    add_int("player.Character.Job")
    add_int("player.Home.PlotMapId")
    add_int("player.Home.PlotNumber")
    add_int("player.Home.ApartmentNumber")
    add_unicode_str("player.Home.Indoor.Name")
    add_int("fieldPlayer.Stats.Values.GearScore")
    add_short("fieldPlayer.State")
    add_field("player.Character.AchievementInfo", 12)
elif mode == 4:  # RemovePlayer
    add_int("objectId")
elif mode == 5:  # UpdatePlayer
    add_int("fieldPlayer.ObjectId")
    add_byte("flag")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 6:  # AddNpc
    add_int("fieldNpc.ObjectId")
    add_int("fieldNpc.Value.Id")
    add_bool("fieldNpc.IsDead")
    add_int("fieldNpc.SpawnPointId")
    add_field("fieldNpc.Position", 12)
elif mode == 7:  # RemoveNpc
    add_int("objectId")
elif mode == 8:  # UpdateNpc
    add_int("fieldNpc.ObjectId")
    add_bool("fieldNpc.IsDead")
    add_field("fieldNpc.Position", 12)
elif mode == 9:  # AddPet
    add_int("fieldPet.ObjectId")
    add_int("fieldPet.SkinId")
    add_int("fieldPet.Value.Id")
    add_bool("fieldPet.IsDead")
    add_field("fieldPet.Position", 12)
elif mode == 10:  # RemovePet
    add_int("objectId")
elif mode == 11:  # UpdatePet
    add_int("fieldPet.ObjectId")
    add_bool("fieldPet.IsDead")
    add_field("fieldPet.Position", 12)
