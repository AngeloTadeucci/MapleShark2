''' Mapleopoly '''
# Auto-generated (Phase 4a/4b) from MapleopolyPacket: Load, Roll, Result, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    add_int("totalTileCount")
    add_int("freeRollAmount")
    add_int("ticketId")
    add_int("playerTicketAmount")
    count = add_int("tiles.Count")
    for i0 in range(count):
        add_short("tile.Type")
        add_int("tile.MoveAmount")
        add_int("tile.Item.ItemId")
        add_byte("tile.Item.Rarity")
        add_int("tile.Item.Amount")
elif mode == 2:  # Roll
    add_byte("error")
    add_int("tileLocation")
    add_int("dice1")
    add_int("dice2")
    add_int("Unknown")
elif mode == 4:  # Result
    add_short("slot.Type")
    add_int("slot.MoveAmount")
    add_int("totalTileCount")
    add_int("freeRollAmount")
    add_int("slot.Item.ItemId")
    add_byte("slot.Item.Rarity")
    add_int("slot.Item.Amount")
elif mode == 6:  # Error
    add_byte("error")
