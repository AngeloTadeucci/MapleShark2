''' ChatStamp '''
# Auto-generated (Phase 4a/4b) from ChatStickerPacket: Load, Add, Use, GroupChat, Favorite, Unfavorite, Error
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    count = add_short("favorites.Count")
    for i0 in range(count):
        add_int("favorite")
    count = add_short("stickers.Count")
    for i0 in range(count):
        add_field("sticker", 12)
elif mode == 2:  # Add
    add_int("itemId")
    count = add_int("stickers.Length")
    for i0 in range(count):
        add_field("sticker", 12)
elif mode == 3:  # Use
    add_int("stickerId")
    add_unicode_str("html")
    add_byte("type")
elif mode == 4:  # GroupChat
    add_int("stickerId")
    add_unicode_str("groupChatName")
elif mode == 5:  # Favorite
    add_int("stickerId")
elif mode == 6:  # Unfavorite
    add_int("stickerId")
elif mode == 7:  # Error
    add_byte("error")
