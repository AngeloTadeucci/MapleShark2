''' Mail '''
# Auto-generated (Phase 4a/4b) from MailPacket: Load, Send, Read, Returned, Collect, CollectRead, AdBill, Deleted, Notify, NotifyTemporary, StartList, EndList, Error, Gift
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Load
    # --- layout truncated: loop body unresolved (Mail: if) (no wire-safe continuation) ---
    pass
elif mode == 1:  # Send
    add_long("mailId")
elif mode == 2:  # Read
    add_long("mail.Id")
    add_long("mail.ReadTime")
elif mode == 3:  # Returned
    add_long("Unknown")
elif mode == 10:  # Collect
    add_long("mailId")
    add_bool("success")
    # --- layout truncated: if (no wire-safe continuation) ---
elif mode == 11:  # CollectRead
    add_long("mail.Id")
    add_long("mail.ReadTime")
elif mode == 12:  # AdBill
    add_long("mail.Id")
    add_long("Unknown")
elif mode == 13:  # Deleted
    add_long("mailId")
elif mode == 14:  # Notify
    add_int("unreadCount")
    add_bool("alert")
    add_int("unreadCount")
elif mode == 15:  # NotifyTemporary
    pass
elif mode == 16:  # StartList
    pass
elif mode == 17:  # EndList
    pass
elif mode == 20:  # Error
    add_byte("code")
    add_byte("error")
elif mode == 22:  # Gift
    add_unicode_str("Unknown")
    add_byte("Unknown")
    add_int("Unknown")
    add_byte("Unknown")
    add_int("Unknown")
    add_str("Unknown")
    add_unicode_str("Unknown")
