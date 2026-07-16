''' BannerList '''
# Auto-generated (Phase 4a/4b) from BannerListPacket: Load
from script_api import *

count = add_short("banners.Count")
for i0 in range(count):
    add_int("Id")
    add_unicode_str("Name")
    add_unicode_str("Type.ToString()")
    add_unicode_str("Function.ToString()")
    add_unicode_str("FunctionParameter")
    add_unicode_str("Url")
    add_int("Language")
    add_long("BeginTime")
    add_long("EndTime")
