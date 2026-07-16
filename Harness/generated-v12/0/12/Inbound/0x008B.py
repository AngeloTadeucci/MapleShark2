''' GuideRecord '''
# Auto-generated (Phase 4a/4b) from GuideRecordPacket: Load
from script_api import *

count = add_int("records.Count")
for i0 in range(count):
    add_int("recordId")
    add_int("step")
add_byte("0x02")
