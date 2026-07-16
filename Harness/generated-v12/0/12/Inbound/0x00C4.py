''' QuizEvent '''
# Auto-generated (Phase 4a) from QuizEventPacket: Question, Answer
from script_api import *

mode = add_byte("mode")
if mode == 0:  # Question
    add_unicode_str("category")
    add_unicode_str("question")
    add_unicode_str("answer")
    add_int("duration")
elif mode == 1:  # Answer
    add_bool("isTrue")
    add_unicode_str("answer")
    add_int("duration")
