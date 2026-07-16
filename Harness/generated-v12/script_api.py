import System
import structure_form as sf


class Node:
    """Wraps the contained elements with a start and end node."""
    def __init__(self, name, expand=False):
        self.name = name
        self.expand = expand

    def __enter__(self):
        sf.StartNode(self.name)

    def __exit__(self, exc_type, exc_value, traceback):
        sf.EndNode(self.expand)


def add_byte(name):
    """Adds unsigned byte as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.Byte](name)

def add_byte_coord(name):
    """Byte coords"""
    with Node(name):
        x = sf.Add[System.Byte]('x')
        y = sf.Add[System.Byte]('y')
        z = sf.Add[System.Byte]('z')
        return

def add_short_coord(name):
    """Short coords"""
    with Node(name):
        x = sf.Add[System.Int16]('x')
        y = sf.Add[System.Int16]('y')
        z = sf.Add[System.Int16]('z')
        return

def add_float_coord(name):
    """Float coords"""
    with Node(name):
        x = sf.Add[System.Single]('x')
        y = sf.Add[System.Single]('y')
        z = sf.Add[System.Single]('z')
        return

def add_sbyte(name):
    """Adds signed byte as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.SByte](name)


def add_ushort(name):
    """Adds unsigned short as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.UInt16](name)


def add_short(name):
    """Adds signed short as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.Int16](name)


def add_uint(name):
    """Adds unsigned int as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.UInt32](name)


def add_int(name):
    """Adds signed int as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.Int32](name)


def add_ulong(name):
    """Adds unsigned long as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.UInt64](name)


def add_long(name):
    """Adds signed long as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.Int64](name)


def add_float(name):
    """Adds single-precision float as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.Single](name)


def add_double(name):
    """Adds double-precision float as a field with given name to the structure view, and returns the value."""
    return sf.Add[System.Double](name)


def add_bool(name):
    """
    Adds 1 byte bool as a field with given name to the structure view, and returns the value.
    - false when byte is 0, true otherwise
    """
    return sf.Add[System.Boolean](name)


def add_str(name):
    """
    Adds a 1-byte/character string preceded by its length as a short, and returns the value
    - Format: [NN NN] [SS SS ...]
    """
    with Node(name):
        size = sf.Add[System.Int16]('size')
        data = sf.AddField(name, size)
        return System.Text.Encoding.UTF8.GetString(data, 0, size)


def add_unicode_str(name):
    """
    Adds a 2-byte/character string preceded by its length as a short, and returns the value.
    - Format: [NN NN] [SSSS SSSS ...]
    """
    with Node(name):
        size = sf.Add[System.Int16]('size') * 2
        data = sf.AddField(name, size)
        return System.Text.Encoding.Unicode.GetString(data, 0, size)


def add_field(name, length=0):
    """Adds a field with given name and length to the structure view, and returns System.Byte[]."""
    sf.AddField(name, length)


def remaining():
    """Returns the number of bytes remaining unprocessed in the packet."""
    return sf.Remaining()


def start_node(name):
    """Adds a sub node with given name as the new parent until required matching EndNode, and returns nothing."""
    sf.StartNode(name)


def end_node(expand=False):
    """Completes the last StartNode, expanding contents if expand is true, and returns nothing."""
    sf.EndNode(expand)


def log(message, level='Info'):
    """Logs the specified message with a log level. (Trace, Debug, Info, Warn, Error, Fatal)"""
    sf.Log(message, level)

def write_character(name):
    """Character"""
    with Node(name):
        add_long("player.AccountId")
        add_long("player.CharacterId")
        add_unicode_str("player.Name")
        add_byte("player.Gender")
        add_byte("1")

        add_long("player.AccountId")
        add_int("")
        add_int("player.MapId")
        add_int("player.MapId")
        add_int("")
        add_short("player.Levels.Level")
        add_short("")
        add_int("player.Job")
        add_int("player.JobCode")
        add_int("player.Stats[PlayerStatId.Hp].Current")
        add_int("player.Stats[PlayerStatId.Hp].Max")
        add_short("")
        add_long("")
        add_long("")
        add_long("")
        add_int("player.ReturnMapId")
        add_float("player.ReturnCoord x")
        add_float("player.ReturnCoord y")
        add_float("player.ReturnCoord z")
        add_int("gearscore")
        add_int("player.SkinColor")
        add_int("player.SkinColor")
        add_long("player.CreationTime")

        add_int("trophyCount")
        add_int("trophyCount")
        add_int("trophyCount")

        add_long("player.Guild.Id")
        add_unicode_str("player.Guild.Name")

        add_unicode_str("player.Motto")

        add_unicode_str("player.ProfileUrl")
        count = add_byte("clubCount")
        for y in range(0, count):
            add_bool("true")
            add_long("club uid")
            add_unicode_str("club name")

        add_byte("")
        add_int("")

        for y in range(0, 11):
            add_int("mastery exp")

        add_unicode_str("")
        add_long("player.UnknownId")
        add_long("2000")
        add_long("3000")

        count = add_int("countA")
        for x in range(0, count):
            add_long("")

        add_byte("")
        add_byte("")
        add_long("")
        add_int("")
        add_int("")
        add_long("")
        add_int("player.Levels.PrestigeLevel")
        add_long("")

        add_short("")
        return

def decode_item(id):
    with Node("Item: " + str(id)):
        add_int("Amount")
        add_int("Unknown")
        add_int("Unknown")
        add_long("CreationTime")
        add_long("ExpiryTime")
        add_long("Unknown")
        add_int("TimesChangedAttribute")
        add_int("RemainingUses")
        add_byte("IsLocked")
        add_long("UnlockTime")
        add_short("GlamorForges")
        add_bool("Unknown")
        add_int("Unknown")
        add_int("item color")
        add_int("item color")
        add_int("item color")
        add_int("index")
        add_int("palette")
        # Item positioning
        if id / 100000 == 113:
            add_field("Cap Position", 13 * 4)
        elif id / 100000 == 102:
            add_field("Back Hair Position", 4 * 7)
            add_field("Front Hair Position", 4 * 7)
        elif id / 100000 == 104:
            add_field("Cosmetic Position", 4 * 4)
        add_byte("Unknown")
        with Node("Stats"):
            add_byte("idk")
            for i in range(9):
                with Node("Iteration " + str(i)):
                    count = add_short("count")
                    for j in range(count):
                        add_short("itemAttribute")
                        add_int("flat")
                        add_float("percent")
                    count = add_short("count")
                    for j in range(count):
                        add_short("itemAttribute")
                        add_float("percent")
                        add_float("flat")
                    add_int("Unknown")
        # Sub
        add_int("Enchants")
        add_int("EnchantExp")
        add_bool("EnchantBasedChargeExp")
        add_long("Unknown+191")
        add_int("Unknown+199")
        add_int("Unknown+203")
        add_bool("CanRepackage")
        add_int("EnchantCharges")

        with Node("general stat diff"):
            count = add_byte("Count")
            for e in range(count):
                add_int("stat index")
                add_int("int diff")
                add_float("float diff")
        # EndSub
        #Sub
        add_int("???")
        with Node("stat diff"):
            count = add_int("Count")
            for i in range(count):
                add_short("itemAttribute")
                add_int("flat")
                add_float("percent")
        with Node("bonus stat diff"):
            count = add_int("Count")
            for i in range(count):
                add_short("itemAttribute")
                add_float("percent")
                add_float("flat")
        # EndSub

        #Testing UGC
        if id == 11400608 or id == 11500523 or id == 11600035:
            with Node("UGC", True):
                # decode_ugc_data()
                add_field("Unknown", 50)

        # Pet
        if id / 100000 == 600 or id / 100000 == 610 or id / 100000 == 611 or id / 100000 == 629:
            with Node("Pet", True):
                add_unicode_str("PetName")
                add_long("PetExp")
                add_int("Unknown")
                add_int("PetLevel")
                add_byte("Unknown")

        # Music Score
        if id / 100000 == 351:
            with Node("MusicScore", True):
                add_int("MusicId")
                add_int("Instrument")
                add_unicode_str("ScoreTitle")
                add_unicode_str("Author")
                add_int("Unknown (1)")
                add_long("AuthorCharacterId")
                add_field("Unknown", 17)

        # Badge
        if id / 1000000 == 70:
            with Node("Badge", True):
                add_byte("Unknown")
                add_byte("Unknown")
                add_unicode_str("BadgeIdStr")
                if id == 70100000: ## PetSkinBadge
                    add_int("PetSkinId")
                elif id == 70100001: ## Transparency
                    add_bool("Headgear")
                    add_bool("Eyewear")
                    add_bool("Top")
                    add_bool("Bottom")
                    add_bool("Cape")
                    add_bool("Earrings")
                    add_bool("Face")
                    add_bool("Gloves")
                    add_bool("Unknown")
                    add_bool("Shoes")

        add_int("TransferFlag")
        add_byte("???")
        add_int("remaining trades")
        add_int("???")
        add_byte("???")
        add_byte("???")
        f = add_byte("IsBound")
        if f != 0:
            add_long("BoundToCharId")
            add_unicode_str("BoundToName")
        add_byte("socks count")
        g = add_byte("unlocked count")
        for x in range(g):
                flag1 = add_bool("flag")
                if flag1:
                    add_int("id")
                    owned = add_bool("owned")
                    if owned:
                        add_long("character id")
                        add_unicode_str("character name")
                locked = add_bool("locked")
                if locked:
                    add_bool("locked")
                    add_long("unlock time")
        b = add_long("PairedCharacterId")
        if b != 0:
            add_unicode_str("PairedName")
            add_byte("Unknown")
        add_long("???")
        add_unicode_str("Unknown")