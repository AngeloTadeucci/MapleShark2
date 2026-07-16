# Harness — MATRIX -> 2464

scripts from build : (matrix, see src column)
packets from build : 2464
packets considered : 1.610
packets executed   : 3.204  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                 18   0.6%
OkExact               2.588   80.8%
UnderRead               557   17.4%
OverRead                 41   1.3%

of packets a script actually ran on (3.186):
  clean (consumed exactly) : 81.2%
  over-read (WRONG)        : 1.3%
  under-read (ambiguous)   : 17.5%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12         514       514   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         514       514   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         514       514   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12         416       416   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0059  IN        12         191       191   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12         124       124   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN      2486         124       124     1.6%    98.4%     0.0%    0.0%           14% / 14%
0x0023  IN      2502         124       124     1.6%    98.4%     0.0%    0.0%             9% / 9%
0x0011  IN        12          85        85    51.8%    48.2%     0.0%    0.0%         100% / 100%
0x000B  OUT       12          42        42   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12          39        39   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN      2511          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0048  IN        12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2504          15        15     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0048  IN      2507          15        15     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0080  IN        12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005F  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AA  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0053  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0095  IN         -           5         -                                     no script
0x004C  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN      2512           4         4     0.0%    75.0%    25.0%    0.0%          28% / 100%
0x006E  IN      2486           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x011B  IN        12           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x0022  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2507           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2511           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2524           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2525           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2550           3         3     0.0%   100.0%     0.0%    0.0%           20% / 23%
0x006C  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B8  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  OUT        -           2         -                                     no script
0x0014  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0032  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0046  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN      2529           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0063  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN      2507           2         2    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x0063  IN      2518           2         2    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006F  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0081  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CE  IN        12           2         2    50.0%    50.0%     0.0%    0.0%          50% / 100%
0x010C  IN      2502           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011E  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x012A  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x012F  IN         -           2         -                                     no script
0x0001  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           1         -                                     no script
0x000F  OUT        -           1         -                                     no script
0x0010  OUT        -           1         -                                     no script
0x0013  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN      2507           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           47% / 47%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002A  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  OUT        -           1         -                                     no script
0x003B  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0050  OUT        -           1         -                                     no script
0x0055  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN      2521           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0055  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0056  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0056  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN      2529           1         1     0.0%     0.0%   100.0%    0.0%           60% / 60%
0x007F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008B  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008F  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A0  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A7  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A9  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AB  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AF  IN         -           1         -                                     no script
0x00B2  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B4  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             2% / 2%
0x00B5  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B7  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B9  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00BB  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00BF  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C6  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CD  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00D3  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00E1  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00E8  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00ED  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F0  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F5  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN      2520           1         1     0.0%     0.0%   100.0%    0.0%             4% / 4%
0x0112  IN         -           1         -                                     no script
0x011D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0127  IN         -           1         -                                     no script
0x0128  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0132  IN         -           1         -                                     no script

## Sample failures

### 0x0048 IN src 2504  over=15 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2504\Inbound\0x0048.py
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 1 of 40 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 1 of 40 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 1 of 40 remain
  last reads before failure (of 12):
        7    4  Single   coords/x = -1,714134E+35
       11    4  Single   coords/y = -1,0492809E-28
       15    4  Single   coords/z = -1,0518699E-28
       19    4  Single   rotation F/x = -1,8024815E+20
       23    4  Single   rotation F/y = 2,77643E-40
       27    4  Single   rotation F/z = 1E-45
       31    4  Single   default coord?/x = 1E-45
       35    4  Single   default coord?/y = 0

### 0x0048 IN src 2507  over=15 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x0048.py
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 1 of 40 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 1 of 40 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 1 of 40 remain
  last reads before failure (of 12):
        7    4  Single   coords/x = -1,714134E+35
       11    4  Single   coords/y = -1,0492809E-28
       15    4  Single   coords/z = -1,0518699E-28
       19    4  Single   rotation/x = -1,8024815E+20
       23    4  Single   rotation/y = 2,77643E-40
       27    4  Single   rotation/z = 1E-45
       31    4  Single   default/x = 1E-45
       35    4  Single   default/y = 0

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1646, only 2 of 1648 remain
  last reads before failure (of 220):
     1582    8  Int64    PlayerInfo/Player+1B0 = 16802512
     1590    8  Int64    PlayerInfo/Player+1B0 = 256
     1598    8  Int64    PlayerInfo/Player+1B0 = 0
     1606    8  Int64    PlayerInfo/Player+1B0 = 0
     1614    8  Int64    PlayerInfo/Player+1B0 = 0
     1622    8  Int64    PlayerInfo/Player+1B0 = 26296771802038272
     1630    8  Int64    PlayerInfo/Player+1B0 = 36028797002186752
     1638    8  Int64    PlayerInfo/Player+1B0 = 0

### 0x002A IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002A.py
  ! Read<Single>: wanted 4 byte(s) at offset 247, only 1 of 248 remain
  last reads before failure (of 69):
      221    2  Int16    Item: 10200000/Stats/Empowerment Stats 1/StatType = 0
      223    4  Int32    Item: 10200000/Stats/Empowerment Stats 1/StatOption 3/IntegerValue = 263168
      227    4  Single   Item: 10200000/Stats/Empowerment Stats 1/StatOption 3/FloatValue = 0
      231    2  Int16    Item: 10200000/Stats/Empowerment Stats 1/StatType = 0
      233    4  Int32    Item: 10200000/Stats/Empowerment Stats 1/StatOption 4/IntegerValue = 0
      237    4  Single   Item: 10200000/Stats/Empowerment Stats 1/StatOption 4/FloatValue = 0
      241    2  Int16    Item: 10200000/Stats/Empowerment Stats 1/StatType = 0
      243    4  Int32    Item: 10200000/Stats/Empowerment Stats 1/StatOption 5/IntegerValue = 0

### 0x00B4 IN src 12  over=1 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B4.py
  ! ReadBytes: negative length -14408 at offset 35/1978
  last reads before failure (of 5):
        0    1  Byte     Function = 0
        1    4  Int32    count = 13
        5    2  Int16    Entry 0/event/size = 13
        7   26  Field    Entry 0/event/event = 460069006E0069007300680050006100..
       33    2  Int16    Entry 1/event/size = -7204

### 0x0015 IN src 2507  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 463, only 1 of 464 remain
  last reads before failure (of 73):
      431    4  Int32    Unlocked Maps/MapId = 788541696
      435    4  Int32    Unlocked Maps/MapId = 1627417856
      439    4  Int32    Unlocked Maps/MapId = 1577060864
      443    4  Int32    Unlocked Maps/MapId = 1946183680
      447    4  Int32    Unlocked Maps/MapId = 1879077888
      451    4  Int32    Unlocked Maps/MapId = 1056994048
      455    4  Int32    Unlocked Maps/MapId = 788544000
      459    4  Int32    Unlocked Maps/MapId = 12032

### 0x004C IN src 2512  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2512\Inbound\0x004C.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  last reads before failure (of 1):
        0    1  Byte     function = 0

### 0x00F6 IN src 2520  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2520\Inbound\0x00F6.py
  ! ReadBytes: wanted 700 byte(s) at offset 11, only 296 of 307 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 0
        1    8  Int64    ClubUid = -879046352201842669
        9    2  Int16    ClubName/size = 350

### 0x0055 IN src 2521  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2521\Inbound\0x0055.py
  ! Read<Single>: wanted 4 byte(s) at offset 8, only 2 of 10 remain
  last reads before failure (of 2):
        0    4  Int32    object id = 270
        4    4  Int32    id = 65792

### 0x0017 IN src 2528  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1646, only 2 of 1648 remain
  last reads before failure (of 220):
     1582    8  Int64    PlayerInfo/Player+1B0 = 16802512
     1590    8  Int64    PlayerInfo/Player+1B0 = 256
     1598    8  Int64    PlayerInfo/Player+1B0 = 0
     1606    8  Int64    PlayerInfo/Player+1B0 = 0
     1614    8  Int64    PlayerInfo/Player+1B0 = 0
     1622    8  Int64    PlayerInfo/Player+1B0 = 26296771802038272
     1630    8  Int64    PlayerInfo/Player+1B0 = 36028797002186752
     1638    8  Int64    PlayerInfo/Player+1B0 = 0

### 0x0055 IN src 2528  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0055.py
  ! Read<Single>: wanted 4 byte(s) at offset 8, only 2 of 10 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 270
        4    4  Int32    NpcId = 65792

### 0x0075 IN src 2529  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2529\Inbound\0x0075.py
  ! Read<Int64>: wanted 8 byte(s) at offset 3, only 2 of 5 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 0
        1    2  Int16    EntityStrId/size = 0
        3    0  Field    EntityStrId/EntityStrId = 
