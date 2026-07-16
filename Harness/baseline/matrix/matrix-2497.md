# Harness — MATRIX -> 2497

scripts from build : (matrix, see src column)
packets from build : 2497
packets considered : 1.491
packets executed   : 3.554  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                442   12.4%
OkExact                 770   21.7%
UnderRead             2.044   57.5%
OverRead                298   8.4%

of packets a script actually ran on (3.112):
  clean (consumed exactly) : 24.7%
  over-read (WRONG)        : 9.6%
  under-read (ambiguous)   : 65.7%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x007E  IN         -         382         -                                     no script
0x0058  IN        12         254       254     0.0%   100.0%     0.0%    0.0%            2% / 13%
0x0058  IN      2521         254       254    22.8%    77.2%     0.0%    0.0%          94% / 100%
0x0058  IN      2527         254       254   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12         146       146     0.0%     0.0%   100.0%    0.0%           23% / 23%
0x0021  IN        12         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2511         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         140       140     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0055  IN        12         118       118     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         118       118     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         118       118   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12          42        42     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521          42        42    14.3%    85.7%     0.0%    0.0%          19% / 100%
0x002E  IN      2528          42        42   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12          36        36    16.7%     0.0%    83.3%    0.0%         100% / 100%
0x0023  IN      2486          36        36    11.1%    88.9%     0.0%    0.0%          17% / 100%
0x0023  IN      2502          36        36    11.1%    88.9%     0.0%    0.0%          11% / 100%
0x003D  IN        12          27        27     0.0%     0.0%   100.0%    0.0%           96% / 98%
0x003D  IN      2512          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          27        27    11.1%    44.4%    44.4%    0.0%         100% / 100%
0x0052  IN        12          22        22     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          22        22    72.7%    27.3%     0.0%    0.0%         100% / 100%
0x0011  IN        12          21        21    61.9%    38.1%     0.0%    0.0%         100% / 100%
0x005E  IN        12          16        16     0.0%    87.5%    12.5%    0.0%             0% / 0%
0x005E  IN      2506          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12          16        16     0.0%     0.0%   100.0%    0.0%           16% / 66%
0x0063  IN      2507          16        16    87.5%    12.5%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          16        16    87.5%    12.5%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          14         -                                     no script
0x0012  OUT       12          13        13     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x000B  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00CC  IN        12           8         8     0.0%    75.0%    25.0%    0.0%           3% / 100%
0x0045  IN        12           6         6     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0061  IN        12           6         6     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x0069  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2486           6         6    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496           6         6    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0069  IN      2497           6         6    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502           6         6    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2504           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2521           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2549           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12           6         6    33.3%    66.7%     0.0%    0.0%          83% / 100%
0x006A  IN      2486           6         6    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           6         6    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2502           6         6    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2503           6         6    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006B  IN        12           6         6     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           6         6    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           6         6     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           6         6    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           6         6     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           6         6     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           6         6     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           6         6     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0128  IN        12           6         6    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0019  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           4         4    50.0%    50.0%     0.0%    0.0%           6% / 100%
0x0024  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           4         -                                     no script
0x0005  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0093  IN         -           3         -                                     no script
0x0001  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           2         -                                     no script
0x000F  OUT        -           2         -                                     no script
0x0010  OUT        -           2         -                                     no script
0x0013  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           26% / 26%
0x0017  IN      2500           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           2         2     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x0017  IN      2528           2         2     0.0%     0.0%   100.0%    0.0%           26% / 26%
0x0017  IN      2550           2         2     0.0%     0.0%   100.0%    0.0%           26% / 26%
0x001F  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x004C  IN      2512           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           47% / 47%
0x004F  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           2         -                                     no script
0x005A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0071  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0073  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           56% / 56%
0x007D  IN      2486           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           2         -                                     no script
0x009E  IN         -           2         -                                     no script
0x00A5  IN         -           2         -                                     no script
0x00A7  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           2         -                                     no script
0x00B0  OUT        -           2         -                                     no script
0x00B2  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           2         -                                     no script
0x00B7  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           2         -                                     no script
0x00CA  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00D1  IN         -           2         -                                     no script
0x00DF  IN         -           2         -                                     no script
0x00E6  IN         -           2         -                                     no script
0x00EB  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           2         -                                     no script
0x00F3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           2         -                                     no script
0x011B  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           2         -                                     no script
0x0131  IN         -           2         -                                     no script
0x0137  IN         -           2         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           50% / 50%
0x004F  OUT        -           1         -                                     no script
0x00B0  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           30% / 30%

## Sample failures

### 0x0047 IN src 12  over=146 threw=0 negative-length=146
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -64264 at offset 3/40
  ! ReadBytes: negative length -64264 at offset 3/40
  ! ReadBytes: negative length -64264 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -32132

### 0x0023 IN src 12  over=30 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100036/Stats/Unknown = 0
      171    4  Int32    Item: 50100036/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100036/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100036/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100036/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100036/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100036/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100036/ItemEnchant/CanRepackage = False

### 0x003D IN src 12  over=27 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  last reads before failure (of 3):
        0    8  Int64    SkillUseUid = 5
        8    4  Int32    ServerTick = 8150528
       12    4  Int32    ObjectId = 8150528

### 0x0063 IN src 12  over=16 threw=0 negative-length=7
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 50792 byte(s) at offset 27, only 14 of 41 remain
  ! ReadBytes: negative length -21698 at offset 27/167
  ! ReadBytes: wanted 426 byte(s) at offset 27, only 139 of 166 remain
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 4121919696389799937
        9    8  Int64    Entry/CharacterId = 3834586823300232801
       17    8  Int64    Entry/AccountId = 3846694439136539697
       25    2  Int16    Entry/Name/size = 25396

### 0x0012 OUT src 12  over=13 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -17152
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 1,0552772E-34

### 0x003D IN src 2520  over=12 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2520\Inbound\0x003D.py
  ! Read<Byte>: wanted 1 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 42, only 0 of 42 remain
  last reads before failure (of 14):
       19    4  Int32    target object id = 1540732
       23    1  Byte     ? = 0
       24    2  Int16    coord/x = 2850
       26    2  Int16    coord/y = -600
       28    2  Int16    coord/z = 1950
       30    4  Single   velocity/x = 0
       34    4  Single   velocity/y = -0,9999778
       38    4  Single   velocity/z = 0,0066665187

### 0x0045 IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 335544320
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 2304
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 4608

### 0x0061 IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 271, only 1 of 272 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0015 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 2562, only 3 of 2565 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 2562, only 3 of 2565 remain
  last reads before failure (of 599):
     2530    4  Int32    Unlocked Taxis/MapId = 889204224
     2534    4  Int32    Unlocked Taxis/MapId = 788541696
     2538    4  Int32    Unlocked Taxis/MapId = 1627417856
     2542    4  Int32    Unlocked Taxis/MapId = 1577060864
     2546    4  Int32    Unlocked Taxis/MapId = 1946183680
     2550    4  Int32    Unlocked Taxis/MapId = 1879077888
     2554    4  Int32    Unlocked Taxis/MapId = 1056994048
     2558    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 11264 byte(s) at offset 1348, only 3739 of 5087 remain
  ! ReadBytes: wanted 11264 byte(s) at offset 1348, only 3739 of 5087 remain
  last reads before failure (of 275):
     1085  138  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/UUID = 000000000000000000000000230E2200..
     1223    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/size = 50
     1225  100  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/ItemName = 38002F00310062002F00320036003000..
     1325    1  Byte     gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 72
     1326    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 24697
     1330    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/AccountId = 0
     1338    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterId = 17347706880
     1346    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterName/size = 5632

### 0x0035 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x004E IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 8 of 15 remain
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 8 of 15 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 601
