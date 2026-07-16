# Harness — MATRIX -> 2491

scripts from build : (matrix, see src column)
packets from build : 2491
packets considered : 1.173
packets executed   : 2.497  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                185   7.4%
OkExact               1.193   47.8%
UnderRead               757   30.3%
OverRead                362   14.5%

of packets a script actually ran on (2.312):
  clean (consumed exactly) : 51.6%
  over-read (WRONG)        : 15.7%
  under-read (ambiguous)   : 32.7%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12         320       320     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0024  IN        12         276       276   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         276       276   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         276       276   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN        12         171       171     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521         171       171    19.9%    80.1%     0.0%    0.0%          97% / 100%
0x0058  IN      2527         171       171   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -         149         -                                     no script
0x0021  IN        12          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2511          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550          39        39     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0011  IN        12          21        21    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x0055  IN        12          13        13     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          13        13     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12          11        11     0.0%    18.2%    81.8%    0.0%           16% / 43%
0x0063  IN      2507          11        11    63.6%    36.4%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          11        11    63.6%    36.4%     0.0%    0.0%         100% / 100%
0x000B  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12           9         9    33.3%     0.0%    66.7%    0.0%          99% / 100%
0x0023  IN      2486           9         9    22.2%    77.8%     0.0%    0.0%          16% / 100%
0x0023  IN      2502           9         9    22.2%    77.8%     0.0%    0.0%          10% / 100%
0x005E  IN        12           8         8     0.0%    87.5%    12.5%    0.0%           20% / 35%
0x005E  IN      2506           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521           7         7    28.6%    71.4%     0.0%    0.0%          19% / 100%
0x002E  IN      2528           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -           7         -                                     no script
0x0052  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0052  IN      2516           5         5    40.0%    60.0%     0.0%    0.0%          20% / 100%
0x0048  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0080  OUT        -           4         -                                     no script
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0061  IN        12           3         3     0.0%     0.0%   100.0%    0.0%            0% / 99%
0x0069  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2486           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0069  IN      2497           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2504           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2521           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2486           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2502           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2503           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006B  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0128  IN        12           3         3    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0006  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x005A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00A5  IN         -           2         -                                     no script
0x00CC  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x012D  IN         -           2         -                                     no script
0x0001  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           66% / 66%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           1         -                                     no script
0x000F  OUT        -           1         -                                     no script
0x0010  OUT        -           1         -                                     no script
0x0011  OUT        -           1         -                                     no script
0x0013  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           47% / 47%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x004E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             1% / 1%
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           1         -                                     no script
0x005F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0065  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0066  OUT        -           1         -                                     no script
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           56% / 56%
0x007D  IN      2486           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           1         -                                     no script
0x009E  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           1         -                                     no script
0x00B0  OUT        -           1         -                                     no script
0x00B2  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           1         -                                     no script
0x00B7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           1         -                                     no script
0x00CA  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x00D1  IN         -           1         -                                     no script
0x00DF  IN         -           1         -                                     no script
0x00E6  IN         -           1         -                                     no script
0x00EB  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           1         -                                     no script
0x00F3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0131  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=320 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 90
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 45
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -40
       28    1  Byte     Segment 0/StateSync/Unknown = 2
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2700
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 250
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    4  Int32    Segment 0/ClientTicks = 1012380448

### 0x0063 IN src 12  over=9 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 29384 byte(s) at offset 27, only 698 of 725 remain
  ! ReadBytes: wanted 334 byte(s) at offset 27, only 139 of 166 remain
  ! ReadBytes: negative length -45136 at offset 27/167
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 7220959189974122516
        9    8  Int64    Entry/CharacterId = 3473736793007141217
       17    8  Int64    Entry/AccountId = 7089005992929933364
       25    2  Int16    Entry/Name/size = 14692

### 0x0023 IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  last reads before failure (of 63):
      180    8  Int64    Item: 50100013/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100013/ItemEnchant/Unknown = 16777216
      192    4  Int32    Item: 50100013/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100013/ItemEnchant/CanRepackage = False
      197    4  Int32    Item: 50100013/ItemEnchant/EnchantCharges = 0
      201    1  Byte     Item: 50100013/ItemEnchant/EnchantStats/EnchantStatCount = 0
      202    4  Int32    Item: 50100013/LimitBreak/LimitBreakLevel = 0
      206    4  Int32    Item: 50100013/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 16777216
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 0
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0

### 0x0061 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 241, only 3 of 244 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0015 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 632, only 1 of 633 remain
  last reads before failure (of 116):
      600    4  Int32    Unlocked Maps/MapId = 822097152
      604    4  Int32    Unlocked Maps/MapId = 1828728576
      608    4  Int32    Unlocked Maps/MapId = 167796992
      612    4  Int32    Unlocked Maps/MapId = 1744854528
      616    4  Int32    Unlocked Maps/MapId = 1946186752
      620    4  Int32    Unlocked Maps/MapId = 1929408512
      624    4  Int32    Unlocked Maps/MapId = 973094656
      628    4  Int32    Unlocked Maps/MapId = 788541184

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1714, only 6 of 1720 remain
  last reads before failure (of 229):
     1650    8  Int64    PlayerInfo/Player+1B0 = -78797847815105810
     1658    8  Int64    PlayerInfo/Player+1B0 = 72274318534967298
     1666    8  Int64    PlayerInfo/Player+1B0 = 1099511627776
     1674    8  Int64    PlayerInfo/Player+1B0 = 0
     1682    8  Int64    PlayerInfo/Player+1B0 = 0
     1690    8  Int64    PlayerInfo/Player+1B0 = 0
     1698    8  Int64    PlayerInfo/Player+1B0 = 0
     1706    8  Int64    PlayerInfo/Player+1B0 = -72057594037927936

### 0x001A IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001A.py
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 19
        1    4  Int32    message = 0

### 0x0035 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x0047 IN src 12  over=1 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -178 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -89

### 0x004E IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 646 byte(s) at offset 7, only 512 of 519 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 38
        5    2  Int16    FunctionCubeName/size = 323

### 0x0054 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 8800387989512
