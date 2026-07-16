# Harness — MATRIX -> 2530

scripts from build : (matrix, see src column)
packets from build : 2530
packets considered : 2.764
packets executed   : 5.740  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                142   2.5%
OkExact               3.087   53.8%
UnderRead             1.567   27.3%
OverRead                944   16.4%

of packets a script actually ran on (5.598):
  clean (consumed exactly) : 55.1%
  over-read (WRONG)        : 16.9%
  under-read (ambiguous)   : 28.0%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12         825       825   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         825       825   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         825       825   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12         699       699     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0011  IN        12         299       299    51.2%    48.8%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         149       149   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12         125       125     1.6%    98.4%     0.0%    0.0%           17% / 20%
0x0021  IN      2511         125       125     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         125       125     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         125       125     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         125       125     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         125       125     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         125       125     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0023  IN        12         105       105     8.6%     0.0%    91.4%    0.0%         100% / 100%
0x0023  IN      2486         105       105     5.7%    94.3%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         105       105     5.7%    94.3%     0.0%    0.0%           11% / 11%
0x00B0  IN        12          36        36     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0006  IN        12          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12          24        24     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x00A8  IN         -          21         -                                     no script
0x005E  IN        12          16        16     0.0%    81.2%    18.8%    0.0%            1% / 26%
0x005E  IN      2506          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -          16         -                                     no script
0x0052  IN        12          15        15     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0052  IN      2516          15        15    40.0%    60.0%     0.0%    0.0%          20% / 100%
0x008A  IN      2511          15        15     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          15        15    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x006A  IN        12          12        12    25.0%    75.0%     0.0%    0.0%          22% / 100%
0x006A  IN      2486          12        12    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          12        12    25.0%    75.0%     0.0%    0.0%          10% / 100%
0x006A  IN      2502          12        12    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          12        12    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006C  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0093  IN         -          12         -                                     no script
0x00F6  IN        12          12        12     0.0%    75.0%    25.0%    0.0%           0% / 100%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0061  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x0069  IN        12           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           9         9     0.0%    66.7%    33.3%    0.0%           20% / 34%
0x0069  IN      2496           9         9     0.0%    66.7%    33.3%    0.0%           34% / 70%
0x0069  IN      2497           9         9     0.0%    66.7%    33.3%    0.0%           20% / 34%
0x0069  IN      2502           9         9     0.0%    66.7%    33.3%    0.0%           20% / 34%
0x0069  IN      2503           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x006B  IN        12           9         9     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           9         9     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0128  IN        12           9         9    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0019  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           6         6    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0044  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CC  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x010A  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           6         -                                     no script
0x012D  IN         -           6         -                                     no script
0x0138  IN         -           6         -                                     no script
0x0005  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -           5         -                                     no script
0x0080  OUT        -           4         -                                     no script
0x00A5  IN         -           4         -                                     no script
0x00E6  IN         -           4         -                                     no script
0x00F4  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0001  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           3         -                                     no script
0x000F  OUT        -           3         -                                     no script
0x0010  OUT        -           3         -                                     no script
0x0013  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2528           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x002B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x002B  IN      2530           3         3     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x002B  IN      2531           3         3     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0033  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           3         -                                     no script
0x006F  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x007D  IN      2486           3         3     0.0%   100.0%     0.0%    0.0%           64% / 64%
0x007D  IN      2502           3         3     0.0%   100.0%     0.0%    0.0%           63% / 63%
0x007D  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           3         -                                     no script
0x009E  IN         -           3         -                                     no script
0x00A7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           3         -                                     no script
0x00B0  OUT        -           3         -                                     no script
0x00B2  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           3         -                                     no script
0x00B7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           3         -                                     no script
0x00CA  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00CB  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00D1  IN         -           3         -                                     no script
0x00DF  IN         -           3         -                                     no script
0x00EB  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           3         -                                     no script
0x00F3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           3         -                                     no script
0x011B  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           3         -                                     no script
0x0131  IN         -           3         -                                     no script
0x0137  IN         -           3         -                                     no script
0x013A  IN         -           3         -                                     no script
0x0017  OUT        -           2         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004A  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           17% / 17%
0x0066  OUT        -           1         -                                     no script
0x006C  OUT        -           1         -                                     no script
0x0084  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             0% / 0%

## Sample failures

### 0x0012 OUT src 12  over=699 threw=0 negative-length=94
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -7168
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 1,30063464E-17

### 0x0023 IN src 12  over=96 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100013/Stats/Unknown = 0
      171    4  Int32    Item: 50100013/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100013/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100013/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100013/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100013/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100013/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100013/ItemEnchant/CanRepackage = False

### 0x00B0 IN src 12  over=36 threw=0 negative-length=36
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -23038 at offset 6/20
  ! ReadBytes: negative length -23038 at offset 6/20
  ! ReadBytes: negative length -54270 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593289216
        4    2  Int16    Motto/size = -11519

### 0x0045 IN src 12  over=9 threw=0
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

### 0x0061 IN src 12  over=9 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 827, only 1 of 828 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0015 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 674, only 3 of 677 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 674, only 3 of 677 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 674, only 3 of 677 remain
  last reads before failure (of 127):
      642    4  Int32    Unlocked Taxis/MapId = 889204224
      646    4  Int32    Unlocked Taxis/MapId = 788541696
      650    4  Int32    Unlocked Taxis/MapId = 1627417856
      654    4  Int32    Unlocked Taxis/MapId = 1577060864
      658    4  Int32    Unlocked Taxis/MapId = 1946183680
      662    4  Int32    Unlocked Taxis/MapId = 1879077888
      666    4  Int32    Unlocked Taxis/MapId = 1056994048
      670    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 258):
     1893    8  Int64    PlayerInfo/Player+1B0 = 8062862954705783552
     1901    8  Int64    PlayerInfo/Player+1B0 = 72058696186371363
     1909    8  Int64    PlayerInfo/Player+1B0 = 16777216
     1917    8  Int64    PlayerInfo/Player+1B0 = 0
     1925    8  Int64    PlayerInfo/Player+1B0 = 0
     1933    8  Int64    PlayerInfo/Player+1B0 = 167773451845632
     1941    8  Int64    PlayerInfo/Player+1B0 = 0
     1949    8  Int64    PlayerInfo/Player+1B0 = -72057594037927936

### 0x001A IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001A.py
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 19
        1    4  Int32    message = 0

### 0x002B IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 227, only 3 of 230 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 227, only 3 of 230 remain
  ! Read<Single>: wanted 4 byte(s) at offset 241, only 1 of 242 remain
  last reads before failure (of 66):
      201    4  Single   Item: 11709003/Stats/ConstantStats/StatOption 7/FloatValue = 0
      205    2  Int16    Item: 11709003/Stats/ConstantStats/StatType = 0
      207    4  Int32    Item: 11709003/Stats/ConstantStats/StatOption 8/IntegerValue = 256
      211    4  Single   Item: 11709003/Stats/ConstantStats/StatOption 8/FloatValue = 0
      215    2  Int16    Item: 11709003/Stats/ConstantStats/StatType = 0
      217    4  Int32    Item: 11709003/Stats/ConstantStats/StatOption 9/IntegerValue = 0
      221    4  Single   Item: 11709003/Stats/ConstantStats/StatOption 9/FloatValue = 0
      225    2  Int16    Item: 11709003/Stats/ConstantStats/StatType = 0

### 0x0035 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x004B OUT src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x004B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 85

### 0x0054 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 4294967296
