# Harness — MATRIX -> 2500

scripts from build : (matrix, see src column)
packets from build : 2500
packets considered : 2.292
packets executed   : 6.520  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                 46   0.7%
OkExact               4.628   71.0%
UnderRead             1.645   25.2%
OverRead                201   3.1%

of packets a script actually ran on (6.474):
  clean (consumed exactly) : 71.5%
  over-read (WRONG)        : 3.1%
  under-read (ambiguous)   : 25.4%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12       1.468     1.468   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       1.468     1.468   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       1.468     1.468   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN        12         220       220     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0058  IN      2521         220       220     2.3%    97.7%     0.0%    0.0%           88% / 90%
0x0058  IN      2527         220       220     2.3%    97.7%     0.0%    0.0%           88% / 94%
0x0021  IN        12          82        82    20.7%    79.3%     0.0%    0.0%          17% / 100%
0x0021  IN      2511          82        82     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x0021  IN      2525          82        82     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x0021  IN      2529          82        82     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x0021  IN      2546          82        82     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x0021  IN      2549          82        82     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x0021  IN      2550          82        82     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x0023  IN        12          81        81     3.7%     0.0%    96.3%    0.0%         100% / 100%
0x0023  IN      2486          81        81     2.5%    97.5%     0.0%    0.0%           17% / 17%
0x0023  IN      2502          81        81     2.5%    97.5%     0.0%    0.0%           11% / 11%
0x00CB  IN        12          70        70     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0047  IN        12          63        63     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0011  IN        12          38        38    52.6%    47.4%     0.0%    0.0%         100% / 100%
0x0012  OUT       12          23        23     0.0%     0.0%   100.0%    0.0%           95% / 95%
0x000B  OUT       12          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12          15        15     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521          15        15    26.7%    73.3%     0.0%    0.0%          19% / 100%
0x002E  IN      2528          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          15        15     0.0%    93.3%     6.7%    0.0%            0% / 26%
0x005E  IN      2506          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00BC  OUT       12          14        14     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x003D  IN        12          11        11     0.0%     0.0%   100.0%    0.0%           96% / 96%
0x003D  IN      2512          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          11        11     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0052  IN        12           9         9     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0052  IN      2516           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x008A  IN      2511           9         9     0.0%   100.0%     0.0%    0.0%             1% / 6%
0x008A  IN      2524           9         9    88.9%     0.0%    11.1%    0.0%         100% / 100%
0x012E  IN         -           9         -                                     no script
0x0048  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -           7         -                                     no script
0x001D  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -           5         -                                     no script
0x0039  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x006A  IN        12           4         4    25.0%    75.0%     0.0%    0.0%          22% / 100%
0x006A  IN      2486           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           4         4    25.0%    75.0%     0.0%    0.0%          10% / 100%
0x006A  IN      2502           4         4    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503           4         4    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00CC  IN        12           4         4     0.0%    75.0%    25.0%    0.0%            4% / 50%
0x0006  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0061  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x0069  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496           3         3    33.3%    66.7%     0.0%    0.0%          57% / 100%
0x0069  IN      2497           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0093  IN         -           3         -                                     no script
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0128  IN        12           3         3    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%    50.0%     0.0%    0.0%           9% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00EB  IN        12           2         2     0.0%    50.0%    50.0%    0.0%          69% / 100%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
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
0x0014  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           21% / 21%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%             8% / 8%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           21% / 21%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%           21% / 21%
0x001F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           1         1     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x004D  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -           1         -                                     no script
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           1         -                                     no script
0x0055  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           1         1     0.0%   100.0%     0.0%    0.0%           64% / 64%
0x0055  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0073  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x007D  IN      2486           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x007D  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x007D  IN      2546           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x007D  IN      2549           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x007D  IN      2550           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0089  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           1         -                                     no script
0x009E  IN         -           1         -                                     no script
0x00A5  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           1         -                                     no script
0x00B0  OUT        -           1         -                                     no script
0x00B0  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x00B2  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           1         -                                     no script
0x00B7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           1         -                                     no script
0x00CA  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00D1  IN         -           1         -                                     no script
0x00DF  IN         -           1         -                                     no script
0x00E6  IN         -           1         -                                     no script
0x00EE  IN         -           1         -                                     no script
0x00F3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0131  IN         -           1         -                                     no script
0x0137  IN         -           1         -                                     no script

## Sample failures

### 0x0023 IN src 12  over=78 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100000/Stats/Unknown = 0
      171    4  Int32    Item: 50100000/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100000/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100000/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100000/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100000/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100000/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100000/ItemEnchant/CanRepackage = False

### 0x0047 IN src 12  over=63 threw=0 negative-length=63
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -15974 at offset 3/40
  ! ReadBytes: negative length -15974 at offset 3/40
  ! ReadBytes: negative length -15974 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -7987

### 0x0012 OUT src 12  over=23 threw=0 negative-length=12
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: wanted 44778 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: wanted 46930 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: wanted 48030 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -8192
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = 22389

### 0x003D IN src 12  over=11 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 2801481960946457860
        8    4  Int32    ServerTick = -1184680960
       12    4  Int32    ObjectId = -1698037760
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 18, only 1 of 19 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 318767104
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 768
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 12800

### 0x0061 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 941, only 2 of 943 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0015 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 2118, only 3 of 2121 remain
  last reads before failure (of 488):
     2086    4  Int32    Unlocked Taxis/MapId = 889204224
     2090    4  Int32    Unlocked Taxis/MapId = 788541696
     2094    4  Int32    Unlocked Taxis/MapId = 1627417856
     2098    4  Int32    Unlocked Taxis/MapId = 1577060864
     2102    4  Int32    Unlocked Taxis/MapId = 1946183680
     2106    4  Int32    Unlocked Taxis/MapId = 1879077888
     2110    4  Int32    Unlocked Taxis/MapId = 1056994048
     2114    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 50331648 byte(s) at offset 1122, only 4146 of 5268 remain
  last reads before failure (of 224):
     1096    8  Int64    Timestamp = 28992395054940206
     1104    4  Int32    Weekly Architect Score = 0
     1108    4  Int32    Architect Score = -1501843712
     1112    1  Boolean  Equip Buffer/isDeflated = True
     1113    4  Int32    Equip Buffer/BufferSize = 0
     1117    0  Field    Equip Buffer/Buffer = 
     1117    1  Boolean  Skin2 Buffer/isDeflated = False
     1118    4  Int32    Skin2 Buffer/BufferSize = 50331648

### 0x0035 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x0054 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 1103806595073

### 0x005E IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x005E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 1 of 1 remain
  last reads before failure (of 0):

### 0x006B IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x006B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    1  Byte     function = 22
        1    4  Int32    PlotId = 0
