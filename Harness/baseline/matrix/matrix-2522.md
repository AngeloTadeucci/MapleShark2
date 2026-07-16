# Harness — MATRIX -> 2522

scripts from build : (matrix, see src column)
packets from build : 2522
packets considered : 7.812
packets executed   : 14.813  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                252   1.7%
OkExact               6.746   45.5%
UnderRead             4.438   30.0%
OverRead              3.377   22.8%

of packets a script actually ran on (14.561):
  clean (consumed exactly) : 46.3%
  over-read (WRONG)        : 23.2%
  under-read (ambiguous)   : 30.5%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12       1.815     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521       1.815     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN      2527       1.815     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12       1.245     1.245     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0011  IN        12       1.003     1.003    50.3%    49.7%     0.0%    0.0%         100% / 100%
0x001C  IN        12         894       894     0.2%     0.0%    99.8%    0.0%         100% / 100%
0x001C  IN      2507         894       894    46.4%     0.0%    53.6%    0.0%         100% / 100%
0x0024  IN        12         552       552   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         552       552   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         552       552   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         500       500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12         366       366     2.5%     0.0%    97.5%    0.0%         100% / 100%
0x0023  IN      2486         366       366     1.6%    98.4%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         366       366     1.6%    98.4%     0.0%    0.0%           11% / 11%
0x0021  IN        12         183       183     2.2%    94.5%     3.3%    0.0%           17% / 20%
0x0021  IN      2511         183       183     2.2%    97.8%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         183       183     2.2%    97.8%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         183       183     2.2%    97.8%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         183       183     2.2%    97.8%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         183       183     2.2%    97.8%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         183       183     2.2%    97.8%     0.0%    0.0%           17% / 20%
0x00B0  IN        12         120       120     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0082  IN        12          91        91     0.0%    27.5%    72.5%    0.0%            2% / 86%
0x0006  IN        12          87        87   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          87        87   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          87        87   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          72        72   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12          72        72     0.0%     0.0%   100.0%    0.0%           23% / 23%
0x0049  OUT       12          55        55    50.9%    49.1%     0.0%    0.0%         100% / 100%
0x005E  IN        12          38        38     0.0%    92.1%     7.9%    0.0%            0% / 20%
0x005E  IN      2506          38        38   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          36         -                                     no script
0x007E  IN         -          33         -                                     no script
0x0093  IN         -          33         -                                     no script
0x0011  OUT        -          32         -                                     no script
0x0037  IN        12          28        28     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x00F6  IN        12          26        26     0.0%    84.6%    15.4%    0.0%           0% / 100%
0x00F6  IN      2520          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12          24        24     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0052  IN        12          21        21     0.0%   100.0%     0.0%    0.0%            1% / 17%
0x0052  IN      2516          21        21    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          21         -                                     no script
0x008A  IN      2511          14        14     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          14        14    78.6%     0.0%    21.4%    0.0%         100% / 100%
0x006A  IN        12          12        12    25.0%    75.0%     0.0%    0.0%          50% / 100%
0x006A  IN      2486          12        12    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          12        12    25.0%    75.0%     0.0%    0.0%          10% / 100%
0x006A  IN      2502          12        12    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          12        12    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006C  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x002E  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2496           9         9     0.0%    66.7%    33.3%    0.0%           34% / 70%
0x0069  IN      2497           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2502           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
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
0x0017  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           8         8     0.0%    37.5%    62.5%    0.0%         100% / 100%
0x0017  IN      2528           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0080  OUT        -           8         -                                     no script
0x00CC  IN        12           8         8     0.0%    87.5%    12.5%    0.0%           20% / 99%
0x00F4  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x0005  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           6         6    50.0%    16.7%    33.3%    0.0%         100% / 100%
0x0039  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0044  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           6         -                                     no script
0x012D  IN         -           6         -                                     no script
0x0138  IN         -           6         -                                     no script
0x0033  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x00E6  IN         -           5         -                                     no script
0x0123  IN         -           5         -                                     no script
0x001E  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0055  OUT        -           4         -                                     no script
0x00A5  IN         -           4         -                                     no script
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
0x001F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0034  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x005A  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           3         3     0.0%    66.7%    33.3%    0.0%            0% / 25%
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
0x00A9  IN        12           3         3     0.0%    33.3%    66.7%    0.0%         100% / 100%
0x00AD  IN         -           3         -                                     no script
0x00B0  OUT        -           3         -                                     no script
0x00B2  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             2% / 2%
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
0x0139  IN         -           3         -                                     no script
0x0018  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0066  OUT        -           1         -                                     no script
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  IN         -           1         -                                     no script
0x00CE  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0109  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           97% / 97%

## Sample failures

### 0x0012 OUT src 12  over=1.245 threw=0 negative-length=177
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -1536
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 8,505811E-05

### 0x001C IN src 12  over=892 threw=0 negative-length=27
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! ReadBytes: negative length -2574 at offset 30/32
  ! ReadBytes: negative length -2574 at offset 30/32
  ! ReadBytes: negative length -2574 at offset 30/32
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 4607
       23    1  Byte     StateSync/Unknown = 78
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 12300
       26    2  Int16    StateSync/CoordS / 1000 = 1
       28    2  Int16    StateSync/AnimationString?/size = -1287

### 0x001C IN src 2507  over=479 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 297
       13    2  Int16    coord x = 3150
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -362258289925534191
       30    2  Int16    speed x = 1

### 0x0023 IN src 12  over=357 threw=0
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

### 0x00B0 IN src 12  over=120 threw=0 negative-length=60
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -20478 at offset 6/20
  ! ReadBytes: wanted 20994 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: negative length -20478 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037824
        4    2  Int16    Motto/size = -10239

### 0x0047 IN src 12  over=72 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 60832 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 60832 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 60832 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 30416

### 0x0082 IN src 12  over=66 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0082.py
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 2 of 2 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 2 of 2 remain
  last reads before failure (of 0):

### 0x0061 IN src 12  over=24 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 5347, only 0 of 5347 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 3807, only 2 of 3809 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=9 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 134217728
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 2304
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 5632

### 0x0017 IN src 12  over=8 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  ! ReadBytes: wanted 36588 byte(s) at offset 3497, only 1835 of 5332 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 258):
     1893    8  Int64    PlayerInfo/Player+1B0 = -5632065550850530816
     1901    8  Int64    PlayerInfo/Player+1B0 = 72058696186371384
     1909    8  Int64    PlayerInfo/Player+1B0 = 16777216
     1917    8  Int64    PlayerInfo/Player+1B0 = 0
     1925    8  Int64    PlayerInfo/Player+1B0 = 0
     1933    8  Int64    PlayerInfo/Player+1B0 = 167773451845632
     1941    8  Int64    PlayerInfo/Player+1B0 = 0
     1949    8  Int64    PlayerInfo/Player+1B0 = -504403158265495552

### 0x0017 IN src 2528  over=8 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  ! ReadBytes: wanted 65536 byte(s) at offset 777, only 4555 of 5332 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 258):
     1893    8  Int64    PlayerInfo/Player+1B0 = -5632065550850530816
     1901    8  Int64    PlayerInfo/Player+1B0 = 72058696186371384
     1909    8  Int64    PlayerInfo/Player+1B0 = 16777216
     1917    8  Int64    PlayerInfo/Player+1B0 = 0
     1925    8  Int64    PlayerInfo/Player+1B0 = 0
     1933    8  Int64    PlayerInfo/Player+1B0 = 167773451845632
     1941    8  Int64    PlayerInfo/Player+1B0 = 0
     1949    8  Int64    PlayerInfo/Player+1B0 = -504403158265495552

### 0x0017 IN src 2550  over=8 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  ! ReadBytes: wanted 36588 byte(s) at offset 3497, only 1835 of 5332 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 258):
     1893    8  Int64    PlayerInfo/Player+1B0 = -5632065550850530816
     1901    8  Int64    PlayerInfo/Player+1B0 = 72058696186371384
     1909    8  Int64    PlayerInfo/Player+1B0 = 16777216
     1917    8  Int64    PlayerInfo/Player+1B0 = 0
     1925    8  Int64    PlayerInfo/Player+1B0 = 0
     1933    8  Int64    PlayerInfo/Player+1B0 = 167773451845632
     1941    8  Int64    PlayerInfo/Player+1B0 = 0
     1949    8  Int64    PlayerInfo/Player+1B0 = -504403158265495552
