# Harness — MATRIX -> 2531

scripts from build : (matrix, see src column)
packets from build : 2531
packets considered : 4.323
packets executed   : 8.792  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                150   1.7%
OkExact               5.453   62.0%
UnderRead             2.571   29.2%
OverRead                492   5.6%
Threw                   126   1.4%

of packets a script actually ran on (8.642):
  clean (consumed exactly) : 63.1%
  over-read (WRONG)        : 5.7%
  under-read (ambiguous)   : 29.8%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12       2.826     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       2.826     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       2.826     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN        12         300       300     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521         300       300    96.7%     3.3%     0.0%    0.0%         100% / 100%
0x0058  IN      2527         300       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12         254       254     2.4%     0.0%    97.6%    0.0%         100% / 100%
0x0023  IN      2486         254       254     1.6%    98.4%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         254       254     1.6%    98.4%     0.0%    0.0%           11% / 11%
0x0021  IN        12         233       233    11.6%    79.4%     9.0%    0.0%          17% / 100%
0x0021  IN      2511         233       233     0.0%    91.0%     0.0%    9.0%            7% / 20%
0x0021  IN      2525         233       233     0.0%    91.0%     0.0%    9.0%            7% / 20%
0x0021  IN      2529         233       233     0.0%    91.0%     0.0%    9.0%            7% / 20%
0x0021  IN      2546         233       233     0.0%    91.0%     0.0%    9.0%            7% / 20%
0x0021  IN      2549         233       233     0.0%    91.0%     0.0%    9.0%            7% / 20%
0x0021  IN      2550         233       233     0.0%    91.0%     0.0%    9.0%            7% / 20%
0x0011  IN        12          80        80    53.8%    46.2%     0.0%    0.0%         100% / 100%
0x0047  IN        12          78        78     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0012  OUT       12          67        67     0.0%     0.0%   100.0%    0.0%           95% / 95%
0x0103  IN         -          40         -                                     no script
0x000B  OUT       12          39        39   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          32        32     0.0%    93.8%     6.2%    0.0%            0% / 11%
0x005E  IN      2506          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008A  IN      2511          20        20     0.0%   100.0%     0.0%    0.0%             1% / 9%
0x008A  IN      2524          20        20    90.0%     5.0%     5.0%    0.0%         100% / 100%
0x0052  IN        12          19        19     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0052  IN      2516          19        19    68.4%    31.6%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          15        15     0.0%    93.3%     6.7%    0.0%             0% / 1%
0x00F6  IN      2520          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -          14         -                                     no script
0x00A8  IN         -          14         -                                     no script
0x0061  IN        12          12        12     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12          11        11    18.2%    18.2%    63.6%    0.0%          90% / 100%
0x0006  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0080  OUT        -           8         -                                     no script
0x00CC  IN        12           8         8     0.0%    75.0%    25.0%    0.0%            6% / 50%
0x002E  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           6         6     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2486           6         6     0.0%    66.7%    33.3%    0.0%           20% / 59%
0x0069  IN      2496           6         6     0.0%    66.7%    33.3%    0.0%           54% / 59%
0x0069  IN      2497           6         6     0.0%    66.7%    33.3%    0.0%           20% / 59%
0x0069  IN      2502           6         6     0.0%    66.7%    33.3%    0.0%           20% / 59%
0x0069  IN      2503           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2504           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2521           6         6    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           6         6     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2549           6         6    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550           6         6    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x006A  IN        12           6         6    66.7%    33.3%     0.0%    0.0%         100% / 100%
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
0x0093  IN         -           6         -                                     no script
0x00B6  IN        12           6         6     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0055  OUT        -           5         -                                     no script
0x0019  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  OUT        -           4         -                                     no script
0x001A  IN        12           4         4    50.0%    50.0%     0.0%    0.0%          36% / 100%
0x0044  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0048  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00AC  IN         -           4         -                                     no script
0x010A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           4         -                                     no script
0x0128  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            6% / 14%
0x012D  IN         -           4         -                                     no script
0x0138  IN         -           4         -                                     no script
0x002D  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -           3         -                                     no script
0x0001  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x0017  IN        12           2         2     0.0%     0.0%   100.0%    0.0%          76% / 100%
0x0017  IN      2500           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           2         2     0.0%   100.0%     0.0%    0.0%            9% / 14%
0x0017  IN      2528           2         2     0.0%     0.0%   100.0%    0.0%           11% / 27%
0x0017  IN      2550           2         2     0.0%     0.0%   100.0%    0.0%          76% / 100%
0x001F  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0035  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           2         2     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             4% / 5%
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
0x00B2  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           2         -                                     no script
0x00B7  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           2         -                                     no script
0x00CA  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00D1  IN         -           2         -                                     no script
0x00DF  IN         -           2         -                                     no script
0x00E6  IN         -           2         -                                     no script
0x00EB  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           2         -                                     no script
0x00F3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           2         -                                     no script
0x011B  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0123  IN         -           2         -                                     no script
0x0125  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           2         -                                     no script
0x0131  IN         -           2         -                                     no script
0x0137  IN         -           2         -                                     no script
0x013A  IN         -           2         -                                     no script
0x0019  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%

## Sample failures

### 0x0023 IN src 12  over=248 threw=0
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

### 0x0047 IN src 12  over=78 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 23648 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 23648 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 23648 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 11824

### 0x0012 OUT src 12  over=67 threw=0 negative-length=23
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -35246 at offset 39/41
  ! ReadBytes: negative length -32656 at offset 39/41
  ! ReadBytes: negative length -32216 at offset 39/41
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 132
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -1533
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = -17623

### 0x0021 IN src 12  over=21 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0021.py
  ! Read<Single>: wanted 4 byte(s) at offset 316, only 2 of 318 remain
  ! Read<Single>: wanted 4 byte(s) at offset 316, only 2 of 318 remain
  ! Read<Single>: wanted 4 byte(s) at offset 316, only 2 of 318 remain
  last reads before failure (of 89):
      290    2  Int16    Item/Item: 11301339/Stats/ConstantStats/StatType = 97
      292    4  Single   Item/Item: 11301339/Stats/ConstantStats/SpecialOption 13/FloatValue = 1,0469406E-38
      296    4  Single   Item/Item: 11301339/Stats/ConstantStats/SpecialOption 13/FloatValue = 1,7E-43
      300    2  Int16    Item/Item: 11301339/Stats/ConstantStats/StatType = 0
      302    4  Single   Item/Item: 11301339/Stats/ConstantStats/SpecialOption 14/FloatValue = 0
      306    4  Single   Item/Item: 11301339/Stats/ConstantStats/SpecialOption 14/FloatValue = 0
      310    2  Int16    Item/Item: 11301339/Stats/ConstantStats/StatType = 0
      312    4  Single   Item/Item: 11301339/Stats/ConstantStats/SpecialOption 15/FloatValue = 0

### 0x0021 IN src 2511  over=0 threw=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2511\Inbound\0x0021.py
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  last reads before failure (of 23):
       70    1  Boolean  Item: 11301339/Unknown = False
       71    4  Int32    Item: 11301339/Unknown = 0
       75    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color1 = -2714780
       79    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color2 = -11762213
       83    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color3 = -4558542
       87    4  Int32    Item: 11301339/ItemExtraData/EquipColor/ColorIndex = 11
       91    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Unknown = 10
       95    0  Field    Item: 11301339/ItemExtraData/113 = 

### 0x0021 IN src 2525  over=0 threw=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2525\Inbound\0x0021.py
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  last reads before failure (of 23):
       70    1  Boolean  Item: 11301339/Unknown = False
       71    4  Int32    Item: 11301339/Unknown = 0
       75    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color1 = -2714780
       79    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color2 = -11762213
       83    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color3 = -4558542
       87    4  Int32    Item: 11301339/ItemExtraData/EquipColor/ColorIndex = 11
       91    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Unknown = 10
       95    0  Field    Item: 11301339/ItemExtraData/113 = 

### 0x0021 IN src 2529  over=0 threw=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2529\Inbound\0x0021.py
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  last reads before failure (of 23):
       70    1  Boolean  Item: 11301339/Unknown = False
       71    4  Int32    Item: 11301339/Unknown = 0
       75    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color1 = -2714780
       79    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color2 = -11762213
       83    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color3 = -4558542
       87    4  Int32    Item: 11301339/ItemExtraData/EquipColor/ColorIndex = 11
       91    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Unknown = 10
       95    0  Field    Item: 11301339/ItemExtraData/113 = 

### 0x0021 IN src 2546  over=0 threw=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2546\Inbound\0x0021.py
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  last reads before failure (of 23):
       70    1  Boolean  Item: 11301339/Unknown = False
       71    4  Int32    Item: 11301339/Unknown = 0
       75    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color1 = -2714780
       79    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color2 = -11762213
       83    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color3 = -4558542
       87    4  Int32    Item: 11301339/ItemExtraData/EquipColor/ColorIndex = 11
       91    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Unknown = 10
       95    0  Field    Item: 11301339/ItemExtraData/113 = 

### 0x0021 IN src 2549  over=0 threw=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2549\Inbound\0x0021.py
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  last reads before failure (of 23):
       70    1  Boolean  Item: 11301339/Unknown = False
       71    4  Int32    Item: 11301339/Unknown = 0
       75    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color1 = -2714780
       79    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color2 = -11762213
       83    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color3 = -4558542
       87    4  Int32    Item: 11301339/ItemExtraData/EquipColor/ColorIndex = 11
       91    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Unknown = 10
       95    0  Field    Item: 11301339/ItemExtraData/113 = 

### 0x0021 IN src 2550  over=0 threw=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0021.py
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  ! name 'decode_coordS' is not defined
  last reads before failure (of 23):
       70    1  Boolean  Item: 11301339/Unknown = False
       71    4  Int32    Item: 11301339/Unknown = 0
       75    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color1 = -2714780
       79    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color2 = -11762213
       83    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Color3 = -4558542
       87    4  Int32    Item: 11301339/ItemExtraData/EquipColor/ColorIndex = 11
       91    4  Int32    Item: 11301339/ItemExtraData/EquipColor/Unknown = 10
       95    0  Field    Item: 11301339/ItemExtraData/113 = 

### 0x0061 IN src 12  over=12 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5167, only 2 of 5169 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 5415, only 0 of 5415 remain
  last reads before failure (of 0):

### 0x0054 IN src 12  over=7 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 17, only 0 of 17 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 4294967296
