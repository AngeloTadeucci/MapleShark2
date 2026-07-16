# Harness — MATRIX -> 2517

scripts from build : (matrix, see src column)
packets from build : 2517
packets considered : 2.386
packets executed   : 6.559  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                129   2.0%
OkExact               4.634   70.7%
UnderRead             1.366   20.8%
OverRead                430   6.6%

of packets a script actually ran on (6.430):
  clean (consumed exactly) : 72.1%
  over-read (WRONG)        : 6.7%
  under-read (ambiguous)   : 21.2%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12       1.413     1.413   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       1.413     1.413   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       1.413     1.413   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12         212       212     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0058  IN        12         154       154     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521         154       154    26.0%    74.0%     0.0%    0.0%          97% / 100%
0x0058  IN      2527         154       154   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12         127       127     2.4%     0.0%    97.6%    0.0%         100% / 100%
0x0023  IN      2486         127       127     1.6%    98.4%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         127       127     1.6%    98.4%     0.0%    0.0%           11% / 11%
0x0021  IN        12          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2511          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x007E  IN         -          90         -                                     no script
0x0047  IN        12          39        39     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0011  IN        12          23        23    56.5%    43.5%     0.0%    0.0%         100% / 100%
0x005E  IN        12          17        17     0.0%    94.1%     5.9%    0.0%            0% / 14%
0x005E  IN      2506          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          16        16     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          12        12     0.0%    91.7%     8.3%    0.0%             0% / 0%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          10        10    70.0%    30.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           16% / 16%
0x0063  IN      2507           9         9    88.9%    11.1%     0.0%    0.0%         100% / 100%
0x0063  IN      2518           9         9    88.9%    11.1%     0.0%    0.0%         100% / 100%
0x0061  IN        12           7         7     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0073  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           44% / 94%
0x0073  IN      2531           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -           7         -                                     no script
0x008A  IN      2511           6         6     0.0%   100.0%     0.0%    0.0%            0% / 68%
0x008A  IN      2524           6         6    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x0069  IN        12           5         5     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           5         5     0.0%    80.0%    20.0%    0.0%            7% / 47%
0x0069  IN      2496           5         5     0.0%    80.0%    20.0%    0.0%           20% / 54%
0x0069  IN      2497           5         5     0.0%    80.0%    20.0%    0.0%            7% / 47%
0x0069  IN      2502           5         5     0.0%    80.0%    20.0%    0.0%            7% / 47%
0x0069  IN      2503           5         5    20.0%    80.0%     0.0%    0.0%           7% / 100%
0x0069  IN      2504           5         5    20.0%    80.0%     0.0%    0.0%           7% / 100%
0x0069  IN      2521           5         5    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x0069  IN      2546           5         5     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           5         5    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x0069  IN      2550           5         5    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x0006  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00CC  IN        12           4         4     0.0%    75.0%    25.0%    0.0%            3% / 50%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0048  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x0093  IN         -           3         -                                     no script
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0128  IN        12           3         3    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%    50.0%     0.0%    0.0%           3% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0068  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486           2         2    50.0%    50.0%     0.0%    0.0%          17% / 100%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x0123  IN         -           2         -                                     no script
0x012D  IN         -           2         -                                     no script
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
0x0011  OUT        -           1         -                                     no script
0x0013  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           88% / 88%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           11% / 11%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%           88% / 88%
0x001D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0037  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502           1         1     0.0%   100.0%     0.0%    0.0%           73% / 73%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  OUT        -           1         -                                     no script
0x0042  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           47% / 47%
0x004F  OUT        -           1         -                                     no script
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           1         -                                     no script
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x005A  IN      2490           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x00A5  IN         -           1         -                                     no script
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
0x00CB  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00D1  IN         -           1         -                                     no script
0x00DF  IN         -           1         -                                     no script
0x00E6  IN         -           1         -                                     no script
0x00EB  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           1         -                                     no script
0x00F3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0131  IN         -           1         -                                     no script
0x0137  IN         -           1         -                                     no script
0x0138  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=212 threw=0 negative-length=47
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -2 at offset 35/41
  ! ReadBytes: negative length -20526 at offset 35/41
  ! ReadBytes: negative length -20526 at offset 35/41
  last reads before failure (of 19):
       21    1  Byte     Segment 0/StateSync/Animation3 = 90
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -9472
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    2  Int16    Segment 0/StateSync/AnimationString?/size = -1

### 0x0023 IN src 12  over=124 threw=0
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

### 0x0047 IN src 12  over=39 threw=0 negative-length=39
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -60058 at offset 3/40
  ! ReadBytes: negative length -60058 at offset 3/40
  ! ReadBytes: negative length -60058 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -30029

### 0x0063 IN src 12  over=9 threw=0 negative-length=6
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 27848 byte(s) at offset 27, only 1598 of 1625 remain
  ! ReadBytes: wanted 334 byte(s) at offset 27, only 139 of 166 remain
  ! ReadBytes: negative length -45136 at offset 27/167
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 3761350251223449645
        9    8  Int64    Entry/CharacterId = 7005738654528332899
       17    8  Int64    Entry/AccountId = 7293967940510299448
       25    2  Int16    Entry/Name/size = 13924

### 0x0061 IN src 12  over=7 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5227, only 0 of 5227 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 5355, only 0 of 5355 remain
  last reads before failure (of 0):

### 0x0073 IN src 12  over=7 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0073.py
  ! ReadBytes: wanted 26316 byte(s) at offset 10, only 450 of 460 remain
  ! ReadBytes: wanted 24772 byte(s) at offset 18, only 23 of 41 remain
  ! ReadBytes: wanted 24772 byte(s) at offset 18, only 23 of 41 remain
  last reads before failure (of 5):
        0    1  Byte     function = 0
        1    2  Int16    flags = 5
        3    1  Boolean  StringInterface/LocalizedString = False
        4    4  Int32    StringInterface/Unknown = 1694507008
        8    2  Int16    StringInterface/message/size = 13158

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 18, only 1 of 19 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 268435456
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 2304
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 12800

### 0x0015 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 2786, only 3 of 2789 remain
  last reads before failure (of 655):
     2754    4  Int32    Unlocked Taxis/MapId = 889204224
     2758    4  Int32    Unlocked Taxis/MapId = 788541696
     2762    4  Int32    Unlocked Taxis/MapId = 1627417856
     2766    4  Int32    Unlocked Taxis/MapId = 1577060864
     2770    4  Int32    Unlocked Taxis/MapId = 1946183680
     2774    4  Int32    Unlocked Taxis/MapId = 1879077888
     2778    4  Int32    Unlocked Taxis/MapId = 1056994048
     2782    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=1 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: negative length -39424 at offset 5378/6118
  last reads before failure (of 1965):
     5343    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = -1291845326
     5347    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = -2079223174905461878
     5355    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = 73903104862789001
     5363    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = False
     5364    4  Int32    gameObject_vtbl+572 virtual call/Unknown = 1
     5368    4  Int32    SkinColor/Color1 = 1
     5372    4  Int32    SkinColor/Color2 = 0
     5376    2  Int16    Profile Url/size = -19712

### 0x0035 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x004B OUT src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x004B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 85

### 0x004E IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 8 of 15 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 601
