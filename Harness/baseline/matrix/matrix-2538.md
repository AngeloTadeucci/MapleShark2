# Harness — MATRIX -> 2538

scripts from build : (matrix, see src column)
packets from build : 2538
packets considered : 883
packets executed   : 2.407  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                 56   2.3%
OkExact                 438   18.2%
UnderRead             1.526   63.4%
OverRead                387   16.1%

of packets a script actually ran on (2.351):
  clean (consumed exactly) : 18.6%
  over-read (WRONG)        : 16.5%
  under-read (ambiguous)   : 64.9%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0023  IN        12         298       298     1.0%     0.0%    99.0%    0.0%         100% / 100%
0x0023  IN      2486         298       298     0.7%    99.3%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         298       298     0.7%    99.3%     0.0%    0.0%           11% / 11%
0x0058  IN        12         111       111     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521         111       111   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN      2527         111       111   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2511          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550          93        93     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0011  IN        12          75        75    52.0%    48.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12          47        47     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x000B  OUT       12          37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          16        16     0.0%    93.8%     6.2%    0.0%             0% / 0%
0x005E  IN      2506          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             0% / 8%
0x0052  IN      2516          11        11    72.7%    27.3%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          11        11     0.0%    81.8%    18.2%    0.0%           0% / 100%
0x00F6  IN      2520          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0053  IN        12           9         9     0.0%    88.9%    11.1%    0.0%            0% / 17%
0x0047  IN        12           7         7     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x00A8  IN         -           7         -                                     no script
0x0006  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12           6         6     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x007E  IN         -           5         -                                     no script
0x0123  IN         -           5         -                                     no script
0x0005  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x008A  IN      2511           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524           4         4    75.0%     0.0%    25.0%    0.0%         100% / 100%
0x0011  OUT        -           3         -                                     no script
0x001D  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           3         3     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2496           3         3     0.0%    66.7%    33.3%    0.0%           51% / 53%
0x0069  IN      2497           3         3     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2502           3         3     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
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
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%           14% / 24%
0x013B  IN         -           3         -                                     no script
0x0010  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%    50.0%     0.0%    0.0%          14% / 100%
0x002B  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CC  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            2% / 50%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x0128  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 14%
0x012D  IN         -           2         -                                     no script
0x0138  IN         -           2         -                                     no script
0x0001  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -           1         -                                     no script
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           1         -                                     no script
0x0055  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             7% / 7%
0x0063  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0063  IN      2518           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
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
0x0097  OUT        -           1         -                                     no script
0x009E  IN         -           1         -                                     no script
0x00A4  IN         -           1         -                                     no script
0x00A5  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           41% / 41%
0x00AD  IN         -           1         -                                     no script
0x00B0  OUT        -           1         -                                     no script
0x00B2  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           1         -                                     no script
0x00B7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           1         -                                     no script
0x00CA  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
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
0x013A  IN         -           1         -                                     no script
0x013C  IN         -           1         -                                     no script

## Sample failures

### 0x0023 IN src 12  over=295 threw=0
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

### 0x0012 OUT src 12  over=47 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 8
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -17657
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 2,3740262E+11

### 0x0047 IN src 12  over=7 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 21816 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 21816 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 21816 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 10908

### 0x0061 IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5463, only 0 of 5463 remain
  ! Read<Single>: wanted 4 byte(s) at offset 4661, only 2 of 4663 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 134217728
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 3072
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 6656

### 0x00F6 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00F6.py
  ! Read<Int32>: wanted 4 byte(s) at offset 515, only 0 of 515 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 739, only 3 of 742 remain
  last reads before failure (of 98):
      471    4  Int32    Entry 29/QuestId? = 0
      475    8  Int64    Entry 29/Timestamp = 545319267021619200
      483    4  Int32    Entry 30/Index+1000 = -1358954496
      487    4  Int32    Entry 30/QuestId? = -2130706432
      491    8  Int64    Entry 30/Timestamp = 4026531840
      499    4  Int32    Entry 31/Index+1000 = 5963953
      503    4  Int32    Entry 31/QuestId? = 301989888
      507    8  Int64    Entry 31/Timestamp = 72057594043978687

### 0x0015 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 3570, only 3 of 3573 remain
  last reads before failure (of 851):
     3538    4  Int32    Unlocked Taxis/MapId = 889204224
     3542    4  Int32    Unlocked Taxis/MapId = 788541696
     3546    4  Int32    Unlocked Taxis/MapId = 1627417856
     3550    4  Int32    Unlocked Taxis/MapId = 1577060864
     3554    4  Int32    Unlocked Taxis/MapId = 1946183680
     3558    4  Int32    Unlocked Taxis/MapId = 1879077888
     3562    4  Int32    Unlocked Taxis/MapId = 1056994048
     3566    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 5384, only 0 of 5384 remain
  last reads before failure (of 685):
     5320    8  Int64    PlayerInfo/Player+1B0 = 73903105067080979
     5328    8  Int64    PlayerInfo/Player+1B0 = 1099511628032
     5336    8  Int64    PlayerInfo/Player+1B0 = 0
     5344    8  Int64    PlayerInfo/Player+1B0 = 0
     5352    8  Int64    PlayerInfo/Player+1B0 = 0
     5360    8  Int64    PlayerInfo/Player+1B0 = 16779776
     5368    8  Int64    PlayerInfo/Player+1B0 = 426726845440
     5376    8  Int64    PlayerInfo/Player+1B0 = 549755813632

### 0x0035 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x0053 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0053.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1, only 5 of 6 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 25

### 0x0054 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 4294967296

### 0x005E IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x005E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 1 of 1 remain
  last reads before failure (of 0):
