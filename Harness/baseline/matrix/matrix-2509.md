# Harness — MATRIX -> 2509

scripts from build : (matrix, see src column)
packets from build : 2509
packets considered : 2.771
packets executed   : 7.629  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                 73   1.0%
OkExact               5.594   73.3%
UnderRead             1.663   21.8%
OverRead                299   3.9%

of packets a script actually ran on (7.556):
  clean (consumed exactly) : 74.0%
  over-read (WRONG)        : 4.0%
  under-read (ambiguous)   : 22.0%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12       1.415     1.415   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       1.415     1.415   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       1.415     1.415   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN        12         509       509     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521         509       509    99.6%     0.4%     0.0%    0.0%         100% / 100%
0x0058  IN      2527         509       509   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        12         133       133    51.1%    48.9%     0.0%    0.0%         100% / 100%
0x0023  IN        12         126       126     2.4%     0.0%    97.6%    0.0%         100% / 100%
0x0023  IN      2486         126       126     1.6%    98.4%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         126       126     1.6%    98.4%     0.0%    0.0%           11% / 11%
0x0012  OUT       12         103       103     0.0%     0.0%   100.0%    0.0%           95% / 95%
0x0021  IN        12          95        95     1.1%    97.9%     1.1%    0.0%            0% / 20%
0x0021  IN      2511          95        95     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2525          95        95     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2529          95        95     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2546          95        95     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2549          95        95     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2550          95        95     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x000B  OUT       12          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12          42        42     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x008A  IN      2511          33        33     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x008A  IN      2524          33        33    90.9%     6.1%     3.0%    0.0%         100% / 100%
0x005E  IN        12          17        17     0.0%    94.1%     5.9%    0.0%            0% / 26%
0x005E  IN      2506          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AD  IN         -          12         -                                     no script
0x00F6  IN        12          12        12     0.0%    91.7%     8.3%    0.0%             0% / 4%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          10        10    70.0%    30.0%     0.0%    0.0%         100% / 100%
0x006A  OUT        -           8         -                                     no script
0x006C  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0093  IN         -           7         -                                     no script
0x00A8  IN         -           7         -                                     no script
0x007D  OUT        -           6         -                                     no script
0x007E  IN         -           6         -                                     no script
0x00D3  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            5% / 24%
0x0039  OUT       12           5         5    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002E  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12           4         4     0.0%    75.0%    25.0%    0.0%            4% / 50%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496           3         3    33.3%    66.7%     0.0%    0.0%          54% / 100%
0x0069  IN      2497           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
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
0x000C  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x000C  IN      2507           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x000C  IN      2525           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%    50.0%     0.0%    0.0%           3% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0048  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -           2         -                                     no script
0x0055  OUT        -           2         -                                     no script
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CB  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            3% / 15%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x0123  IN         -           2         -                                     no script
0x0128  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 14%
0x0001  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  OUT        -           1         -                                     no script
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
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           88% / 88%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%             8% / 8%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           11% / 11%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%           88% / 88%
0x0019  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x005A  IN      2490           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0073  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x0097  OUT        -           1         -                                     no script
0x009E  IN         -           1         -                                     no script
0x00A4  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00A5  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
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
0x0138  IN         -           1         -                                     no script

## Sample failures

### 0x0023 IN src 12  over=123 threw=0
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

### 0x0012 OUT src 12  over=103 threw=0 negative-length=66
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: wanted 64744 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: negative length -63434 at offset 39/41
  ! ReadBytes: negative length -63002 at offset 39/41
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 132
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -1533
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = 32372

### 0x0047 IN src 12  over=42 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 65480 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 65480 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 65480 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 32740

### 0x0061 IN src 12  over=5 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5161, only 2 of 5163 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5425, only 2 of 5427 remain
  last reads before failure (of 0):

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
  ! Read<Int32>: wanted 4 byte(s) at offset 2782, only 3 of 2785 remain
  last reads before failure (of 654):
     2750    4  Int32    Unlocked Taxis/MapId = 889204224
     2754    4  Int32    Unlocked Taxis/MapId = 788541696
     2758    4  Int32    Unlocked Taxis/MapId = 1627417856
     2762    4  Int32    Unlocked Taxis/MapId = 1577060864
     2766    4  Int32    Unlocked Taxis/MapId = 1946183680
     2770    4  Int32    Unlocked Taxis/MapId = 1879077888
     2774    4  Int32    Unlocked Taxis/MapId = 1056994048
     2778    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 2084 byte(s) at offset 5233, only 680 of 5913 remain
  last reads before failure (of 1927):
     5200    1  Boolean  InBattle = True
     5201    1  Byte     gameObject_vtbl+572 virtual call/Unknown = 6
     5202    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 65537
     5206    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 65536
     5214    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = 8430742350258503680
     5222    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
     5223    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 8421449843236667411
     5231    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = 1042

### 0x0021 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0021.py
  ! Read<Int64>: wanted 8 byte(s) at offset 195, only 3 of 198 remain
  last reads before failure (of 60):
      172    2  Int16    Item/Item: 20300006/Stats/Empowerment Stats 3/EmpowermentSpecialOptionCount = 0
      174    4  Int32    Item/Item: 20300006/Stats/Unknown = 65536
      178    2  Int16    Item/Item: 20300006/Stats/Empowerment Stats 4/EmpowermentStatOptionCount = 0
      180    2  Int16    Item/Item: 20300006/Stats/Empowerment Stats 4/EmpowermentSpecialOptionCount = 0
      182    4  Int32    Item/Item: 20300006/Stats/Unknown = 0
      186    4  Int32    Item/Item: 20300006/ItemEnchant/Enchants = 0
      190    4  Int32    Item/Item: 20300006/ItemEnchant/EnchantExp = 0
      194    1  Byte     Item/Item: 20300006/ItemEnchant/EnchantBasedChargeExp = 0

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
