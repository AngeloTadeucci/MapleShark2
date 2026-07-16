# Harness — MATRIX -> 2493

scripts from build : (matrix, see src column)
packets from build : 2493
packets considered : 4.658
packets executed   : 10.834  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                137   1.3%
OkExact               7.310   67.5%
UnderRead             3.028   27.9%
OverRead                359   3.3%

of packets a script actually ran on (10.697):
  clean (consumed exactly) : 68.3%
  over-read (WRONG)        : 3.4%
  under-read (ambiguous)   : 28.3%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12       2.113     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521       2.113     1.500    63.5%    36.5%     0.0%    0.0%         100% / 100%
0x0058  IN      2527       2.113     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN        12       1.468     1.468   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       1.468     1.468   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       1.468     1.468   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        12         188       188    50.5%    49.5%     0.0%    0.0%         100% / 100%
0x0012  OUT       12         163       163     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x000B  OUT       12          94        94   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12          82        82     1.2%    97.6%     1.2%    0.0%            0% / 20%
0x0021  IN      2511          82        82     0.0%    98.8%     1.2%    0.0%            0% / 20%
0x0021  IN      2525          82        82     0.0%    98.8%     1.2%    0.0%            0% / 20%
0x0021  IN      2529          82        82     0.0%    98.8%     1.2%    0.0%            0% / 20%
0x0021  IN      2546          82        82     0.0%    98.8%     1.2%    0.0%            0% / 20%
0x0021  IN      2549          82        82     0.0%    98.8%     1.2%    0.0%            0% / 20%
0x0021  IN      2550          82        82     0.0%    98.8%     1.2%    0.0%            0% / 20%
0x007E  IN         -          77         -                                     no script
0x0023  IN        12          76        76     3.9%     0.0%    96.1%    0.0%           99% / 99%
0x0023  IN      2486          76        76     2.6%    97.4%     0.0%    0.0%           16% / 16%
0x0023  IN      2502          76        76     2.6%    97.4%     0.0%    0.0%           10% / 10%
0x0047  IN        12          50        50     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x00B0  IN        12          31        31     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0026  OUT       12          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12          24        24     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          17        17     0.0%    94.1%     5.9%    0.0%            0% / 26%
0x005E  IN      2506          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521          12        12    41.7%    58.3%     0.0%    0.0%          19% / 100%
0x002E  IN      2528          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  IN        12          10        10    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x0052  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          10        10    70.0%    30.0%     0.0%    0.0%         100% / 100%
0x0093  IN         -           7         -                                     no script
0x00A8  IN         -           7         -                                     no script
0x0020  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507           6         6    83.3%    16.7%     0.0%    0.0%         100% / 100%
0x0020  OUT     2512           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  OUT        -           6         -                                     no script
0x0011  OUT        -           5         -                                     no script
0x0018  OUT       12           5         5    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -           5         -                                     no script
0x0097  IN         -           5         -                                     no script
0x0055  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           4         4     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00B6  IN        12           4         4     0.0%    50.0%    50.0%    0.0%            0% / 80%
0x00CC  IN        12           4         4     0.0%    75.0%    25.0%    0.0%            4% / 50%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x004F  OUT        -           3         -                                     no script
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
0x00F6  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00F6  IN      2520           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%    50.0%     0.0%    0.0%           4% / 100%
0x0022  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0048  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507           2         2     0.0%   100.0%     0.0%    0.0%             1% / 6%
0x0056  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CB  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            2% / 19%
0x00F4  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            1% / 24%
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
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           48% / 48%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%             8% / 8%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           48% / 48%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%           48% / 48%
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           1         1     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
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
0x009E  IN         -           1         -                                     no script
0x00A5  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           1         -                                     no script
0x00B0  OUT        -           1         -                                     no script
0x00B2  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
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
0x0109  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           97% / 97%
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0131  IN         -           1         -                                     no script
0x0136  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=163 threw=0 negative-length=21
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 254
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 11270
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 1
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = 1,84034E-40
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 8,452644E-32

### 0x0023 IN src 12  over=73 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  last reads before failure (of 63):
      180    8  Int64    Item: 50100000/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100000/ItemEnchant/Unknown = 16777216
      192    4  Int32    Item: 50100000/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100000/ItemEnchant/CanRepackage = False
      197    4  Int32    Item: 50100000/ItemEnchant/EnchantCharges = 0
      201    1  Byte     Item: 50100000/ItemEnchant/EnchantStats/EnchantStatCount = 0
      202    4  Int32    Item: 50100000/LimitBreak/LimitBreakLevel = 0
      206    4  Int32    Item: 50100000/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x0047 IN src 12  over=50 threw=0 negative-length=6
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -60570 at offset 3/40
  ! ReadBytes: negative length -60568 at offset 3/40
  ! ReadBytes: negative length -60566 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -30285

### 0x00B0 IN src 12  over=31 threw=0 negative-length=30
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: wanted 12292 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: negative length -54270 at offset 6/20
  ! ReadBytes: negative length -54270 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = -1876876032
        4    2  Int16    Motto/size = 6146

### 0x0061 IN src 12  over=4 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5291, only 2 of 5293 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 435, only 0 of 435 remain
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

### 0x0022 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0022.py
  ! Read<Single>: wanted 4 byte(s) at offset 274, only 0 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 276, only 0 of 276 remain
  last reads before failure (of 77):
      248    2  Int16    Item: 13200229/Stats/StaticStats/StatType = 105
      250    4  Int32    Item: 13200229/Stats/StaticStats/StatOption 13/IntegerValue = 7209063
      254    4  Single   Item: 13200229/Stats/StaticStats/StatOption 13/FloatValue = 0
      258    2  Int16    Item: 13200229/Stats/StaticStats/StatType = 0
      260    4  Int32    Item: 13200229/Stats/StaticStats/StatOption 14/IntegerValue = 0
      264    4  Single   Item: 13200229/Stats/StaticStats/StatOption 14/FloatValue = 0
      268    2  Int16    Item: 13200229/Stats/StaticStats/StatType = 0
      270    4  Int32    Item: 13200229/Stats/StaticStats/StatOption 15/IntegerValue = 0

### 0x002F IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 2261092
        4    1  Byte     Function = 1

### 0x0056 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 2243212

### 0x00B6 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B6.py
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 2 of 2 remain
  last reads before failure (of 0):

### 0x0015 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 2710, only 3 of 2713 remain
  last reads before failure (of 636):
     2678    4  Int32    Unlocked Taxis/MapId = 889204224
     2682    4  Int32    Unlocked Taxis/MapId = 788541696
     2686    4  Int32    Unlocked Taxis/MapId = 1627417856
     2690    4  Int32    Unlocked Taxis/MapId = 1577060864
     2694    4  Int32    Unlocked Taxis/MapId = 1946183680
     2698    4  Int32    Unlocked Taxis/MapId = 1879077888
     2702    4  Int32    Unlocked Taxis/MapId = 1056994048
     2706    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=1 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: negative length -50116 at offset 2671/5595
  last reads before failure (of 755):
     2638    1  Boolean  InBattle = True
     2639    1  Byte     gameObject_vtbl+572 virtual call/Unknown = 63
     2640    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 506783422
     2644    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 3236477766710020996
     2652    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = -554664723975151972
     2660    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
     2661    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 7206817000620441733
     2669    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = -25058
