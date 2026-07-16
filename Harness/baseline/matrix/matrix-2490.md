# Harness — MATRIX -> 2490

scripts from build : (matrix, see src column)
packets from build : 2490
packets considered : 2.052
packets executed   : 4.624  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                161   3.5%
OkExact               1.202   26.0%
UnderRead             2.442   52.8%
OverRead                818   17.7%
Threw                     1   0.0%

of packets a script actually ran on (4.463):
  clean (consumed exactly) : 26.9%
  over-read (WRONG)        : 18.3%
  under-read (ambiguous)   : 54.7%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12         625       625     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521         625       625    33.4%    66.6%     0.0%    0.0%          97% / 100%
0x0058  IN      2527         625       625   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12         375       375     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0023  IN        12         286       286     1.0%     0.0%    99.0%    0.0%           99% / 99%
0x0023  IN      2486         286       286     0.7%    99.3%     0.0%    0.0%           16% / 16%
0x0023  IN      2502         286       286     0.7%    99.3%     0.0%    0.0%           10% / 10%
0x0011  IN        12         122       122    50.8%    49.2%     0.0%    0.0%         100% / 100%
0x007E  IN         -         112         -                                     no script
0x0012  OUT       12         107       107     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0021  IN        12          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2511          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550          85        85     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x000B  OUT       12          61        61   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12          18        18     0.0%     0.0%   100.0%    0.0%           16% / 16%
0x0063  IN      2507          18        18    94.4%     5.6%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          18        18    94.4%     5.6%     0.0%    0.0%         100% / 100%
0x005E  IN        12          16        16     0.0%    93.8%     6.2%    0.0%             0% / 0%
0x005E  IN      2506          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12          16        16     0.0%    68.8%    31.2%    0.0%           9% / 100%
0x0006  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             0% / 8%
0x0052  IN      2516          11        11    72.7%    27.3%     0.0%    0.0%         100% / 100%
0x002E  IN        12          10        10     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x002E  IN      2521          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN      2528          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12           8         8     0.0%    87.5%    12.5%    0.0%           0% / 100%
0x00F6  IN      2520           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           7         7     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0078  OUT        -           7         -                                     no script
0x00A8  IN         -           7         -                                     no script
0x0037  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x005A  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0123  IN         -           5         -                                     no script
0x0048  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           19% / 33%
0x006A  IN      2486           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           4         4    25.0%    75.0%     0.0%    0.0%           5% / 100%
0x006A  IN      2502           4         4    50.0%    50.0%     0.0%    0.0%           7% / 100%
0x006A  IN      2503           4         4    50.0%    50.0%     0.0%    0.0%           7% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x008A  IN      2511           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524           4         4    75.0%     0.0%     0.0%   25.0%         100% / 100%
0x0024  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x005B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0069  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496           3         3    33.3%    66.7%     0.0%    0.0%          51% / 100%
0x0069  IN      2497           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502           3         3    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          18% / 100%
0x006B  IN      2507           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x006B  IN      2524           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x006B  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x006B  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x006B  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%           14% / 24%
0x0128  IN        12           3         3    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0005  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%    50.0%     0.0%    0.0%          14% / 100%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  OUT        -           2         -                                     no script
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x0093  IN         -           2         -                                     no script
0x00E6  IN         -           2         -                                     no script
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x012D  IN         -           2         -                                     no script
0x0001  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           1         -                                     no script
0x000F  OUT        -           1         -                                     no script
0x0010  OUT        -           1         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           18% / 18%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           18% / 18%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%           18% / 18%
0x001D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           50% / 50%
0x004D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x004D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           1         1     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x004D  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           13% / 13%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           1         -                                     no script
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2486           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           1         -                                     no script
0x009E  IN         -           1         -                                     no script
0x00A4  IN         -           1         -                                     no script
0x00A5  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           41% / 41%
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
0x00EB  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           1         -                                     no script
0x00F3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0103  IN         -           1         -                                     no script
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0131  IN         -           1         -                                     no script
0x0136  IN         -           1         -                                     no script

## Sample failures

### 0x0047 IN src 12  over=375 threw=0 negative-length=375
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -19730 at offset 3/40
  ! ReadBytes: negative length -19730 at offset 3/40
  ! ReadBytes: negative length -19730 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -9865

### 0x0023 IN src 12  over=283 threw=0
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

### 0x0012 OUT src 12  over=107 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 90
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 45
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -40
       28    1  Byte     Segment 0/StateSync/Unknown = 17
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 0
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 317
       33    4  Int32    Segment 0/StateSync/Unknown = 65021
       37    4  Int32    Segment 0/ClientTicks = 445682676

### 0x0063 IN src 12  over=18 threw=0 negative-length=12
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 26222 byte(s) at offset 27, only 194 of 221 remain
  ! ReadBytes: wanted 426 byte(s) at offset 27, only 139 of 166 remain
  ! ReadBytes: negative length -21696 at offset 27/167
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 4122482646343221254
        9    8  Int64    Entry/CharacterId = 7221584014890840931
       17    8  Int64    Entry/AccountId = 7221914744518895158
       25    2  Int16    Entry/Name/size = 13111

### 0x00CC IN src 12  over=5 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00CC.py
  ! ReadBytes: wanted 512 byte(s) at offset 27, only 283 of 310 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 280, only 0 of 280 remain
  ! ReadBytes: wanted 512 byte(s) at offset 27, only 283 of 310 remain
  last reads before failure (of 20):
       18    1  Byte     type = 43
       19    1  Byte     type = 25
       20    1  Byte     type = 45
       21    1  Byte     type = 36
       22    1  Byte     type = 4
       23    2  Int16    Unknown/size = 0
       25    0  Field    Unknown/Unknown = 
       25    2  Int16    Unknown/size = 256

### 0x0061 IN src 12  over=4 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5393, only 0 of 5393 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 1665, only 0 of 1665 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 117440512
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 2304
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 5632

### 0x005B IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x005B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 57766

### 0x0015 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 3362, only 3 of 3365 remain
  last reads before failure (of 799):
     3330    4  Int32    Unlocked Taxis/MapId = 889204224
     3334    4  Int32    Unlocked Taxis/MapId = 788541696
     3338    4  Int32    Unlocked Taxis/MapId = 1627417856
     3342    4  Int32    Unlocked Taxis/MapId = 1577060864
     3346    4  Int32    Unlocked Taxis/MapId = 1946183680
     3350    4  Int32    Unlocked Taxis/MapId = 1879077888
     3354    4  Int32    Unlocked Taxis/MapId = 1056994048
     3358    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 51200 byte(s) at offset 991, only 4465 of 5456 remain
  last reads before failure (of 221):
      958    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 1610662971
      962    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 17695
      970    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = 2522089132189024256
      978    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
      979    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 7782220156096217123
      987    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = 0
      989    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/UUID = 
      989    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/size = 25600

### 0x0035 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x003B OUT src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x003B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 1 of 2 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 2
