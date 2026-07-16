# Harness — MATRIX -> 2528

scripts from build : (matrix, see src column)
packets from build : 2528
packets considered : 5.968
packets executed   : 11.390  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                128   1.1%
OkExact               5.995   52.6%
UnderRead             3.820   33.5%
OverRead              1.447   12.7%

of packets a script actually ran on (11.262):
  clean (consumed exactly) : 53.2%
  over-read (WRONG)        : 12.8%
  under-read (ambiguous)   : 33.9%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12       2.826     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       2.826     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       2.826     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12         931       931     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0058  IN        12         826       826     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521         826       826    53.5%    46.5%     0.0%    0.0%         100% / 100%
0x0058  IN      2527         826       826    66.3%    33.7%     0.0%    0.0%         100% / 100%
0x0023  IN        12         254       254     2.4%     0.0%    97.6%    0.0%         100% / 100%
0x0023  IN      2486         254       254     1.6%    98.4%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         254       254     1.6%    98.4%     0.0%    0.0%           11% / 11%
0x0021  IN        12         199       199     6.5%    93.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2511         199       199     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         199       199     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         199       199     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         199       199     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         199       199     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         199       199     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0011  IN        12         148       148    52.0%    48.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12          90        90     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0047  IN        12          87        87     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x000B  OUT       12          73        73   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          49        49     0.0%    95.9%     4.1%    0.0%            0% / 16%
0x005E  IN      2506          49        49   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          24        24     0.0%    91.7%     8.3%    0.0%             0% / 0%
0x00F6  IN      2520          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -          21         -                                     no script
0x0006  IN        12          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          20        20     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          20        20    70.0%    30.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12          19        19     0.0%   100.0%     0.0%    0.0%            2% / 26%
0x002E  IN      2521          19        19    63.2%    31.6%     5.3%    0.0%         100% / 100%
0x002E  IN      2528          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  OUT        -          18         -                                     no script
0x0074  IN        12          18        18     0.0%    94.4%     5.6%    0.0%             5% / 8%
0x004B  IN        12          14        14     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          14        14     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00A8  IN         -          14         -                                     no script
0x008A  IN      2511          12        12     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          12        12    75.0%     8.3%    16.7%    0.0%         100% / 100%
0x0061  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0093  IN         -          10         -                                     no script
0x00CC  IN        12           9         9     0.0%    77.8%    22.2%    0.0%            9% / 50%
0x006C  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0045  IN        12           6         6     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0055  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           6         6     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528           6         6    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x0069  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           6         6     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2496           6         6     0.0%    66.7%    33.3%    0.0%           47% / 54%
0x0069  IN      2497           6         6     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2502           6         6     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2503           6         6     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           6         6     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           6         6    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           6         6     0.0%   100.0%     0.0%    0.0%            2% / 20%
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
0x00B6  IN        12           6         6     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0039  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x003D  IN        12           5         5     0.0%    20.0%    80.0%    0.0%          96% / 100%
0x003D  IN      2512           5         5    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520           5         5    40.0%    40.0%    20.0%    0.0%         100% / 100%
0x00F4  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x011C  IN         -           5         -                                     no script
0x0128  IN        12           5         5    20.0%    80.0%     0.0%    0.0%          14% / 100%
0x0019  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           4         4    50.0%    50.0%     0.0%    0.0%           3% / 100%
0x0022  OUT       12           4         4     0.0%   100.0%     0.0%    0.0%           85% / 85%
0x0044  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004C  IN        12           4         4     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x0123  IN         -           4         -                                     no script
0x012D  IN         -           4         -                                     no script
0x0138  IN         -           4         -                                     no script
0x0020  OUT       12           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0020  OUT     2507           3         3    33.3%    66.7%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0048  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x0017  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           92% / 96%
0x0017  IN      2500           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           2         2     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x0017  IN      2528           2         2     0.0%     0.0%   100.0%    0.0%           11% / 11%
0x0017  IN      2550           2         2     0.0%     0.0%   100.0%    0.0%           92% / 96%
0x001F  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x002F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0033  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           2         2     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           2         -                                     no script
0x005A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             4% / 4%
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
0x0080  OUT        -           2         -                                     no script
0x0089  IN      2527           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           2         -                                     no script
0x009E  IN         -           2         -                                     no script
0x00A5  IN         -           2         -                                     no script
0x00A7  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           2         -                                     no script
0x00B0  OUT        -           2         -                                     no script
0x00B2  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           2         -                                     no script
0x00B7  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           2         -                                     no script
0x00CA  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             8% / 8%
0x00D1  IN         -           2         -                                     no script
0x00DF  IN         -           2         -                                     no script
0x00E6  IN         -           2         -                                     no script
0x00EB  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           2         -                                     no script
0x00F3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           2         -                                     no script
0x011B  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           2         -                                     no script
0x0131  IN         -           2         -                                     no script
0x0137  IN         -           2         -                                     no script
0x013A  IN         -           2         -                                     no script
0x001C  OUT        -           1         -                                     no script
0x002B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           93% / 93%
0x002B  IN      2530           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           53% / 53%
0x0037  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0056  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0090  IN         -           1         -                                     no script
0x0094  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=931 threw=0 negative-length=50
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 8
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -21753
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    4  Int32    Segment 0/ClientTicks = 447943370

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

### 0x00B0 IN src 12  over=90 threw=0 negative-length=90
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -6654 at offset 6/20
  ! ReadBytes: negative length -43006 at offset 6/20
  ! ReadBytes: negative length -47102 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593032960
        4    2  Int16    Motto/size = -3327

### 0x0047 IN src 12  over=87 threw=0 negative-length=87
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -44104 at offset 3/40
  ! ReadBytes: negative length -44104 at offset 3/40
  ! ReadBytes: negative length -44104 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -22052

### 0x0061 IN src 12  over=11 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5091, only 0 of 5091 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5381, only 0 of 5381 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=6 threw=0
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

### 0x003D IN src 12  over=4 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Boolean>: wanted 1 byte(s) at offset 56, only 0 of 56 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  last reads before failure (of 17):
       29    4  Single   DirectionCoordF/X = 5,303815E-35
       33    4  Single   DirectionCoordF/Y = 1,052E-42
       37    4  Single   DirectionCoordF/Z = 1,487735E-38
       41    4  Single   RotationCoordF/X = 7,313838E-39
       45    4  Single   RotationCoordF/Y = 2,658537E+36
       49    4  Single   RotationCoordF/Z = NaN
       53    2  Int16    CoordS / 10 = -1
       55    1  Boolean  Unknown = True

### 0x0015 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 2790, only 3 of 2793 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 2790, only 3 of 2793 remain
  last reads before failure (of 656):
     2758    4  Int32    Unlocked Taxis/MapId = 889204224
     2762    4  Int32    Unlocked Taxis/MapId = 788541696
     2766    4  Int32    Unlocked Taxis/MapId = 1627417856
     2770    4  Int32    Unlocked Taxis/MapId = 1577060864
     2774    4  Int32    Unlocked Taxis/MapId = 1946183680
     2778    4  Int32    Unlocked Taxis/MapId = 1879077888
     2782    4  Int32    Unlocked Taxis/MapId = 1056994048
     2786    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=2 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: negative length -63486 at offset 5884/6111
  ! ReadBytes: wanted 16736 byte(s) at offset 5607, only 465 of 6072 remain
  last reads before failure (of 1578):
     4585    1  Byte     gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 0
     4586    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 0
     4590    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/AccountId = 10110013718571484
     4598    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterId = 1923884184537835996
     4606    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterName/size = 633
     4608  1266  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterName/CharacterName = B31AE3145E0501000100000000000000..
     5874    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CreationTime = 37
     5882    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UGC Url/size = -31743

### 0x002F IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 6203868
        4    1  Byte     Function = 1

### 0x0035 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x004B OUT src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x004B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 85
