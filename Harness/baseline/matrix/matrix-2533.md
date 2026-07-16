# Harness — MATRIX -> 2533

scripts from build : (matrix, see src column)
packets from build : 2533
packets considered : 108.241
packets executed   : 26.430  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              2.136   8.1%
OkExact              12.281   46.5%
UnderRead             6.702   25.4%
OverRead              5.311   20.1%

of packets a script actually ran on (24.294):
  clean (consumed exactly) : 50.6%
  over-read (WRONG)        : 21.9%
  under-read (ambiguous)   : 27.6%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x001C  IN        12      55.591     1.500     1.2%     0.2%    98.6%    0.0%         100% / 100%
0x001C  IN      2507      55.591     1.500    73.7%    20.3%     6.0%    0.0%         100% / 100%
0x0058  IN        12      27.428     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      27.428     1.500    82.6%    17.4%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      27.428     1.500    95.8%     4.2%     0.0%    0.0%         100% / 100%
0x0012  OUT       12      13.662     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0011  IN        12       2.077     1.500    49.0%    51.0%     0.0%    0.0%           6% / 100%
0x0024  IN        12       1.935     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       1.935     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       1.935     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -       1.562         -                                     no script
0x0047  IN        12       1.082     1.082     0.0%     0.0%   100.0%    0.0%             7% / 7%
0x000B  OUT       12       1.037     1.037   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         450       450     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x005E  IN        12         324       324     0.0%    97.8%     2.2%    0.0%           26% / 35%
0x005E  IN      2506         324       324   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12         268       268     0.4%    99.3%     0.4%    0.0%           17% / 20%
0x0021  IN      2511         268       268     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         268       268     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         268       268     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         268       268     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         268       268     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         268       268     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0006  IN        12         262       262   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         262       262   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         262       262   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -         196         -                                     no script
0x0023  IN        12         167       167    12.6%     0.0%    87.4%    0.0%         100% / 100%
0x0023  IN      2486         167       167     8.4%    91.6%     0.0%    0.0%           17% / 20%
0x0023  IN      2502         167       167     8.4%    91.6%     0.0%    0.0%           11% / 20%
0x0055  IN        12         137       137     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         137       137     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         137       137    97.1%     2.9%     0.0%    0.0%         100% / 100%
0x001D  IN        12         130       130   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12         110       110    43.6%     0.0%    56.4%    0.0%         100% / 100%
0x002E  IN        12          97        97     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521          97        97    30.9%    51.5%    17.5%    0.0%          32% / 100%
0x002E  IN      2528          97        97    82.5%    17.5%     0.0%    0.0%         100% / 100%
0x0093  IN         -          74         -                                     no script
0x004F  OUT        -          54         -                                     no script
0x0061  IN        12          53        53     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x00A8  IN         -          51         -                                     no script
0x0066  IN        12          46        46     0.0%    47.8%    52.2%    0.0%            0% / 44%
0x0011  OUT        -          45         -                                     no script
0x0056  IN        12          42        42     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0052  IN        12          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0052  IN      2516          35        35    40.0%    60.0%     0.0%    0.0%          20% / 100%
0x0017  IN        12          28        28     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          28        28     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          28        28     0.0%    57.1%    42.9%    0.0%          60% / 100%
0x0017  IN      2528          28        28     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          28        28     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  OUT       12          28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12          28        28     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0128  IN        12          25        25    20.0%    80.0%     0.0%    0.0%          11% / 100%
0x0048  IN        12          24        24     0.0%    91.7%     8.3%    0.0%           48% / 48%
0x0048  IN      2504          24        24    91.7%     8.3%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          24        24    91.7%     8.3%     0.0%    0.0%         100% / 100%
0x0045  IN        12          22        22     0.0%    13.6%    86.4%    0.0%           98% / 98%
0x008A  IN      2511          22        22     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          22        22    81.8%     0.0%    18.2%    0.0%         100% / 100%
0x00F4  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x0069  IN        12          21        21     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          21        21     0.0%    66.7%    33.3%    0.0%           20% / 43%
0x0069  IN      2496          21        21    14.3%    52.4%    33.3%    0.0%          34% / 100%
0x0069  IN      2497          21        21     0.0%    66.7%    33.3%    0.0%           20% / 43%
0x0069  IN      2502          21        21     0.0%    66.7%    33.3%    0.0%           20% / 43%
0x0069  IN      2503          21        21     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          21        21     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          21        21    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546          21        21     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          21        21    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550          21        21    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x006A  IN        12          21        21    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2486          21        21    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          21        21    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          21        21    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          21        21    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006B  IN        12          21        21     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507          21        21    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          21        21    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          21        21     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0005  IN        12          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12          18        18    38.9%     5.6%    55.6%    0.0%          97% / 100%
0x003D  IN      2512          18        18    61.1%    38.9%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          18        18    38.9%    44.4%    16.7%    0.0%          95% / 100%
0x00F6  IN        12          17        17     0.0%    76.5%    23.5%    0.0%           0% / 100%
0x00F6  IN      2520          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506          16        16     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CA  IN        12          16        16     0.0%    43.8%    56.2%    0.0%           50% / 50%
0x00F1  IN         -          16         -                                     no script
0x003F  IN        12          15        15     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12          15        15    26.7%    13.3%    60.0%    0.0%          90% / 100%
0x0019  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          14        14    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0022  OUT       12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12          14        14     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004B  IN        12          14        14     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          14        14    42.9%    57.1%     0.0%    0.0%           6% / 100%
0x006D  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CC  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00E6  IN         -          14         -                                     no script
0x010A  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          14         -                                     no script
0x012D  IN         -          14         -                                     no script
0x0138  IN         -          14         -                                     no script
0x0020  OUT       12          13        13    53.8%    46.2%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507          13        13     7.7%    92.3%     0.0%    0.0%           89% / 89%
0x0020  OUT     2512          13        13    53.8%    46.2%     0.0%    0.0%         100% / 100%
0x0033  IN        12          13        13     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12          13        13     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0044  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0063  IN        12          11        11     0.0%     0.0%   100.0%    0.0%           33% / 35%
0x0063  IN      2507          11        11     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0063  IN      2518          11        11     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0055  OUT        -          10         -                                     no script
0x000C  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           7         -                                     no script
0x000F  OUT        -           7         -                                     no script
0x0010  OUT        -           7         -                                     no script
0x0015  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0035  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           56% / 56%
0x007D  IN      2486           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           7         -                                     no script
0x009E  IN         -           7         -                                     no script
0x00A5  IN         -           7         -                                     no script
0x00A7  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           7         -                                     no script
0x00B0  OUT        -           7         -                                     no script
0x00B2  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00B3  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           7         -                                     no script
0x00B7  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           7         -                                     no script
0x00CB  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           15% / 15%
0x00D1  IN         -           7         -                                     no script
0x00DF  IN         -           7         -                                     no script
0x00EB  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           7         -                                     no script
0x00F3  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           7         -                                     no script
0x011B  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           7         -                                     no script
0x0131  IN         -           7         -                                     no script
0x0137  IN         -           7         -                                     no script
0x013A  IN         -           7         -                                     no script
0x0013  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12           6         6     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0010  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F2  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002D  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  OUT       12           3         3     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00BB  OUT        -           3         -                                     no script
0x012A  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00BA  OUT        -           2         -                                     no script
0x00C1  IN         -           2         -                                     no script
0x00C3  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0109  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           91% / 91%
0x0030  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004A  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           17% / 17%
0x005F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0084  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             0% / 0%
0x00F9  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=201
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -3140 at offset 35/41
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 19):
       21    1  Byte     Segment 0/StateSync/Animation3 = 90
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 201
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 1800
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    2  Int16    Segment 0/StateSync/AnimationString?/size = -1570

### 0x001C IN src 12  over=1.479 threw=0 negative-length=92
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Single>: wanted 4 byte(s) at offset 36, only 0 of 36 remain
  ! Read<Single>: wanted 4 byte(s) at offset 36, only 0 of 36 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 18):
       17    2  Int16    StateSync/SpeedCoordS/X = 11264
       19    2  Int16    StateSync/SpeedCoordS/Y = 1536
       21    2  Int16    StateSync/SpeedCoordS/Z = 1024
       23    1  Byte     StateSync/Unknown = 66
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 26629
       26    2  Int16    StateSync/CoordS / 1000 = 256
       28    4  Single   StateSync/UnknownCoordF/X = 1,4177314E-37
       32    4  Single   StateSync/UnknownCoordF/Y = 5,50293E-40

### 0x0047 IN src 12  over=1.082 threw=0 negative-length=903
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -46742 at offset 3/44
  ! ReadBytes: negative length -46742 at offset 3/44
  ! ReadBytes: negative length -46742 at offset 3/44
  last reads before failure (of 2):
        0    1  Byte     function = 2
        1    2  Int16    message/size = -23371

### 0x00B0 IN src 12  over=450 threw=0 negative-length=330
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -8702 at offset 6/20
  ! ReadBytes: negative length -54782 at offset 6/20
  ! ReadBytes: negative length -8702 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037312
        4    2  Int16    Motto/size = -4351

### 0x0023 IN src 12  over=146 threw=0
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

### 0x001C IN src 2507  over=90 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 1053
       13    2  Int16    coord x = 3140
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = 578431082174366722
       30    2  Int16    speed x = 6

### 0x004E IN src 12  over=62 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 16014 byte(s) at offset 7, only 48 of 55 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1, only 5 of 6 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 13, only 1 of 14 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 10
        5    2  Int16    FunctionCubeName/size = 8007

### 0x0061 IN src 12  over=53 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 1317, only 1 of 1318 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0056 IN src 12  over=42 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 30442

### 0x0017 IN src 12  over=28 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1542, only 3 of 1545 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 4315, only 6 of 4321 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 209):
     1478    8  Int64    PlayerInfo/Player+1B0 = -1801437670676221739
     1486    8  Int64    PlayerInfo/Player+1B0 = 4305693181
     1494    8  Int64    PlayerInfo/Player+1B0 = 65536
     1502    8  Int64    PlayerInfo/Player+1B0 = 0
     1510    8  Int64    PlayerInfo/Player+1B0 = 0
     1518    8  Int64    PlayerInfo/Player+1B0 = 0
     1526    8  Int64    PlayerInfo/Player+1B0 = 0
     1534    8  Int64    PlayerInfo/Player+1B0 = 1406125048070144

### 0x0017 IN src 2528  over=28 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1542, only 3 of 1545 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 4315, only 6 of 4321 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 209):
     1478    8  Int64    PlayerInfo/Player+1B0 = -1801437670676221739
     1486    8  Int64    PlayerInfo/Player+1B0 = 4305693181
     1494    8  Int64    PlayerInfo/Player+1B0 = 65536
     1502    8  Int64    PlayerInfo/Player+1B0 = 0
     1510    8  Int64    PlayerInfo/Player+1B0 = 0
     1518    8  Int64    PlayerInfo/Player+1B0 = 0
     1526    8  Int64    PlayerInfo/Player+1B0 = 0
     1534    8  Int64    PlayerInfo/Player+1B0 = 1406125048070144

### 0x0017 IN src 2550  over=28 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1542, only 3 of 1545 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 4315, only 6 of 4321 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  last reads before failure (of 209):
     1478    8  Int64    PlayerInfo/Player+1B0 = -1801437670676221739
     1486    8  Int64    PlayerInfo/Player+1B0 = 4305693181
     1494    8  Int64    PlayerInfo/Player+1B0 = 65536
     1502    8  Int64    PlayerInfo/Player+1B0 = 0
     1510    8  Int64    PlayerInfo/Player+1B0 = 0
     1518    8  Int64    PlayerInfo/Player+1B0 = 0
     1526    8  Int64    PlayerInfo/Player+1B0 = 0
     1534    8  Int64    PlayerInfo/Player+1B0 = 1406125048070144
