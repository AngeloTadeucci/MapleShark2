# Harness — MATRIX -> 2529

scripts from build : (matrix, see src column)
packets from build : 2529
packets considered : 65.185
packets executed   : 49.533  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              2.566   5.2%
OkExact              20.403   41.2%
UnderRead            20.225   40.8%
OverRead              6.339   12.8%

of packets a script actually ran on (46.967):
  clean (consumed exactly) : 43.4%
  over-read (WRONG)        : 13.5%
  under-read (ambiguous)   : 43.1%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      23.044     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521      23.044     1.500    48.3%    51.7%     0.0%    0.0%          97% / 100%
0x0058  IN      2527      23.044     1.500    96.7%     3.3%     0.0%    0.0%         100% / 100%
0x0012  OUT       12      13.195     1.500     0.1%     0.0%    99.9%    0.0%          95% / 100%
0x002E  IN        12       6.583     1.500     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521       6.583     1.500     3.3%    83.5%    13.2%    0.0%          19% / 100%
0x002E  IN      2528       6.583     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN        12       3.956     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       3.956     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       3.956     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        12       3.016     1.500    51.9%    48.1%     0.0%    0.0%         100% / 100%
0x000B  OUT       12       1.501     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -       1.378         -                                     no script
0x003D  IN        12       1.342     1.342     0.0%     2.2%    97.8%    0.0%         100% / 100%
0x003D  IN      2512       1.342     1.342    97.6%     2.4%     0.0%    0.0%         100% / 100%
0x003D  IN      2520       1.342     1.342     1.3%    98.6%     0.1%    0.0%             2% / 4%
0x003C  IN        12       1.083     1.083     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506       1.083     1.083     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507       1.083     1.083   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512       1.083     1.083   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520       1.083     1.083   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12         953       953     2.3%     0.0%    97.7%    0.0%           27% / 55%
0x0021  IN        12         765       765     1.4%    97.0%     1.6%    0.0%           17% / 20%
0x0021  IN      2511         765       765     0.8%    99.1%     0.1%    0.0%           17% / 20%
0x0021  IN      2525         765       765     1.3%    98.7%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         765       765     1.3%    98.7%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         765       765     1.3%    98.7%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         765       765     1.3%    98.7%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         765       765     1.3%    98.7%     0.0%    0.0%           17% / 20%
0x0066  IN        12         731       731    19.0%    53.2%    27.8%    0.0%           6% / 100%
0x0023  IN        12         439       439    14.4%     0.0%    85.6%    0.0%         100% / 100%
0x0023  IN      2486         439       439     9.6%    90.4%     0.0%    0.0%           17% / 20%
0x0023  IN      2502         439       439     9.6%    90.4%     0.0%    0.0%           11% / 20%
0x0006  IN        12         390       390   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         390       390   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         389       389   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12         375       375     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0020  OUT       12         373       373    93.3%     0.8%     5.9%    0.0%         100% / 100%
0x0020  OUT     2507         373       373    38.1%    61.9%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         373       373    93.3%     0.8%     5.9%    0.0%         100% / 100%
0x005E  IN        12         343       343     0.0%    93.9%     6.1%    0.0%           35% / 35%
0x005E  IN      2506         343       343   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  OUT       12         326       326   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12         313       313     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529         313       313   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         301       301     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0052  IN        12         269       269     0.0%    85.1%    14.9%    0.0%           20% / 85%
0x0052  IN      2516         269       269    18.6%    77.0%     4.5%    0.0%           8% / 100%
0x004B  IN        12         265       265     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507         265       265    16.2%    83.8%     0.0%    0.0%           6% / 100%
0x0055  IN        12         244       244     0.0%    99.6%     0.4%    0.0%             1% / 1%
0x0055  IN      2521         244       244     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         244       244    93.4%     0.4%     6.1%    0.0%         100% / 100%
0x004F  OUT        -         193         -                                     no script
0x00A8  IN         -         147         -                                     no script
0x0093  IN         -         143         -                                     no script
0x0056  IN        12         124       124     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0048  IN        12         118       118     0.0%    78.8%    21.2%    0.0%           48% / 90%
0x0048  IN      2504         118       118    78.8%    21.2%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         118       118    78.8%    21.2%     0.0%    0.0%         100% / 100%
0x0014  IN        12         104       104   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12          85        85     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12          70        70    54.3%    45.7%     0.0%    0.0%         100% / 100%
0x006A  IN      2486          70        70    68.6%    31.4%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          70        70    28.6%    71.4%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          70        70    34.3%    65.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          70        70    34.3%    65.7%     0.0%    0.0%          20% / 100%
0x0069  IN        12          67        67     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2486          67        67     0.0%    67.2%    32.8%    0.0%           20% / 84%
0x0069  IN      2496          67        67    22.4%    44.8%    32.8%    0.0%          70% / 100%
0x0069  IN      2497          67        67     0.0%    67.2%    32.8%    0.0%           20% / 84%
0x0069  IN      2502          67        67     0.0%    67.2%    32.8%    0.0%           20% / 84%
0x0069  IN      2503          67        67     1.5%    98.5%     0.0%    0.0%            3% / 20%
0x0069  IN      2504          67        67     1.5%    98.5%     0.0%    0.0%            3% / 20%
0x0069  IN      2521          67        67    67.2%     0.0%    32.8%    0.0%         100% / 100%
0x0069  IN      2546          67        67     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2549          67        67    67.2%     0.0%    32.8%    0.0%         100% / 100%
0x0069  IN      2550          67        67    67.2%     0.0%    32.8%    0.0%         100% / 100%
0x006B  IN        12          65        65     0.0%    67.7%    32.3%    0.0%          46% / 100%
0x006B  IN      2507          65        65    66.2%    33.8%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          65        65     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          65        65    66.2%    33.8%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          65        65     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          65        65     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          65        65     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          65        65   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          65        65     0.0%    67.7%    32.3%    0.0%           24% / 80%
0x0128  IN        12          48        48     8.3%    91.7%     0.0%    0.0%           14% / 14%
0x0019  IN        12          46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12          46        46     0.0%    43.5%    56.5%    0.0%           98% / 98%
0x00CC  IN        12          46        46     0.0%    95.7%     4.3%    0.0%           20% / 50%
0x00F1  IN         -          46         -                                     no script
0x0061  IN        12          45        45     0.0%     0.0%   100.0%    0.0%             0% / 0%
0x0005  IN        12          44        44   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12          43        43     0.0%   100.0%     0.0%    0.0%           14% / 14%
0x0138  IN         -          43         -                                     no script
0x001A  IN        12          42        42    50.0%     4.8%    45.2%    0.0%         100% / 100%
0x010A  IN        12          42        42     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          42         -                                     no script
0x012D  IN         -          42         -                                     no script
0x005F  IN        12          38        38     0.0%    97.4%     2.6%    0.0%             3% / 3%
0x0029  OUT       12          37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  IN        12          32        32     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12          31        31     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F4  IN        12          31        31     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x004F  IN        12          30        30     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x004F  IN      2507          30        30    23.3%     0.0%    76.7%    0.0%          16% / 100%
0x0080  OUT        -          30         -                                     no script
0x001E  IN        12          29        29     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0063  IN        12          29        29     0.0%    41.4%    58.6%    0.0%           24% / 27%
0x0063  IN      2507          29        29     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0063  IN      2518          29        29     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x00EB  IN        12          29        29     3.4%     0.0%    96.6%    0.0%         100% / 100%
0x0033  IN        12          28        28     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x008E  OUT        -          28         -                                     no script
0x002F  IN        12          27        27     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0037  IN        12          27        27     0.0%   100.0%     0.0%    0.0%           16% / 56%
0x0055  OUT        -          27         -                                     no script
0x00A5  IN         -          25         -                                     no script
0x001C  IN        12          24        24     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001C  IN      2507          24        24     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0044  IN        12          24        24     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00E6  IN         -          24         -                                     no script
0x0017  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          23        23     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          23        23     0.0%    26.1%    73.9%    0.0%         100% / 100%
0x0017  IN      2528          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  OUT       12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  OUT     2511          23        23     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          23        23    95.7%     4.3%     0.0%    0.0%         100% / 100%
0x0054  IN        12          23        23     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0001  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000F  OUT        -          22         -                                     no script
0x0010  OUT        -          22         -                                     no script
0x0016  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          22        22     9.1%    90.9%     0.0%    0.0%           62% / 62%
0x0035  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0039  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          22        22     0.0%    18.2%    81.8%    0.0%           56% / 56%
0x007D  IN      2486          22        22     0.0%     9.1%    90.9%    0.0%         100% / 100%
0x007D  IN      2502          22        22    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          22        22    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          22        22    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          22        22    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          22        22    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x00B0  OUT        -          22         -                                     no script
0x00B3  IN        12          22        22     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          22        22     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          22         -                                     no script
0x00CA  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12          22        22     0.0%   100.0%     0.0%    0.0%            8% / 10%
0x00D1  IN         -          22         -                                     no script
0x00F3  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0004  IN        12          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          21         -                                     no script
0x0013  IN        12          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12          21        21     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0015  IN      2507          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0070  IN        12          21        21     0.0%    95.2%     4.8%    0.0%           25% / 25%
0x0089  IN      2527          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          21         -                                     no script
0x00A7  IN        12          21        21     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          21        21     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -          21         -                                     no script
0x00B2  IN        12          21        21     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B7  IN        12          21        21     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          21        21     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          21        21     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          21         -                                     no script
0x00DF  IN         -          21         -                                     no script
0x00EE  IN         -          21         -                                     no script
0x0110  IN         -          21         -                                     no script
0x0126  IN         -          21         -                                     no script
0x0131  IN         -          21         -                                     no script
0x0137  IN         -          21         -                                     no script
0x013A  IN         -          21         -                                     no script
0x0031  OUT       12          20        20     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0010  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          16        16     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          12        12     0.0%    91.7%     8.3%    0.0%             0% / 0%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12          10        10     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0103  IN         -           9         -                                     no script
0x002F  OUT       12           8         8     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x00F2  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  OUT        -           7         -                                     no script
0x0016  OUT        -           6         -                                     no script
0x0038  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x003A  OUT        -           6         -                                     no script
0x0049  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529           6         6     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x008A  IN      2511           6         6     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524           6         6    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x001C  OUT        -           5         -                                     no script
0x0025  IN        12           5         5     0.0%     0.0%   100.0%    0.0%             7% / 9%
0x002B  IN        12           5         5     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002B  IN      2531           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002C  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0057  OUT        -           5         -                                     no script
0x000C  IN        12           4         4    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x000C  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  IN      2525           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           4         -                                     no script
0x0011  OUT        -           3         -                                     no script
0x0021  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x003F  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0009  OUT       12           2         2    50.0%     0.0%    50.0%    0.0%          14% / 100%
0x0009  OUT     2525           2         2    50.0%     0.0%    50.0%    0.0%          14% / 100%
0x000A  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0042  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 6%
0x0048  OUT        -           2         -                                     no script
0x005A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             4% / 5%
0x005A  IN      2490           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0068  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486           2         2    50.0%    50.0%     0.0%    0.0%          17% / 100%
0x0071  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00B8  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x00F9  IN         -           2         -                                     no script
0x0123  IN         -           2         -                                     no script
0x0009  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             2% / 2%
0x000B  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%           76% / 76%
0x000E  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0030  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502           1         1     0.0%   100.0%     0.0%    0.0%           73% / 73%
0x003C  OUT        -           1         -                                     no script
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x008A  OUT        -           1         -                                     no script
0x009C  OUT        -           1         -                                     no script
0x00D6  IN         -           1         -                                     no script
0x00FE  IN         -           1         -                                     no script
0x0109  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           91% / 91%
0x010F  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.499 threw=0 negative-length=150
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: wanted 29248 byte(s) at offset 45, only 0 of 45 remain
  ! ReadBytes: wanted 14718 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 22):
       28    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 833
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 16
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 16385
       34    1  Byte     Segment 0/StateSync/Unknown = 27
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 62
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = 1531
       39    4  Int32    Segment 0/StateSync/Unknown = -499449852
       43    2  Int16    Segment 0/StateSync/UnknownStr/size = 14624

### 0x003D IN src 12  over=1.313 threw=0 negative-length=366
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Boolean>: wanted 1 byte(s) at offset 56, only 0 of 56 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Boolean>: wanted 1 byte(s) at offset 56, only 0 of 56 remain
  last reads before failure (of 17):
       29    4  Single   DirectionCoordF/X = -2,3766398E+37
       33    4  Single   DirectionCoordF/Y = 1,683E-42
       37    4  Single   DirectionCoordF/Z = 4,591775E-39
       41    4  Single   RotationCoordF/X = 0,1500702
       45    4  Single   RotationCoordF/Y = -1,7014638E+38
       49    4  Single   RotationCoordF/Z = NaN
       53    2  Int16    CoordS / 10 = -1
       55    1  Boolean  Unknown = True

### 0x004E IN src 12  over=931 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 4000 byte(s) at offset 7, only 30 of 37 remain
  ! ReadBytes: wanted 47324 byte(s) at offset 11, only 22 of 33 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1, only 5 of 6 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 2000

### 0x0023 IN src 12  over=376 threw=0
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

### 0x0047 IN src 12  over=375 threw=0 negative-length=79
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 12950 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 12950 byte(s) at offset 3, only 10 of 13 remain
  ! ReadBytes: wanted 12950 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 6475

### 0x00B0 IN src 12  over=301 threw=0 negative-length=211
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -4092 at offset 6/20
  ! ReadBytes: negative length -20478 at offset 6/20
  ! ReadBytes: wanted 20994 byte(s) at offset 6, only 14 of 20 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = -1876901632
        4    2  Int16    Motto/size = -2046

### 0x0066 IN src 12  over=203 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0066.py
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 2 of 2 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 2 of 2 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 1 of 1 remain
  last reads before failure (of 0):

### 0x002E IN src 2521  over=198 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2521\Inbound\0x002E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  last reads before failure (of 12):
       10    4  Int32    0 base = 0
       14    4  Int32    0 total = 100
       18    4  Int32    1 bonus = 57
       22    4  Int32    1 base = 0
       26    4  Int32    1 total = 100
       30    4  Int32    2 bonus = 12
       34    4  Int32    2 base = 0
       38    4  Int32    2 total = 100

### 0x0056 IN src 12  over=124 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 4069814

### 0x0061 IN src 12  over=45 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  last reads before failure (of 0):

### 0x0052 IN src 12  over=40 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0052.py
  ! Read<Int32>: wanted 4 byte(s) at offset 11, only 2 of 13 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 11, only 2 of 13 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 11, only 2 of 13 remain
  last reads before failure (of 5):
        0    1  Byte     function = 1
        1    1  Byte     count = 182
        2    4  Int32    Item 0/serialId = 16793113
        6    4  Int32    Item 0/ItemId = -2113929216
       10    1  Byte     Item 0/field_64 = 100

### 0x0073 IN src 12  over=32 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0073.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 1 of 5 remain
  ! ReadBytes: wanted 24680 byte(s) at offset 10, only 367 of 377 remain
  ! ReadBytes: wanted 27750 byte(s) at offset 18, only 23 of 41 remain
  last reads before failure (of 3):
        0    1  Byte     function = 0
        1    2  Int16    flags = 0
        3    1  Boolean  StringInterface/LocalizedString = False
