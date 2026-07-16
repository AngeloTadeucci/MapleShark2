# Harness — MATRIX -> 2502

scripts from build : (matrix, see src column)
packets from build : 2502
packets considered : 78.812
packets executed   : 65.321  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              2.210   3.4%
OkExact              21.647   33.1%
UnderRead            32.773   50.2%
OverRead              8.691   13.3%

of packets a script actually ran on (63.111):
  clean (consumed exactly) : 34.3%
  over-read (WRONG)        : 13.8%
  under-read (ambiguous)   : 51.9%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12      17.948     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      17.948     1.500    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      17.948     1.500    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x0058  IN        12      14.758     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521      14.758     1.500    29.5%    70.5%     0.0%    0.0%          88% / 100%
0x0058  IN      2527      14.758     1.500    43.8%    56.2%     0.0%    0.0%          89% / 100%
0x0012  OUT       12      13.582     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x001C  IN        12       4.354     1.500     0.5%     0.2%    99.3%    0.0%         100% / 100%
0x001C  IN      2507       4.354     1.500    80.1%     2.0%    17.9%    0.0%         100% / 100%
0x0011  IN        12       3.654     1.500    52.0%    48.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12       2.509     1.500     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521       2.509     1.500     8.5%    89.1%     2.3%    0.0%          19% / 100%
0x002E  IN      2528       2.509     1.500    99.1%     0.3%     0.5%    0.0%         100% / 100%
0x00CB  IN        12       2.166     1.500     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0023  IN        12       2.027     1.500     7.2%     0.0%    92.8%    0.0%         100% / 100%
0x0023  IN      2486       2.027     1.500     3.0%    97.0%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       2.027     1.500     3.5%    96.5%     0.0%    0.0%           11% / 11%
0x003D  IN        12       1.923     1.500     0.0%     1.6%    98.4%    0.0%           96% / 96%
0x003D  IN      2512       1.923     1.500    98.4%     1.6%     0.0%    0.0%         100% / 100%
0x003D  IN      2520       1.923     1.500     4.1%    95.9%     0.0%    0.0%             4% / 4%
0x000B  OUT       12       1.814     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12       1.766     1.500     0.0%    99.9%     0.1%    0.0%           17% / 20%
0x0021  IN      2511       1.766     1.500     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2525       1.766     1.500     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2529       1.766     1.500     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2546       1.766     1.500     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2549       1.766     1.500     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2550       1.766     1.500     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0041  OUT       12       1.013     1.013     0.0%   100.0%     0.0%    0.0%           41% / 41%
0x007E  IN         -         853         -                                     no script
0x005E  IN        12         623       623     0.0%    95.0%     5.0%    0.0%           14% / 26%
0x005E  IN      2506         623       623   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12         608       608     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0075  IN        12         563       563     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529         563       563   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12         469       469   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507         469       469    43.9%    56.1%     0.0%    0.0%          99% / 100%
0x0020  OUT     2512         469       469   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12         428       428   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         428       428   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         427       427   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12         379       379     0.0%   100.0%     0.0%    0.0%            8% / 17%
0x0052  IN      2516         379       379    34.3%    24.8%    40.9%    0.0%         100% / 100%
0x00B0  IN        12         336       336     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0069  IN        12         297       297     0.0%   100.0%     0.0%    0.0%           10% / 33%
0x0069  IN      2486         297       297    13.1%    86.9%     0.0%    0.0%          33% / 100%
0x0069  IN      2496         297       297    19.9%    80.1%     0.0%    0.0%          33% / 100%
0x0069  IN      2497         297       297    13.1%    86.9%     0.0%    0.0%          20% / 100%
0x0069  IN      2502         297       297    26.3%    73.7%     0.0%    0.0%          33% / 100%
0x0069  IN      2503         297       297     7.4%    92.6%     0.0%    0.0%           20% / 33%
0x0069  IN      2504         297       297     7.4%    92.6%     0.0%    0.0%           20% / 33%
0x0069  IN      2521         297       297    97.6%     0.7%     1.7%    0.0%         100% / 100%
0x0069  IN      2546         297       297     0.0%   100.0%     0.0%    0.0%           10% / 33%
0x0069  IN      2549         297       297    97.6%     0.7%     1.7%    0.0%         100% / 100%
0x0069  IN      2550         297       297    97.6%     0.7%     1.7%    0.0%         100% / 100%
0x004D  IN        12         271       271     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503         271       271   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504         271       271     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507         271       271   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546         271       271   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549         271       271   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550         271       271   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12         243       243     0.0%    84.0%    16.0%    0.0%            0% / 99%
0x00F6  IN      2520         243       243   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12         241       241     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x004E  IN        12         235       235     6.4%     0.0%    93.6%    0.0%           18% / 93%
0x00A8  IN         -         217         -                                     no script
0x0037  OUT       12         168       168    97.0%     3.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502         168       168    11.3%    88.7%     0.0%    0.0%          33% / 100%
0x0055  IN        12         162       162     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         162       162     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         162       162    84.0%     1.2%    14.8%    0.0%         100% / 100%
0x0093  IN         -         162         -                                     no script
0x003C  IN        12         127       127     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         127       127     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         127       127   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         127       127   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         127       127   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12         126       126     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  IN        12         125       125     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12         124       124    28.2%    71.8%     0.0%    0.0%          50% / 100%
0x006A  IN      2486         124       124    74.2%    25.8%     0.0%    0.0%         100% / 100%
0x006A  IN      2500         124       124    25.8%    74.2%     0.0%    0.0%          20% / 100%
0x006A  IN      2502         124       124    48.4%    51.6%     0.0%    0.0%          20% / 100%
0x006A  IN      2503         124       124    48.4%    51.6%     0.0%    0.0%          20% / 100%
0x001D  IN        12         118       118   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12         114       114     0.0%     0.0%   100.0%    0.0%          94% / 100%
0x004F  OUT        -         104         -                                     no script
0x006B  IN        12          94        94     0.0%    67.0%    33.0%    0.0%          46% / 100%
0x006B  IN      2507          94        94    67.0%    33.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          94        94     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          94        94    67.0%    33.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          94        94     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          94        94     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          94        94     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          94        94   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          94        94     0.0%    67.0%    33.0%    0.0%           24% / 80%
0x0128  IN        12          93        93    31.2%    68.8%     0.0%    0.0%          14% / 100%
0x0053  IN        12          91        91     0.0%    96.7%     3.3%    0.0%             0% / 0%
0x006E  IN      2486          91        91    28.6%    71.4%     0.0%    0.0%           3% / 100%
0x0026  OUT       12          86        86   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12          83        83     0.0%    86.7%    13.3%    0.0%           20% / 50%
0x0048  IN        12          81        81     0.0%    97.5%     2.5%    0.0%           48% / 48%
0x0048  IN      2504          81        81    97.5%     2.5%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          81        81    97.5%     2.5%     0.0%    0.0%         100% / 100%
0x008A  IN      2511          80        80     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          80        80    82.5%     2.5%    15.0%    0.0%         100% / 100%
0x0080  OUT        -          78         -                                     no script
0x0045  IN        12          77        77     0.0%    24.7%    75.3%    0.0%           98% / 98%
0x0056  IN        12          76        76     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0019  IN        12          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          64        64    96.9%     0.0%     3.1%    0.0%         100% / 100%
0x001A  IN        12          62        62    50.0%    19.4%    30.6%    0.0%         100% / 100%
0x006D  IN        12          62        62     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          62        62     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          62         -                                     no script
0x0011  OUT        -          47         -                                     no script
0x0044  IN        12          45        45     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004C  IN        12          43        43     0.0%    51.2%    48.8%    0.0%           2% / 100%
0x004C  IN      2512          43        43   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12          42        42   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12          42        42   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F4  IN        12          42        42     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0034  OUT       12          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12          40        40     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          40        40     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          40        40     0.0%   100.0%     0.0%    0.0%           42% / 66%
0x0017  IN      2528          40        40     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          40        40     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x008E  OUT        -          39         -                                     no script
0x00EB  IN        12          39        39     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002F  IN        12          36        36     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0063  IN        12          36        36     0.0%    25.0%    75.0%    0.0%           16% / 27%
0x0063  IN      2507          36        36    41.7%    58.3%     0.0%    0.0%           3% / 100%
0x0063  IN      2518          36        36    41.7%    58.3%     0.0%    0.0%           3% / 100%
0x00A5  IN         -          36         -                                     no script
0x00E6  IN         -          36         -                                     no script
0x0055  OUT        -          35         -                                     no script
0x0033  IN        12          34        34     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12          34        34     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0054  IN        12          34        34     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x006F  IN        12          34        34     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0123  IN         -          34         -                                     no script
0x000F  OUT        -          32         -                                     no script
0x0010  OUT        -          32         -                                     no script
0x0016  IN        12          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0035  IN        12          32        32     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511          32        32     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  IN        12          32        32     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          32        32     0.0%    87.5%    12.5%    0.0%            1% / 56%
0x007D  IN      2486          32        32    62.5%    21.9%    15.6%    0.0%         100% / 100%
0x007D  IN      2502          32        32    15.6%    84.4%     0.0%    0.0%          99% / 100%
0x007D  IN      2503          32        32    15.6%    84.4%     0.0%    0.0%          99% / 100%
0x007D  IN      2546          32        32    15.6%    84.4%     0.0%    0.0%          99% / 100%
0x007D  IN      2549          32        32    15.6%    84.4%     0.0%    0.0%          99% / 100%
0x007D  IN      2550          32        32    15.6%    84.4%     0.0%    0.0%          99% / 100%
0x00B7  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00CA  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           10% / 20%
0x00D1  IN         -          32         -                                     no script
0x00F3  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0001  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          31         -                                     no script
0x0013  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12          31        31     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0015  IN      2507          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          31         -                                     no script
0x00A7  IN        12          31        31     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          31        31     0.0%     6.5%    93.5%    0.0%         100% / 100%
0x00AD  IN         -          31         -                                     no script
0x00B0  OUT        -          31         -                                     no script
0x00B2  IN        12          31        31     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12          31        31     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          31        31     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          31         -                                     no script
0x00B9  IN        12          31        31     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          31        31     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          31         -                                     no script
0x00DF  IN         -          31         -                                     no script
0x00EE  IN         -          31         -                                     no script
0x0110  IN         -          31         -                                     no script
0x0125  IN        12          31        31     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -          31         -                                     no script
0x0131  IN         -          31         -                                     no script
0x0137  IN         -          31         -                                     no script
0x0068  IN        12          27        27     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  IN        12          26        26    19.2%    57.7%    23.1%    0.0%           6% / 100%
0x0039  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x005A  IN        12          22        22     0.0%   100.0%     0.0%    0.0%             4% / 5%
0x005A  IN      2490          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  OUT       12          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12          17        17     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0031  OUT       12          15        15     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x004B  OUT       12          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0079  IN        12          10        10     0.0%     0.0%   100.0%    0.0%           20% / 29%
0x0079  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  OUT        -           9         -                                     no script
0x00A2  OUT     2502           9         9    77.8%    22.2%     0.0%    0.0%         100% / 100%
0x010C  IN      2502           9         9    22.2%    77.8%     0.0%    0.0%           5% / 100%
0x001E  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0082  IN        12           7         7     0.0%    14.3%    85.7%    0.0%            0% / 89%
0x003F  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00A4  OUT       12           6         6     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0018  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  OUT       12           5         5    60.0%    40.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           5         -                                     no script
0x0082  OUT       12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           5         -                                     no script
0x0025  IN        12           4         4     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x0025  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT     2502           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x002B  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529           4         4     0.0%   100.0%     0.0%    0.0%             1% / 3%
0x004F  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 2%
0x004F  IN      2507           4         4    50.0%     0.0%    50.0%    0.0%          16% / 100%
0x0063  OUT        -           4         -                                     no script
0x009F  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x00CF  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0010  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           93% / 93%
0x002B  IN      2530           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN      2531           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           53% / 53%
0x005B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x005F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x006C  OUT        -           3         -                                     no script
0x0095  OUT     2520           3         3     0.0%   100.0%     0.0%    0.0%           69% / 69%
0x00C1  IN         -           3         -                                     no script
0x0018  OUT       12           2         2    50.0%    50.0%     0.0%    0.0%          11% / 100%
0x002F  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0042  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 6%
0x0060  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           52% / 56%
0x0090  IN         -           2         -                                     no script
0x0090  OUT     2504           2         2    50.0%    50.0%     0.0%    0.0%          80% / 100%
0x00A4  IN         -           2         -                                     no script
0x00AA  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           19% / 24%
0x00F0  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x011F  IN         -           2         -                                     no script
0x003A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x004D  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0051  OUT        -           1         -                                     no script
0x00DC  IN         -           1         -                                     no script
0x00EA  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00EA  IN      2504           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EA  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00FB  IN         -           1         -                                     no script
0x00FF  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=188
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! ReadBytes: wanted 42734 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       25    2  Int16    Segment 0/StateSync/Rotation = 0
       27    1  Byte     Segment 0/StateSync/Animation3 = 2
       28    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 900
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 17
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 5376
       34    1  Byte     Segment 0/StateSync/Unknown = 50
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 27
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = 19760

### 0x001C IN src 12  over=1.490 threw=0 negative-length=58
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       18    2  Int16    StateSync/PositionCoordS/Z = 45
       20    2  Int16    StateSync/Rotation = 0
       22    1  Byte     StateSync/Animation3 = 17
       23    2  Int16    StateSync/SpeedCoordS/X = 2250
       25    2  Int16    StateSync/SpeedCoordS/Y = 46
       27    2  Int16    StateSync/SpeedCoordS/Z = -1280
       29    1  Byte     StateSync/Unknown = 248
       30    2  Int16    StateSync/Rotation2 CoordS / 10 = 1

### 0x003D IN src 12  over=1.476 threw=0 negative-length=7
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 5718285099487424004
        8    4  Int32    ServerTick = -2009833472
       12    4  Int32    ObjectId = -1698037759
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0023 IN src 12  over=1.392 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100325/Stats/Unknown = 0
      171    4  Int32    Item: 50100325/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100325/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100325/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100325/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100325/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100325/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100325/ItemEnchant/CanRepackage = False

### 0x0047 IN src 12  over=608 threw=0 negative-length=314
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 63344 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 63344 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 63126 byte(s) at offset 3, only 33 of 36 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 31672

### 0x00B0 IN src 12  over=336 threw=0 negative-length=215
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: wanted 44034 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 8706 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 44034 byte(s) at offset 6, only 14 of 20 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593044736
        4    2  Int16    Motto/size = 22017

### 0x001C IN src 2507  over=268 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 31, only 1 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 16):
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = 0
       21    1  Byte     animation3 = 0
       22    2  Int16    speed x = -13807
       24    2  Int16    speed x = 11784
       26    2  Int16    speed x = 0
       28    1  Byte     unk = 251
       29    2  Int16    unk2 = 504

### 0x004E IN src 12  over=220 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1200 byte(s) at offset 7, only 8 of 15 remain
  ! ReadBytes: wanted 6200 byte(s) at offset 7, only 2012 of 2019 remain
  ! ReadBytes: wanted 10000 byte(s) at offset 3, only 8 of 11 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 600

### 0x0052 IN src 2516  over=155 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2516\Inbound\0x0052.py
  ! Read<Int32>: wanted 4 byte(s) at offset 13, only 0 of 13 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 13, only 0 of 13 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 13, only 0 of 13 remain
  last reads before failure (of 4):
        0    1  Byte     quest mode = 3
        1    4  Int32    quest id = 89000376
        5    4  Int32    condition index = 1
        9    4  Int32    value = 354

### 0x0061 IN src 12  over=126 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  last reads before failure (of 0):

### 0x0035 OUT src 12  over=114 threw=0 negative-length=14
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0035.py
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  last reads before failure (of 18):
       15    2  Int16    StateSync/SpeedCoordS/X = 0
       17    2  Int16    StateSync/SpeedCoordS/Y = 0
       19    2  Int16    StateSync/SpeedCoordS/Z = 4352
       21    1  Byte     StateSync/Unknown = 0
       22    2  Int16    StateSync/Rotation2 CoordS / 10 = 27136
       24    2  Int16    StateSync/CoordS / 1000 = 1
       26    4  Single   StateSync/UnknownCoordF/X = NaN
       30    4  Single   StateSync/UnknownCoordF/Y = 0,11580449

### 0x0056 IN src 12  over=76 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 29292
