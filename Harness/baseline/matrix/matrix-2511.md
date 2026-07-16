# Harness — MATRIX -> 2511

scripts from build : (matrix, see src column)
packets from build : 2511
packets considered : 31.953
packets executed   : 34.135  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                862   2.5%
OkExact              10.958   32.1%
UnderRead            16.042   47.0%
OverRead              6.261   18.3%
Threw                    12   0.0%

of packets a script actually ran on (33.273):
  clean (consumed exactly) : 32.9%
  over-read (WRONG)        : 18.8%
  under-read (ambiguous)   : 48.2%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12      11.591     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      11.591     1.500    95.5%     4.5%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      11.591     1.500    95.5%     4.5%     0.0%    0.0%         100% / 100%
0x0058  IN        12       4.954     1.500     0.0%   100.0%     0.0%    0.0%           12% / 13%
0x0058  IN      2521       4.954     1.500    27.7%    72.3%     0.0%    0.0%          90% / 100%
0x0058  IN      2527       4.954     1.500    30.5%    69.5%     0.0%    0.0%          94% / 100%
0x0012  OUT       12       2.843     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0023  IN        12       2.303     1.500     1.3%     0.0%    98.7%    0.0%         100% / 100%
0x0023  IN      2486       2.303     1.500     0.9%    99.1%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       2.303     1.500     0.9%    99.1%     0.0%    0.0%           11% / 11%
0x0011  IN        12       2.283     1.500    50.1%    49.9%     0.0%    0.0%         100% / 100%
0x001C  IN        12       1.387     1.387     0.4%     0.0%    99.6%    0.0%         100% / 100%
0x001C  IN      2507       1.387     1.387    68.8%     9.0%    22.2%    0.0%         100% / 100%
0x000B  OUT       12       1.137     1.137   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12         906       906     4.5%    89.7%     5.7%    0.0%            0% / 20%
0x0021  IN      2511         906       906     2.0%    96.0%     1.8%    0.2%            0% / 20%
0x0021  IN      2525         906       906     3.8%    96.0%     0.0%    0.2%            0% / 20%
0x0021  IN      2529         906       906     3.8%    96.0%     0.0%    0.2%            0% / 20%
0x0021  IN      2546         906       906     3.8%    96.0%     0.0%    0.2%            0% / 20%
0x0021  IN      2549         906       906     3.8%    96.0%     0.0%    0.2%            0% / 20%
0x0021  IN      2550         906       906     3.8%    96.0%     0.0%    0.2%            0% / 20%
0x0047  IN        12         566       566     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x00B0  IN        12         398       398     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x002E  IN        12         246       246     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521         246       246    25.6%    74.4%     0.0%    0.0%          19% / 100%
0x002E  IN      2528         246       246   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -         226         -                                     no script
0x0006  IN        12         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12         190       190     0.0%    94.2%     5.8%    0.0%            0% / 26%
0x005E  IN      2506         190       190   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12         182       182     0.0%     0.0%   100.0%    0.0%           96% / 96%
0x003D  IN      2512         182       182   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         182       182     6.6%    93.4%     0.0%    0.0%             4% / 4%
0x0052  IN        12          99        99     0.0%   100.0%     0.0%    0.0%            0% / 17%
0x0052  IN      2516          99        99    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x001D  IN        12          98        98   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12          96        96     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x008A  IN      2511          81        81     0.0%   100.0%     0.0%    0.0%             0% / 6%
0x008A  IN      2524          81        81    79.0%     7.4%    13.6%    0.0%         100% / 100%
0x0093  IN         -          81         -                                     no script
0x00A8  IN         -          77         -                                     no script
0x004F  OUT        -          57         -                                     no script
0x00F6  IN        12          54        54     0.0%    87.0%    13.0%    0.0%           0% / 100%
0x00F6  IN      2520          54        54   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  OUT        -          51         -                                     no script
0x0061  IN        12          44        44     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006C  IN        12          44        44     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0114  IN        12          40        40     0.0%    87.5%    12.5%    0.0%           20% / 50%
0x00CC  IN        12          39        39     0.0%    76.9%    23.1%    0.0%            7% / 50%
0x006A  IN        12          38        38    44.7%    55.3%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          38        38    71.1%    28.9%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          38        38    23.7%    76.3%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          38        38    36.8%    63.2%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          38        38    36.8%    63.2%     0.0%    0.0%          20% / 100%
0x0123  IN         -          37         -                                     no script
0x006B  IN        12          36        36     0.0%    69.4%    30.6%    0.0%          46% / 100%
0x006B  IN      2507          36        36    61.1%    38.9%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          36        36     2.8%    97.2%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          36        36    61.1%    38.9%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          36        36     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          36        36     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          36        36     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          36        36   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12          35        35     0.0%   100.0%     0.0%    0.0%           21% / 23%
0x004D  IN      2503          35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          35        35     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507          35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          35        35     0.0%    65.7%    34.3%    0.0%           24% / 80%
0x0045  IN        12          33        33     0.0%     6.1%    93.9%    0.0%           98% / 98%
0x0069  IN        12          33        33     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          33        33    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496          33        33    33.3%    66.7%     0.0%    0.0%          51% / 100%
0x0069  IN      2497          33        33    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502          33        33    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503          33        33     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          33        33     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546          33        33     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550          33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          30        30     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          30        30     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          30        30    93.3%     6.7%     0.0%    0.0%         100% / 100%
0x00A8  OUT       12          30        30     0.0%    83.3%    16.7%    0.0%           10% / 50%
0x00CB  IN        12          30        30     0.0%   100.0%     0.0%    0.0%            5% / 15%
0x0128  IN        12          29        29    20.7%    72.4%     6.9%    0.0%          14% / 100%
0x0054  IN        12          28        28    14.3%    21.4%    64.3%    0.0%          90% / 100%
0x0019  IN        12          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011B  IN        12          27        27     0.0%    77.8%    22.2%    0.0%           11% / 20%
0x00F4  IN        12          24        24     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x0048  IN        12          23        23     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          22        22    50.0%    40.9%     9.1%    0.0%         100% / 100%
0x006D  IN        12          22        22     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          22        22     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          22         -                                     no script
0x0016  OUT        -          20         -                                     no script
0x0044  IN        12          20        20     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0005  IN        12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN        12          18        18     0.0%     0.0%   100.0%    0.0%             7% / 8%
0x0026  IN        12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  IN        12          17        17    76.5%     0.0%    23.5%    0.0%         100% / 100%
0x0017  IN        12          16        16     0.0%     6.2%    93.8%    0.0%         100% / 100%
0x0017  IN      2500          16        16     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          16        16     0.0%    87.5%    12.5%    0.0%          16% / 100%
0x0017  IN      2528          16        16     0.0%     0.0%   100.0%    0.0%          28% / 100%
0x0017  IN      2550          16        16     0.0%     6.2%    93.8%    0.0%         100% / 100%
0x00AD  OUT        -          16         -                                     no script
0x00E6  IN         -          16         -                                     no script
0x0033  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x00B4  OUT        -          14         -                                     no script
0x0038  OUT     2511          13        13     7.7%    92.3%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          13        13    92.3%     0.0%     7.7%    0.0%         100% / 100%
0x0055  OUT        -          13         -                                     no script
0x006F  IN        12          13        13     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0097  OUT        -          13         -                                     no script
0x00A5  IN         -          13         -                                     no script
0x0020  OUT       12          12        12    91.7%     8.3%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507          12        12    83.3%    16.7%     0.0%    0.0%         100% / 100%
0x0020  OUT     2512          12        12    91.7%     8.3%     0.0%    0.0%         100% / 100%
0x00D1  IN         -          12         -                                     no script
0x00EB  IN        12          12        12     0.0%    16.7%    83.3%    0.0%         100% / 100%
0x0001  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          11         -                                     no script
0x000F  OUT        -          11         -                                     no script
0x0010  OUT        -          11         -                                     no script
0x0013  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0034  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0039  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  IN        12          11        11     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          11        11     0.0%    45.5%    54.5%    0.0%           56% / 56%
0x007D  IN      2486          11        11     0.0%    45.5%    54.5%    0.0%         100% / 100%
0x007D  IN      2502          11        11    54.5%    45.5%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          11        11    54.5%    45.5%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          11        11    54.5%    45.5%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          11        11    54.5%    45.5%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          11        11    54.5%    45.5%     0.0%    0.0%         100% / 100%
0x0089  IN      2527          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -          11         -                                     no script
0x009E  IN         -          11         -                                     no script
0x00A7  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          11        11     0.0%    18.2%    81.8%    0.0%         100% / 100%
0x00AD  IN         -          11         -                                     no script
0x00B0  OUT        -          11         -                                     no script
0x00B2  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          11        11     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          11         -                                     no script
0x00B7  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          11        11     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          11         -                                     no script
0x00CA  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00DF  IN         -          11         -                                     no script
0x00EE  IN         -          11         -                                     no script
0x00F3  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -          11         -                                     no script
0x0125  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -          11         -                                     no script
0x0131  IN         -          11         -                                     no script
0x0138  IN         -          11         -                                     no script
0x0018  OUT       12          10        10    90.0%    10.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12          10        10     0.0%    40.0%    60.0%    0.0%         100% / 100%
0x005A  IN        12          10        10     0.0%   100.0%     0.0%    0.0%             4% / 5%
0x005A  IN      2490          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x001E  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002D  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0103  IN         -           7         -                                     no script
0x003A  OUT        -           6         -                                     no script
0x0013  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x004C  IN      2512           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0042  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0017  OUT        -           2         -                                     no script
0x0018  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           2         2     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           2         -                                     no script
0x007B  OUT        -           2         -                                     no script
0x0082  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00A2  OUT     2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  IN         -           2         -                                     no script
0x00C1  IN         -           2         -                                     no script
0x00D6  IN         -           2         -                                     no script
0x010C  IN      2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011F  IN         -           2         -                                     no script
0x001C  OUT        -           1         -                                     no script
0x002B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002B  IN      2531           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004D  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x005B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0063  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           35% / 35%
0x0063  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0063  IN      2518           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00DC  IN         -           1         -                                     no script
0x0109  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           97% / 97%

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=284
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -8448
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 4,8712594E+26

### 0x0023 IN src 12  over=1.480 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50200151/Stats/Unknown = 0
      171    4  Int32    Item: 50200151/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50200151/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50200151/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50200151/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50200151/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50200151/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50200151/ItemEnchant/CanRepackage = False

### 0x001C IN src 12  over=1.381 threw=0 negative-length=116
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 4607
       23    1  Byte     StateSync/Unknown = 0
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 13056
       26    2  Int16    StateSync/CoordS / 1000 = 1
       28    4  Single   StateSync/UnknownCoordF/X = 8,9673E-41

### 0x0047 IN src 12  over=566 threw=0 negative-length=177
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -43308 at offset 3/40
  ! ReadBytes: negative length -43308 at offset 3/40
  ! ReadBytes: negative length -43308 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -21654

### 0x00B0 IN src 12  over=398 threw=0 negative-length=276
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: wanted 8706 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 44034 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 8706 byte(s) at offset 6, only 14 of 20 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593046528
        4    2  Int16    Motto/size = 4353

### 0x001C IN src 2507  over=308 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 151
       13    2  Int16    coord x = 0
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -434315883913936879
       30    2  Int16    speed x = 0

### 0x003D IN src 12  over=182 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 2046588063465271556
        8    4  Int32    ServerTick = -1890281216
       12    4  Int32    ObjectId = -1698037760
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0021 IN src 12  over=52 threw=0 negative-length=4
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0021.py
  ! Read<Single>: wanted 4 byte(s) at offset 550, only 0 of 550 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 15, only 0 of 15 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 195, only 3 of 198 remain
  last reads before failure (of 165):
      524    2  Int16    Item/Item: 11400607/Stats/Empowerment Stats 2/StatType = 0
      526    4  Int32    Item/Item: 11400607/Stats/Empowerment Stats 2/StatOption 36/IntegerValue = 65536
      530    4  Single   Item/Item: 11400607/Stats/Empowerment Stats 2/StatOption 36/FloatValue = 3E-45
      534    2  Int16    Item/Item: 11400607/Stats/Empowerment Stats 2/StatType = 0
      536    4  Int32    Item/Item: 11400607/Stats/Empowerment Stats 2/StatOption 37/IntegerValue = 0
      540    4  Single   Item/Item: 11400607/Stats/Empowerment Stats 2/StatOption 37/FloatValue = 0
      544    2  Int16    Item/Item: 11400607/Stats/Empowerment Stats 2/StatType = 0
      546    4  Int32    Item/Item: 11400607/Stats/Empowerment Stats 2/StatOption 38/IntegerValue = 0

### 0x0061 IN src 12  over=44 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 827, only 1 of 828 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=31 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 0
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 0
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0

### 0x0025 IN src 12  over=18 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0025.py
  ! ReadBytes: wanted 3080 byte(s) at offset 18, only 293 of 311 remain
  ! ReadBytes: wanted 3082 byte(s) at offset 18, only 293 of 311 remain
  ! ReadBytes: wanted 2060 byte(s) at offset 18, only 329 of 347 remain
  last reads before failure (of 4):
        0    4  Int32    UserObjectId = 28782099
        4    4  Int32    ItemId = 13100313
        8    8  Int64    ItemUid = 2607054233069640132
       16    2  Int16    EquipSlot/size = 1540

### 0x0054 IN src 12  over=18 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 17, only 0 of 17 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 2203318222850
