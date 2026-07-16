# Harness — MATRIX -> 2503

scripts from build : (matrix, see src column)
packets from build : 2503
packets considered : 67.267
packets executed   : 62.576  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              1.606   2.6%
OkExact              23.504   37.6%
UnderRead            30.626   48.9%
OverRead              6.840   10.9%

of packets a script actually ran on (60.970):
  clean (consumed exactly) : 38.6%
  over-read (WRONG)        : 11.2%
  under-read (ambiguous)   : 50.2%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12      16.216     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      16.216     1.500    96.1%     3.9%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      16.216     1.500    96.1%     3.9%     0.0%    0.0%         100% / 100%
0x001C  IN        12      15.507     1.500     1.1%     0.7%    98.2%    0.0%         100% / 100%
0x001C  IN      2507      15.507     1.500    80.5%    14.5%     5.1%    0.0%         100% / 100%
0x0012  OUT       12      10.857     1.500     0.0%     0.1%    99.9%    0.0%          95% / 100%
0x0058  IN        12       4.604     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521       4.604     1.500    49.3%    50.7%     0.0%    0.0%          97% / 100%
0x0058  IN      2527       4.604     1.500    66.1%    33.9%     0.0%    0.0%         100% / 100%
0x0011  IN        12       3.627     1.500    50.9%    49.1%     0.0%    0.0%         100% / 100%
0x0023  IN        12       2.281     1.500    52.6%     0.0%    47.4%    0.0%         100% / 100%
0x0023  IN      2486       2.281     1.500     2.1%    97.9%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       2.281     1.500    48.2%    51.8%     0.0%    0.0%          11% / 100%
0x000B  OUT       12       1.805     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN        12       1.337     1.337     0.1%    99.9%     0.0%    0.0%             4% / 7%
0x0069  IN      2486       1.337     1.337     1.8%    98.2%     0.0%    0.0%             7% / 7%
0x0069  IN      2496       1.337     1.337     3.0%    97.0%     0.0%    0.0%             7% / 7%
0x0069  IN      2497       1.337     1.337     1.8%    98.2%     0.0%    0.0%             7% / 7%
0x0069  IN      2502       1.337     1.337    19.1%    80.9%     0.0%    0.0%           7% / 100%
0x0069  IN      2503       1.337     1.337    29.9%    70.1%     0.0%    0.0%           7% / 100%
0x0069  IN      2504       1.337     1.337    29.9%    70.1%     0.0%    0.0%           7% / 100%
0x0069  IN      2521       1.337     1.337    99.9%     0.1%     0.1%    0.0%         100% / 100%
0x0069  IN      2546       1.337     1.337     0.1%    99.9%     0.0%    0.0%             4% / 7%
0x0069  IN      2549       1.337     1.337    99.9%     0.1%     0.1%    0.0%         100% / 100%
0x0069  IN      2550       1.337     1.337    99.9%     0.1%     0.1%    0.0%         100% / 100%
0x002E  IN        12       1.228     1.228     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521       1.228     1.228    13.8%    83.1%     3.2%    0.0%          19% / 100%
0x002E  IN      2528       1.228     1.228    96.7%     3.2%     0.2%    0.0%         100% / 100%
0x0021  IN        12       1.188     1.188     0.1%    99.8%     0.1%    0.0%           17% / 20%
0x0021  IN      2511       1.188     1.188     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2525       1.188     1.188     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2529       1.188     1.188     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2546       1.188     1.188     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2549       1.188     1.188     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x0021  IN      2550       1.188     1.188     0.1%    99.9%     0.0%    0.0%           17% / 20%
0x003D  IN        12         784       784     0.0%     4.3%    95.7%    0.0%           96% / 96%
0x003D  IN      2512         784       784    94.3%     5.7%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         784       784    14.3%    81.6%     4.1%    0.0%           4% / 100%
0x0047  IN        12         721       721     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x007E  IN         -         482         -                                     no script
0x0006  IN        12         450       450   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         450       450   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         450       450   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         434       434     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x005E  IN        12         375       375     0.0%    94.1%     5.9%    0.0%           11% / 26%
0x005E  IN      2506         375       375   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12         244       244     0.0%    85.2%    14.8%    0.0%            0% / 99%
0x00F6  IN      2520         244       244   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12         234       234    88.0%     8.5%     3.4%    0.0%         100% / 100%
0x0020  OUT     2507         234       234    38.0%    62.0%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         234       234    88.0%     8.5%     3.4%    0.0%         100% / 100%
0x0037  IN        12         213       213     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0080  OUT        -         170         -                                     no script
0x0052  IN        12         162       162     0.0%    99.4%     0.6%    0.0%            1% / 20%
0x0052  IN      2516         162       162    58.6%    41.4%     0.0%    0.0%         100% / 100%
0x00A8  IN         -         154         -                                     no script
0x0093  IN         -         147         -                                     no script
0x0035  OUT       12         142       142     0.0%     0.0%   100.0%    0.0%          94% / 100%
0x004D  IN        12         142       142     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503         142       142   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504         142       142     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507         142       142   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546         142       142   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549         142       142   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550         142       142   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT       12         111       111    95.5%     4.5%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502         111       111     7.2%    92.8%     0.0%    0.0%           20% / 73%
0x0061  IN        12         106       106     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x001D  IN        12         104       104   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12          90        90     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506          90        90     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507          90        90   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512          90        90   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520          90        90   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12          88        88     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12          86        86    27.9%    72.1%     0.0%    0.0%          50% / 100%
0x006A  IN      2486          86        86    74.4%    25.6%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          86        86    25.6%    74.4%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          86        86    48.8%    51.2%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          86        86    48.8%    51.2%     0.0%    0.0%          20% / 100%
0x004F  IN        12          85        85     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x004F  IN      2507          85        85     2.4%     0.0%    97.6%    0.0%           16% / 16%
0x004E  IN        12          84        84    21.4%     2.4%    76.2%    0.0%          27% / 100%
0x004C  IN        12          82        82     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          82         -                                     no script
0x00B6  IN        12          67        67     0.0%    65.7%    34.3%    0.0%           24% / 80%
0x006B  IN        12          66        66     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507          66        66    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          66        66     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          66        66    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          66        66     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          66        66     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          66        66     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0128  IN        12          64        64    31.2%    68.8%     0.0%    0.0%          14% / 100%
0x00CC  IN        12          62        62     0.0%    82.3%    17.7%    0.0%           20% / 50%
0x0045  IN        12          54        54     0.0%    22.2%    77.8%    0.0%           98% / 98%
0x008A  IN      2511          48        48     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          48        48    81.2%     6.2%    12.5%    0.0%         100% / 100%
0x002F  IN        12          47        47     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x011C  IN         -          45         -                                     no script
0x0019  IN        12          44        44   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          44        44   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          44        44    50.0%    18.2%    31.8%    0.0%         100% / 100%
0x006D  IN        12          44        44     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          44        44     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x006E  IN      2486          40        40    37.5%    62.5%     0.0%    0.0%           3% / 100%
0x0005  IN        12          36        36   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12          36        36     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          36        36     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          36        36     0.0%   100.0%     0.0%    0.0%           16% / 66%
0x0017  IN      2528          36        36     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          36        36     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F4  IN        12          36        36     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0011  OUT        -          35         -                                     no script
0x0044  IN        12          32        32     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0048  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          32        32     0.0%    96.9%     3.1%    0.0%             1% / 6%
0x0055  IN      2521          32        32     0.0%   100.0%     0.0%    0.0%           64% / 99%
0x0055  IN      2528          32        32    12.5%     0.0%    87.5%    0.0%          98% / 100%
0x0033  IN        12          30        30     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12          30        30     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x00CB  IN        12          28        28     0.0%   100.0%     0.0%    0.0%             2% / 4%
0x00E6  IN         -          28         -                                     no script
0x00EB  IN        12          28        28     0.0%     3.6%    96.4%    0.0%         100% / 100%
0x008E  OUT        -          27         -                                     no script
0x0071  IN        12          26        26     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0014  IN        12          25        25   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -          25         -                                     no script
0x00A5  IN         -          25         -                                     no script
0x00C3  IN        12          25        25     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0001  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          22         -                                     no script
0x000F  OUT        -          22         -                                     no script
0x0010  OUT        -          22         -                                     no script
0x0013  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12          22        22     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0015  IN      2507          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0035  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511          22        22     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12          22        22     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x006F  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12          22        22     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          22        22     0.0%    81.8%    18.2%    0.0%            1% / 56%
0x007D  IN      2486          22        22    54.5%    36.4%     9.1%    0.0%         100% / 100%
0x007D  IN      2502          22        22     9.1%    90.9%     0.0%    0.0%           99% / 99%
0x007D  IN      2503          22        22     9.1%    90.9%     0.0%    0.0%          99% / 100%
0x007D  IN      2546          22        22     9.1%    90.9%     0.0%    0.0%          99% / 100%
0x007D  IN      2549          22        22     9.1%    90.9%     0.0%    0.0%          99% / 100%
0x007D  IN      2550          22        22     9.1%    90.9%     0.0%    0.0%          99% / 100%
0x0089  IN      2527          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          22         -                                     no script
0x00A7  IN        12          22        22     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -          22         -                                     no script
0x00B0  OUT        -          22         -                                     no script
0x00B2  IN        12          22        22     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12          22        22     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          22        22     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          22         -                                     no script
0x00B7  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          22        22     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          22         -                                     no script
0x00CA  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00D1  IN         -          22         -                                     no script
0x00DF  IN         -          22         -                                     no script
0x00EE  IN         -          22         -                                     no script
0x00F3  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -          22         -                                     no script
0x011B  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -          22         -                                     no script
0x0131  IN         -          22         -                                     no script
0x0137  IN         -          22         -                                     no script
0x0138  IN         -          22         -                                     no script
0x0034  OUT       12          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0068  IN        12          15        15     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  OUT       12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x005A  IN      2490          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0123  IN         -          12         -                                     no script
0x003F  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0039  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x00C1  IN         -           8         -                                     no script
0x0079  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  OUT       12           7         7     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0010  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0027  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  OUT        -           5         -                                     no script
0x0018  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           41% / 45%
0x008B  IN        12           4         4     0.0%     0.0%   100.0%    0.0%          97% / 100%
0x0025  IN        12           3         3     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x0026  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x005F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0066  OUT        -           3         -                                     no script
0x0082  OUT       12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00CF  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           3         -                                     no script
0x0109  IN        12           3         3     0.0%    33.3%    66.7%    0.0%           97% / 97%
0x0063  OUT        -           2         -                                     no script
0x009F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x0029  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x0051  OUT        -           1         -                                     no script
0x0090  OUT     2504           1         1     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x00F8  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%

## Sample failures

### 0x0012 OUT src 12  over=1.499 threw=0 negative-length=208
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int32>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       25    2  Int16    Segment 0/StateSync/Rotation = 0
       27    1  Byte     Segment 0/StateSync/Animation3 = 2
       28    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 2700
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 16
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -256
       34    1  Byte     Segment 0/StateSync/Unknown = 255
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 32767
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = 11995

### 0x001C IN src 12  over=1.473 threw=0 negative-length=107
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       18    2  Int16    StateSync/PositionCoordS/Z = 45
       20    2  Int16    StateSync/Rotation = -39
       22    1  Byte     StateSync/Animation3 = 17
       23    2  Int16    StateSync/SpeedCoordS/X = 440
       25    2  Int16    StateSync/SpeedCoordS/Y = 305
       27    2  Int16    StateSync/SpeedCoordS/Z = -2304
       29    1  Byte     StateSync/Unknown = 248
       30    2  Int16    StateSync/Rotation2 CoordS / 10 = 0

### 0x003D IN src 12  over=750 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 453337440330617860
        8    4  Int32    ServerTick = 506497024
       12    4  Int32    ObjectId = -1698037760
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0047 IN src 12  over=721 threw=0 negative-length=136
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 51008 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 51008 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 51008 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 25504

### 0x0023 IN src 12  over=711 threw=0
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

### 0x00B0 IN src 12  over=434 threw=0 negative-length=312
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -22526 at offset 6/20
  ! ReadBytes: wanted 24578 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: negative length -12798 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593036032
        4    2  Int16    Motto/size = -11263

### 0x0035 OUT src 12  over=142 threw=0 negative-length=20
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0035.py
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  last reads before failure (of 18):
       15    2  Int16    StateSync/SpeedCoordS/X = 0
       17    2  Int16    StateSync/SpeedCoordS/Y = 0
       19    2  Int16    StateSync/SpeedCoordS/Z = 4352
       21    1  Byte     StateSync/Unknown = 0
       22    2  Int16    StateSync/Rotation2 CoordS / 10 = 17408
       24    2  Int16    StateSync/CoordS / 1000 = 0
       26    4  Single   StateSync/UnknownCoordF/X = NaN
       30    4  Single   StateSync/UnknownCoordF/Y = 7,6987774E-20

### 0x0061 IN src 12  over=106 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 551, only 0 of 551 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x004F IN src 2507  over=83 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x004F.py
  ! ReadBytes: wanted 26210 byte(s) at offset 7, only 38 of 45 remain
  ! ReadBytes: wanted 12848 byte(s) at offset 7, only 38 of 45 remain
  ! ReadBytes: wanted 26210 byte(s) at offset 7, only 38 of 45 remain
  last reads before failure (of 3):
        0    1  Byte     byte = 1
        1    4  Int32    count = 1647902752
        5    2  Int16    entity id/size = 26210

### 0x001C IN src 2507  over=76 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 151
       13    2  Int16    coord x = 440
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -506936427938727919
       30    2  Int16    speed x = 0

### 0x004E IN src 12  over=64 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 6802 byte(s) at offset 7, only 306 of 313 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1, only 5 of 6 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 13, only 1 of 14 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 23
        5    2  Int16    FunctionCubeName/size = 3401

### 0x002F IN src 12  over=47 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 8983284
        4    1  Byte     Function = 1
