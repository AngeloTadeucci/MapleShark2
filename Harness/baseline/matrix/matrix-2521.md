# Harness — MATRIX -> 2521

scripts from build : (matrix, see src column)
packets from build : 2521
packets considered : 65.905
packets executed   : 42.320  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              2.207   5.2%
OkExact              16.799   39.7%
UnderRead            16.163   38.2%
OverRead              7.139   16.9%
Threw                    12   0.0%

of packets a script actually ran on (40.113):
  clean (consumed exactly) : 41.9%
  over-read (WRONG)        : 17.8%
  under-read (ambiguous)   : 40.3%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      22.939     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      22.939     1.500    53.9%    46.1%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      22.939     1.500    98.8%     1.2%     0.0%    0.0%         100% / 100%
0x0012  OUT       12      18.588     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0024  IN        12       5.145     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       5.145     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       5.145     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN        12       4.506     1.500     1.3%     0.0%    98.7%    0.0%         100% / 100%
0x001C  IN      2507       4.506     1.500    87.9%     0.8%    11.3%    0.0%         100% / 100%
0x0023  IN        12       2.155     1.500     1.7%     0.0%    98.3%    0.0%         100% / 100%
0x0023  IN      2486       2.155     1.500     1.0%    99.0%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       2.155     1.500     1.0%    99.0%     0.0%    0.0%           11% / 11%
0x0011  IN        12       1.774     1.500    51.5%    48.5%     0.0%    0.0%         100% / 100%
0x007E  IN         -       1.595         -                                     no script
0x002E  IN        12       1.028     1.028     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521       1.028     1.028    12.0%    83.7%     4.4%    0.0%          32% / 100%
0x002E  IN      2528       1.028     1.028    95.9%     2.9%     1.2%    0.0%         100% / 100%
0x000B  OUT       12         883       883   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12         687       687     0.0%     3.2%    96.8%    0.0%           84% / 90%
0x003D  IN      2512         687       687    96.8%     3.2%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         687       687    86.8%    13.2%     0.0%    0.0%         100% / 100%
0x0021  IN        12         617       617     0.5%    97.4%     2.1%    0.0%           17% / 20%
0x0021  IN      2511         617       617     0.3%    98.7%     0.6%    0.3%           17% / 20%
0x0021  IN      2525         617       617     1.0%    98.7%     0.0%    0.3%           17% / 20%
0x0021  IN      2529         617       617     1.0%    98.7%     0.0%    0.3%           17% / 20%
0x0021  IN      2546         617       617     1.0%    98.7%     0.0%    0.3%           17% / 20%
0x0021  IN      2549         617       617     1.0%    98.7%     0.0%    0.3%           17% / 20%
0x0021  IN      2550         617       617     1.0%    98.7%     0.0%    0.3%           17% / 20%
0x005E  IN        12         604       604     0.0%    98.0%     2.0%    0.0%           35% / 35%
0x005E  IN      2506         604       604   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12         437       437     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0055  IN        12         313       313     0.0%    98.7%     1.3%    0.0%             1% / 1%
0x0055  IN      2521         313       313     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         313       313    99.4%     0.3%     0.3%    0.0%         100% / 100%
0x0020  OUT       12         277       277    98.6%     0.4%     1.1%    0.0%         100% / 100%
0x0020  OUT     2507         277       277    29.2%    70.8%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         277       277    98.6%     0.4%     1.1%    0.0%         100% / 100%
0x0056  IN        12         220       220     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0006  IN        12         169       169   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         169       169   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         169       169   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12         161       161     0.0%    98.1%     1.9%    0.0%             2% / 2%
0x0075  IN      2529         161       161   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         152       152     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x004E  IN        12         135       135     3.0%     0.0%    97.0%    0.0%           27% / 93%
0x002B  IN        12         120       120     0.0%     0.0%   100.0%    0.0%           93% / 93%
0x002B  IN      2530         120       120    95.0%     0.0%     5.0%    0.0%         100% / 100%
0x002B  IN      2531         120       120    95.0%     0.0%     5.0%    0.0%         100% / 100%
0x002C  IN        12         115       115   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12         115       115     0.0%   100.0%     0.0%    0.0%           16% / 56%
0x0066  IN        12         109       109     4.6%    77.1%    18.3%    0.0%            5% / 44%
0x0052  IN        12         107       107     0.0%    96.3%     3.7%    0.0%            8% / 41%
0x0052  IN      2516         107       107    45.8%    50.5%     3.7%    0.0%          20% / 100%
0x003C  IN        12         103       103     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         103       103     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         103       103   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         103       103   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         103       103   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  OUT       12          87        87   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          84         -                                     no script
0x004D  IN        12          82        82     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          82        82     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -          78         -                                     no script
0x002D  IN        12          77        77     7.8%    92.2%     0.0%    0.0%           53% / 53%
0x0093  IN         -          73         -                                     no script
0x0048  IN        12          57        57     0.0%    98.2%     1.8%    0.0%           48% / 48%
0x0048  IN      2504          57        57    98.2%     1.8%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          57        57    98.2%     1.8%     0.0%    0.0%         100% / 100%
0x0039  IN        12          55        55     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x006C  IN        12          54        54     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x001D  OUT       12          53        53   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12          50        50    36.0%    64.0%     0.0%    0.0%          50% / 100%
0x006A  IN      2486          50        50    72.0%    28.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          50        50    22.0%    78.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          50        50    38.0%    62.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          50        50    38.0%    62.0%     0.0%    0.0%          20% / 100%
0x0069  IN        12          45        45     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          45        45     0.0%    68.9%    31.1%    0.0%           20% / 53%
0x0069  IN      2496          45        45     0.0%    68.9%    31.1%    0.0%           34% / 70%
0x0069  IN      2497          45        45     0.0%    68.9%    31.1%    0.0%           20% / 53%
0x0069  IN      2502          45        45     0.0%    68.9%    31.1%    0.0%           20% / 53%
0x0069  IN      2503          45        45     2.2%    97.8%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          45        45     2.2%    97.8%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          45        45    68.9%     0.0%    31.1%    0.0%         100% / 100%
0x0069  IN      2546          45        45     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          45        45    68.9%     0.0%    31.1%    0.0%         100% / 100%
0x0069  IN      2550          45        45    68.9%     0.0%    31.1%    0.0%         100% / 100%
0x0061  IN        12          43        43     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006B  IN        12          43        43     0.0%    69.8%    30.2%    0.0%          46% / 100%
0x006B  IN      2507          43        43    65.1%    34.9%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          43        43     2.3%    97.7%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          43        43    65.1%    34.9%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          43        43     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          43        43     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          43        43     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          43        43   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12          39        39     0.0%     0.0%   100.0%    0.0%           16% / 52%
0x0063  IN      2507          39        39    64.1%    35.9%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          39        39    64.1%    35.9%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          38         -                                     no script
0x0128  IN        12          38        38    26.3%    73.7%     0.0%    0.0%          14% / 100%
0x00B6  IN        12          37        37     0.0%    67.6%    32.4%    0.0%           24% / 80%
0x00F6  IN        12          37        37     0.0%    94.6%     5.4%    0.0%             0% / 7%
0x00F6  IN      2520          37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12          36        36     0.0%    13.9%    86.1%    0.0%           98% / 98%
0x008A  IN      2511          34        34     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524          34        34    67.6%     2.9%    29.4%    0.0%         100% / 100%
0x0014  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12          31        31     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0053  IN        12          30        30     0.0%   100.0%     0.0%    0.0%             0% / 2%
0x007A  IN        12          30        30     0.0%     0.0%   100.0%    0.0%           78% / 78%
0x011C  IN         -          30         -                                     no script
0x00CC  IN        12          28        28     0.0%    92.9%     7.1%    0.0%           20% / 50%
0x001D  IN        12          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12          26        26     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          26        26     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          26        26     0.0%    65.4%    34.6%    0.0%          61% / 100%
0x0017  IN      2528          26        26     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          26        26     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0138  IN         -          26         -                                     no script
0x002F  IN        12          25        25     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  OUT       12          25        25   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12          25        25     0.0%   100.0%     0.0%    0.0%           14% / 14%
0x0019  IN        12          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          24        24    50.0%    12.5%    37.5%    0.0%         100% / 100%
0x010A  IN        12          24        24     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x012D  IN         -          24         -                                     no script
0x0005  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  IN        12          22        22     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0073  IN        12          20        20     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AD  IN         -          20         -                                     no script
0x004F  IN        12          19        19     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x004F  IN      2507          19        19    26.3%     0.0%    73.7%    0.0%          16% / 100%
0x00EB  IN        12          19        19     5.3%     0.0%    94.7%    0.0%         100% / 100%
0x0022  OUT       12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12          18        18     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0039  OUT       12          18        18    94.4%     5.6%     0.0%    0.0%         100% / 100%
0x0041  IN        12          18        18     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x004B  IN        12          18        18     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          18        18    22.2%    77.8%     0.0%    0.0%           6% / 100%
0x008E  OUT        -          18         -                                     no script
0x00CB  IN        12          18        18     0.0%   100.0%     0.0%    0.0%             4% / 5%
0x00F1  IN         -          18         -                                     no script
0x00F4  IN        12          17        17     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0038  OUT     2511          16        16     6.2%    93.8%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          16        16    93.8%     0.0%     6.2%    0.0%         100% / 100%
0x00E6  IN         -          16         -                                     no script
0x0001  IN        12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -          15         -                                     no script
0x006F  IN        12          15        15     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00A5  IN         -          15         -                                     no script
0x0123  IN         -          15         -                                     no script
0x000F  OUT        -          14         -                                     no script
0x0010  OUT        -          14         -                                     no script
0x0016  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0035  IN        12          14        14     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x007D  IN        12          14        14     0.0%    57.1%    42.9%    0.0%           11% / 56%
0x007D  IN      2486          14        14     0.0%    42.9%    57.1%    0.0%         100% / 100%
0x007D  IN      2502          14        14    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          14        14    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          14        14    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          14        14    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          14        14    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x00CA  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -          14         -                                     no script
0x00F3  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x000C  OUT       12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12          13        13     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x00B3  IN        12          13        13     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          13        13     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          13         -                                     no script
0x0125  IN        12          13        13     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0004  IN        12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          12         -                                     no script
0x0011  OUT        -          12         -                                     no script
0x0015  IN        12          12        12     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          12         -                                     no script
0x00A7  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          12        12     0.0%    41.7%    58.3%    0.0%         100% / 100%
0x00B0  OUT        -          12         -                                     no script
0x00B2  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B7  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          12        12     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          12        12     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          12         -                                     no script
0x00DF  IN         -          12         -                                     no script
0x00EE  IN         -          12         -                                     no script
0x0110  IN         -          12         -                                     no script
0x0126  IN         -          12         -                                     no script
0x0131  IN         -          12         -                                     no script
0x0137  IN         -          12         -                                     no script
0x0139  IN         -          12         -                                     no script
0x005F  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x000C  IN        12           8         8    25.0%     0.0%    75.0%    0.0%         100% / 100%
0x000C  IN      2507           8         8    37.5%     0.0%    62.5%    0.0%         100% / 100%
0x000C  IN      2525           8         8    37.5%     0.0%    62.5%    0.0%         100% / 100%
0x0018  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003E  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x005A  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12           7         7     0.0%    57.1%    42.9%    0.0%           2% / 100%
0x004C  IN      2512           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0029  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0070  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           25% / 25%
0x001C  OUT        -           5         -                                     no script
0x0026  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x0049  IN      2529           5         5     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x004B  OUT       12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006A  OUT        -           5         -                                     no script
0x009D  IN         -           5         -                                     no script
0x00A4  IN         -           5         -                                     no script
0x00F2  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0109  IN        12           5         5     0.0%    40.0%    60.0%    0.0%           91% / 98%
0x0037  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502           4         4     0.0%   100.0%     0.0%    0.0%            0% / 73%
0x0038  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x005B  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006E  IN      2486           4         4    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0071  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0010  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0027  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  OUT       12           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           3         -                                     no script
0x0068  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0003  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0009  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  OUT        -           2         -                                     no script
0x002C  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x0042  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             2% / 6%
0x006C  OUT        -           2         -                                     no script
0x0079  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0082  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00C6  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x00D6  IN         -           2         -                                     no script
0x0002  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT     2525           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             2% / 2%
0x000B  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%           76% / 76%
0x000D  OUT        -           1         -                                     no script
0x000E  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  OUT        -           1         -                                     no script
0x0019  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             9% / 9%
0x0025  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT     2502           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0036  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  OUT        -           1         -                                     no script
0x0048  OUT        -           1         -                                     no script
0x004A  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           17% / 17%
0x0057  OUT        -           1         -                                     no script
0x0063  OUT        -           1         -                                     no script
0x0065  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0080  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0084  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             0% / 0%
0x0095  OUT     2520           1         1     0.0%   100.0%     0.0%    0.0%           69% / 69%
0x009F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x00A2  OUT     2502           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AF  IN         -           1         -                                     no script
0x00B8  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x00CF  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F9  IN         -           1         -                                     no script
0x010C  IN      2502           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x010F  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=187
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -37224 at offset 39/41
  ! ReadBytes: negative length -37890 at offset 39/41
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 15
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2062
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 721684
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = -18612

### 0x001C IN src 12  over=1.481 threw=0 negative-length=67
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9472
       21    2  Int16    StateSync/SpeedCoordS/Z = 767
       23    1  Byte     StateSync/Unknown = 202
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 6664
       26    2  Int16    StateSync/CoordS / 1000 = 0
       28    4  Single   StateSync/UnknownCoordF/X = 3,7597E-40

### 0x0023 IN src 12  over=1.475 threw=0
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

### 0x003D IN src 12  over=665 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 6704925261832171012
        8    4  Int32    ServerTick = -1713518080
       12    4  Int32    ObjectId = -1698037759
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0047 IN src 12  over=437 threw=0 negative-length=238
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 44660 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 44660 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 44660 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 22330

### 0x0056 IN src 12  over=220 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 5789407

### 0x001C IN src 2507  over=170 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 751
       13    2  Int16    coord x = 440
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = 1733041436691118082
       30    2  Int16    speed x = 4

### 0x00B0 IN src 12  over=152 threw=0 negative-length=122
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -23038 at offset 6/20
  ! ReadBytes: negative length -23038 at offset 6/20
  ! ReadBytes: negative length -47102 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593288960
        4    2  Int16    Motto/size = -11519

### 0x004E IN src 12  over=131 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 16006 byte(s) at offset 7, only 463 of 470 remain
  ! ReadBytes: wanted 47324 byte(s) at offset 11, only 23 of 34 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1, only 5 of 6 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 50
        5    2  Int16    FunctionCubeName/size = 8003

### 0x002B IN src 12  over=120 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 3 of 45 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 3 of 45 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 3 of 45 remain
  last reads before failure (of 11):
       12    1  Boolean  flag = True
       13    8  Int64    Uid = 8224726441977300490
       21    4  Single   positionCoordF/X = 1,166212E+23
       25    4  Single   positionCoordF/Y = 1,8084683E-38
       29    4  Single   positionCoordF/Z = -1,6349934E+37
       33    4  Int32    ownerObjectId = 1725
       37    4  Int32    Unknown = 1
       41    1  Byte     Unknown = 21

### 0x002E IN src 2521  over=45 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2521\Inbound\0x002E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  last reads before failure (of 12):
       10    4  Int32    0 base = 0
       14    4  Int32    0 total = 100
       18    4  Int32    1 bonus = 231064
       22    4  Int32    1 base = 0
       26    4  Int32    1 total = 100
       30    4  Int32    2 bonus = 231064
       34    4  Int32    2 base = 0
       38    4  Int32    2 total = 100

### 0x0061 IN src 12  over=43 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 827, only 1 of 828 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):
