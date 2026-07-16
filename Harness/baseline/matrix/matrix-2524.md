# Harness — MATRIX -> 2524

scripts from build : (matrix, see src column)
packets from build : 2524
packets considered : 29.897
packets executed   : 26.724  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                592   2.2%
OkExact               9.832   36.8%
UnderRead            12.039   45.0%
OverRead              4.259   15.9%
Threw                     2   0.0%

of packets a script actually ran on (26.132):
  clean (consumed exactly) : 37.6%
  over-read (WRONG)        : 16.3%
  under-read (ambiguous)   : 46.1%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12      11.189     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      11.189     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      11.189     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN        12      10.918     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      10.918     1.500    58.9%    41.1%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      10.918     1.500    92.7%     7.3%     0.0%    0.0%         100% / 100%
0x0023  IN        12       1.371     1.371     1.8%     0.0%    98.2%    0.0%         100% / 100%
0x0023  IN      2486       1.371     1.371     1.2%    98.8%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       1.371     1.371     1.2%    98.8%     0.0%    0.0%           11% / 11%
0x0012  OUT       12       1.198     1.198     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x001C  IN        12         770       770     1.2%     0.0%    98.8%    0.0%         100% / 100%
0x001C  IN      2507         770       770    95.6%     0.0%     4.4%    0.0%         100% / 100%
0x0021  IN        12         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2511         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         720       720     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0011  IN        12         633       633    51.7%    48.3%     0.0%    0.0%         100% / 100%
0x0047  IN        12         319       319     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x000B  OUT       12         314       314   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -         243         -                                     no script
0x00B0  IN        12         182       182     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x005E  IN        12         129       129     0.0%    93.8%     6.2%    0.0%            0% / 14%
0x005E  IN      2506         129       129   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12         119       119     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504         119       119   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         119       119   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12         109       109     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521         109       109    28.4%    56.9%    14.7%    0.0%          19% / 100%
0x002E  IN      2528         109       109    85.3%    14.7%     0.0%    0.0%         100% / 100%
0x008A  IN      2511         108       108     0.0%   100.0%     0.0%    0.0%             0% / 6%
0x008A  IN      2524         108       108    81.5%     9.3%     7.4%    1.9%         100% / 100%
0x0052  IN        12          77        77     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0052  IN      2516          77        77    68.8%    31.2%     0.0%    0.0%         100% / 100%
0x0006  IN        12          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12          63        63     0.0%    31.7%    68.3%    0.0%           96% / 96%
0x003D  IN      2512          63        63    68.3%    31.7%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          63        63    31.7%    68.3%     0.0%    0.0%           4% / 100%
0x00A8  IN         -          56         -                                     no script
0x00F6  IN        12          55        55     0.0%    92.7%     7.3%    0.0%             0% / 0%
0x00F6  IN      2520          55        55   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          46        46     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          46        46     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          46        46    97.8%     2.2%     0.0%    0.0%         100% / 100%
0x0061  IN        12          46        46     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006B  IN        12          31        31     0.0%    74.2%    25.8%    0.0%           9% / 100%
0x006B  IN      2507          31        31    54.8%    45.2%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          31        31     6.5%    93.5%     0.0%    0.0%            3% / 20%
0x006B  IN      2524          31        31    54.8%    45.2%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          31        31     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2546          31        31     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2549          31        31     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2550          31        31    93.5%     0.0%     6.5%    0.0%         100% / 100%
0x00CC  IN        12          31        31     0.0%    74.2%    25.8%    0.0%            7% / 50%
0x006A  IN        12          29        29    27.6%    72.4%     0.0%    0.0%          22% / 100%
0x006A  IN      2486          29        29    72.4%    27.6%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          29        29    17.2%    82.8%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          29        29    34.5%    65.5%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          29        29    34.5%    65.5%     0.0%    0.0%          20% / 100%
0x004E  IN        12          25        25    96.0%     0.0%     4.0%    0.0%         100% / 100%
0x0093  IN         -          25         -                                     no script
0x0045  IN        12          24        24     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          24        24     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2496          24        24     0.0%    66.7%    33.3%    0.0%           42% / 54%
0x0069  IN      2497          24        24     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2502          24        24     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2503          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          24        24    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          24        24    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550          24        24    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x00B6  IN        12          24        24     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0123  IN         -          23         -                                     no script
0x0128  IN        12          22        22    27.3%    72.7%     0.0%    0.0%          14% / 100%
0x007A  IN        12          18        18     0.0%     0.0%   100.0%    0.0%           78% / 78%
0x0017  IN        12          17        17     0.0%     0.0%   100.0%    0.0%          83% / 100%
0x0017  IN      2500          17        17     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          17        17     0.0%    94.1%     5.9%    0.0%            8% / 11%
0x0017  IN      2528          17        17     0.0%     0.0%   100.0%    0.0%          12% / 100%
0x0017  IN      2550          17        17     0.0%     0.0%   100.0%    0.0%          83% / 100%
0x004F  OUT        -          17         -                                     no script
0x0019  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          16        16    50.0%    43.8%     6.2%    0.0%         100% / 100%
0x003C  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506          16        16     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004D  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          16        16     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12          16        16     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          16        16     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          16         -                                     no script
0x012D  IN         -          16         -                                     no script
0x0138  IN         -          16         -                                     no script
0x0037  IN        12          15        15     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0075  IN        12          14        14     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F4  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0038  OUT     2511          13        13     0.0%    84.6%    15.4%    0.0%           20% / 69%
0x0038  OUT     2550          13        13    69.2%    30.8%     0.0%    0.0%         100% / 100%
0x00A5  IN         -          12         -                                     no script
0x0005  IN        12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x00E6  IN         -           9         -                                     no script
0x0001  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           8         -                                     no script
0x000F  OUT        -           8         -                                     no script
0x0010  OUT        -           8         -                                     no script
0x0013  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0034  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0039  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12           8         8     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           8         -                                     no script
0x006F  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           8         8     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           8         8     0.0%    62.5%    37.5%    0.0%           11% / 56%
0x007D  IN      2486           8         8     0.0%    25.0%    75.0%    0.0%         100% / 100%
0x007D  IN      2502           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           8         -                                     no script
0x009E  IN         -           8         -                                     no script
0x00A7  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           8         -                                     no script
0x00B0  OUT        -           8         -                                     no script
0x00B2  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           8         -                                     no script
0x00B7  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           8         8     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           8         -                                     no script
0x00CA  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             5% / 6%
0x00D1  IN         -           8         -                                     no script
0x00DF  IN         -           8         -                                     no script
0x00EB  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           8         -                                     no script
0x00F3  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           8         -                                     no script
0x011B  IN        12           8         8     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0125  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           8         -                                     no script
0x0131  IN         -           8         -                                     no script
0x0137  IN         -           8         -                                     no script
0x013A  IN         -           8         -                                     no script
0x0063  IN        12           7         7     0.0%     0.0%   100.0%    0.0%             2% / 9%
0x0063  IN      2507           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0063  IN      2518           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0071  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -           6         -                                     no script
0x004F  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           4         -                                     no script
0x010E  IN        12           4         4     0.0%     0.0%   100.0%    0.0%          56% / 100%
0x00A4  OUT       12           3         3     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0010  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0011  OUT        -           1         -                                     no script
0x0018  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x0023  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x003A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x005B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00B6  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BC  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00C1  IN         -           1         -                                     no script
0x00D6  IN         -           1         -                                     no script
0x011F  IN         -           1         -                                     no script
0x012E  IN         -           1         -                                     no script

## Sample failures

### 0x0023 IN src 12  over=1.347 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100003/Stats/Unknown = 0
      171    4  Int32    Item: 50100003/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100003/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100003/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100003/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100003/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100003/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100003/ItemEnchant/CanRepackage = False

### 0x0012 OUT src 12  over=1.198 threw=0 negative-length=100
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: wanted 38802 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: wanted 49064 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: wanted 49686 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -1536
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = 19401

### 0x001C IN src 12  over=761 threw=0 negative-length=27
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 767
       23    1  Byte     StateSync/Unknown = 70
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 4101
       26    2  Int16    StateSync/CoordS / 1000 = 0
       28    4  Int32    StateSync/Unknown = 1627869

### 0x0047 IN src 12  over=319 threw=0 negative-length=115
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 37204 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 37204 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 37204 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 18602

### 0x00B0 IN src 12  over=182 threw=0 negative-length=92
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -22526 at offset 6/20
  ! ReadBytes: wanted 24578 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: negative length -12798 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593036032
        4    2  Int16    Motto/size = -11263

### 0x0061 IN src 12  over=46 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 4981, only 0 of 4981 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 4935, only 0 of 4935 remain
  last reads before failure (of 0):

### 0x003D IN src 12  over=43 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 4632184214782530308
        8    4  Int32    ServerTick = 1114082560
       12    4  Int32    ObjectId = -1698037759
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x001C IN src 2507  over=34 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 3751
       13    2  Int16    coord x = 3140
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -1161365748790311934
       30    2  Int16    speed x = 24

### 0x0045 IN src 12  over=24 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 18, only 1 of 19 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 335544320
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 3072
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 12800

### 0x007A IN src 12  over=18 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x007A.py
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  last reads before failure (of 4):
        0    8  Int64    CharacterId = 5730271978251734440
        8    1  Boolean  Bool = True
        9    8  Int64    Unknown = 6487720560882160622
       17    8  Int64    CharacterId = 250516027153067264

### 0x0017 IN src 12  over=17 threw=0 negative-length=8
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: negative length -17408 at offset 4286/5927
  ! Read<Int32>: wanted 4 byte(s) at offset 4042, only 3 of 4045 remain
  ! ReadBytes: negative length -27648 at offset 5351/5939
  last reads before failure (of 1637):
     4237    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 0
     4241    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 4784754647275973120
     4249    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = 7653770810771417601
     4257    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
     4258    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 515482181886949288
     4266    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = 8
     4268   16  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/UUID = 01000000010000000000000000AA4840
     4284    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/size = -8704

### 0x0017 IN src 2528  over=17 threw=0 negative-length=10
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! ReadBytes: negative length -47070 at offset 620/5927
  ! ReadBytes: wanted 51200 byte(s) at offset 915, only 3130 of 4045 remain
  ! ReadBytes: negative length -47070 at offset 620/5939
  last reads before failure (of 120):
      587    1  Boolean  InBattle = True
      588    1  Byte     gameObject_vtbl+572 virtual call/Unknown = 0
      589    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 5
      593    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 288401504795099392
      601    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = -6588484775571357696
      609    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
      610    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 281474976711936
      618    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = -23535
