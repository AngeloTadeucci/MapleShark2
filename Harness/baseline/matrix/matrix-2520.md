# Harness — MATRIX -> 2520

scripts from build : (matrix, see src column)
packets from build : 2520
packets considered : 18.957
packets executed   : 22.704  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                514   2.3%
OkExact              10.357   45.6%
UnderRead             7.102   31.3%
OverRead              4.731   20.8%

of packets a script actually ran on (22.190):
  clean (consumed exactly) : 46.7%
  over-read (WRONG)        : 21.3%
  under-read (ambiguous)   : 32.0%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12       4.773     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0058  IN        12       4.523     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521       4.523     1.500    62.8%    37.2%     0.0%    0.0%         100% / 100%
0x0058  IN      2527       4.523     1.500    80.1%    19.9%     0.0%    0.0%         100% / 100%
0x0024  IN        12       3.654     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       3.654     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       3.654     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN        12       1.489     1.489     0.9%     0.1%    98.9%    0.0%         100% / 100%
0x001C  IN      2507       1.489     1.489    64.6%     0.0%    35.4%    0.0%         100% / 100%
0x0011  IN        12         826       826    50.8%    49.2%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         410       410   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12         403       403     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521         403       403     4.2%    95.3%     0.5%    0.0%           19% / 19%
0x002E  IN      2528         403       403    99.5%     0.5%     0.0%    0.0%         100% / 100%
0x003D  IN        12         380       380     0.0%     1.6%    98.4%    0.0%           96% / 96%
0x003D  IN      2512         380       380    98.4%     1.6%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         380       380     1.6%    98.4%     0.0%    0.0%             4% / 4%
0x0023  IN        12         347       347     4.3%     0.0%    95.7%    0.0%         100% / 100%
0x0023  IN      2486         347       347     2.9%    97.1%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         347       347     2.9%    97.1%     0.0%    0.0%           11% / 11%
0x007E  IN         -         250         -                                     no script
0x0021  IN        12         216       216     0.0%    99.1%     0.9%    0.0%           17% / 20%
0x0021  IN      2511         216       216     0.0%    99.5%     0.5%    0.0%           17% / 20%
0x0021  IN      2525         216       216     0.5%    99.5%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         216       216     0.5%    99.5%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         216       216     0.5%    99.5%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         216       216     0.5%    99.5%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         216       216     0.5%    99.5%     0.0%    0.0%           17% / 20%
0x00B0  IN        12         155       155     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0047  IN        12         119       119     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0006  IN        12         108       108   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         108       108   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         108       108   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          67        67     0.0%    92.5%     7.5%    0.0%           26% / 35%
0x005E  IN      2506          67        67   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12          63        63     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          63        63   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          63        63   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          52        52     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          52        52     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          52        52    73.1%     0.0%    26.9%    0.0%         100% / 100%
0x0037  IN        12          49        49     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x001D  IN        12          46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          36         -                                     no script
0x0093  IN         -          35         -                                     no script
0x0022  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  IN        12          30        30     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          30        30    33.3%    66.7%     0.0%    0.0%           6% / 100%
0x0052  IN        12          30        30     0.0%   100.0%     0.0%    0.0%           11% / 20%
0x0052  IN      2516          30        30    46.7%    50.0%     3.3%    0.0%          20% / 100%
0x0011  OUT        -          27         -                                     no script
0x006A  IN        12          23        23    26.1%    73.9%     0.0%    0.0%          22% / 100%
0x006A  IN      2486          23        23    73.9%    26.1%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          23        23    21.7%    78.3%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          23        23    43.5%    56.5%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          23        23    43.5%    56.5%     0.0%    0.0%          20% / 100%
0x006C  IN        12          21        21     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x008A  IN      2511          20        20     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          20        20    85.0%     0.0%    15.0%    0.0%         100% / 100%
0x0017  IN        12          18        18     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          18        18     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          18        18     0.0%    55.6%    44.4%    0.0%          26% / 100%
0x0017  IN      2528          18        18     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          18        18     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0128  IN        12          18        18    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0045  IN        12          17        17     0.0%    11.8%    88.2%    0.0%           98% / 98%
0x0061  IN        12          17        17     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x0069  IN        12          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          17        17     0.0%    64.7%    35.3%    0.0%           20% / 47%
0x0069  IN      2496          17        17     0.0%    64.7%    35.3%    0.0%           34% / 90%
0x0069  IN      2497          17        17     0.0%    64.7%    35.3%    0.0%           20% / 47%
0x0069  IN      2502          17        17     0.0%    64.7%    35.3%    0.0%           20% / 47%
0x0069  IN      2503          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          17        17    64.7%     0.0%    35.3%    0.0%         100% / 100%
0x0069  IN      2546          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          17        17    64.7%     0.0%    35.3%    0.0%         100% / 100%
0x0069  IN      2550          17        17    64.7%     0.0%    35.3%    0.0%         100% / 100%
0x00F6  IN        12          17        17     0.0%   100.0%     0.0%    0.0%             0% / 7%
0x00F6  IN      2520          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12          16        16     0.0%    68.8%    31.2%    0.0%          46% / 100%
0x006B  IN      2507          16        16    68.8%    31.2%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          16        16     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          16        16    68.8%    31.2%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          16        16     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          16        16     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          16        16     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0053  IN        12          15        15     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B6  IN        12          15        15     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x004F  OUT        -          13         -                                     no script
0x00CC  IN        12          13        13     0.0%    84.6%    15.4%    0.0%           20% / 50%
0x012D  IN         -          12         -                                     no script
0x0044  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0051  IN        12          11        11     0.0%   100.0%     0.0%    0.0%            6% / 33%
0x0051  IN      2537          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2546          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2549          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2550          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0138  IN         -          11         -                                     no script
0x0019  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          10        10    50.0%    10.0%    40.0%    0.0%         100% / 100%
0x006D  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00F4  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x010A  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          10         -                                     no script
0x0005  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0054  IN        12           8         8    25.0%    12.5%    62.5%    0.0%          90% / 100%
0x005A  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000F  OUT        -           6         -                                     no script
0x0010  OUT        -           6         -                                     no script
0x0016  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x002F  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           6         6     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529           6         6    16.7%    83.3%     0.0%    0.0%           1% / 100%
0x0055  OUT        -           6         -                                     no script
0x0073  IN        12           6         6     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           6         6     0.0%    83.3%    16.7%    0.0%            0% / 56%
0x007D  IN      2486           6         6     0.0%    66.7%    33.3%    0.0%          64% / 100%
0x007D  IN      2502           6         6    33.3%    66.7%     0.0%    0.0%          63% / 100%
0x007D  IN      2503           6         6    33.3%    66.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           6         6    33.3%    66.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           6         6    33.3%    66.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           6         6    33.3%    66.7%     0.0%    0.0%         100% / 100%
0x0080  OUT        -           6         -                                     no script
0x008E  OUT        -           6         -                                     no script
0x00A5  IN         -           6         -                                     no script
0x00CA  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           10% / 20%
0x00D1  IN         -           6         -                                     no script
0x00E6  IN         -           6         -                                     no script
0x00EB  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F3  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0001  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           5         -                                     no script
0x0013  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12           5         5     0.0%   100.0%     0.0%    0.0%            1% / 18%
0x004D  IN      2503           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           5         5     0.0%   100.0%     0.0%    0.0%            9% / 18%
0x004D  IN      2507           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0089  IN      2527           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           5         -                                     no script
0x00A7  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           5         -                                     no script
0x00B0  OUT        -           5         -                                     no script
0x00B2  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           5         5     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           5         -                                     no script
0x00B7  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           5         5     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           5         -                                     no script
0x00CB  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             7% / 9%
0x00DF  IN         -           5         -                                     no script
0x00EE  IN         -           5         -                                     no script
0x0110  IN         -           5         -                                     no script
0x0125  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           5         -                                     no script
0x0131  IN         -           5         -                                     no script
0x0137  IN         -           5         -                                     no script
0x0139  IN         -           5         -                                     no script
0x0025  OUT       12           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0025  OUT     2502           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x003C  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           3         3     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0018  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12           2         2    50.0%    50.0%     0.0%    0.0%          98% / 100%
0x0020  OUT     2507           2         2    50.0%    50.0%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512           2         2    50.0%    50.0%     0.0%    0.0%          98% / 100%
0x0039  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x003E  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x009D  IN         -           2         -                                     no script
0x00A2  OUT     2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00C1  IN         -           2         -                                     no script
0x010C  IN      2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0028  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%             8% / 8%
0x002D  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           35% / 35%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0056  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x005B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0063  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           15% / 15%
0x0063  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0063  IN      2518           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0066  OUT        -           1         -                                     no script
0x0069  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  OUT        -           1         -                                     no script
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0095  OUT     2520           1         1     0.0%   100.0%     0.0%    0.0%           69% / 69%
0x0103  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=217
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 15
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 1806
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = 9,2917E-41
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = -2,2079235E-37

### 0x001C IN src 12  over=1.473 threw=0 negative-length=31
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       18    2  Int16    StateSync/PositionCoordS/Z = 45
       20    2  Int16    StateSync/Rotation = -39
       22    1  Byte     StateSync/Animation3 = 17
       23    2  Int16    StateSync/SpeedCoordS/X = 0
       25    2  Int16    StateSync/SpeedCoordS/Y = 307
       27    2  Int16    StateSync/SpeedCoordS/Z = -2304
       29    1  Byte     StateSync/Unknown = 250
       30    2  Int16    StateSync/Rotation2 CoordS / 10 = 0

### 0x001C IN src 2507  over=527 threw=0
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
       22    8  Int64    2x float = -362821239946870767
       30    2  Int16    speed x = 0

### 0x003D IN src 12  over=374 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = -8514037492455305212
        8    4  Int32    ServerTick = -2031516926
       12    4  Int32    ObjectId = 1283
       16    4  Int32    SkillId = 0
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0023 IN src 12  over=332 threw=0
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

### 0x00B0 IN src 12  over=155 threw=0 negative-length=94
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -4092 at offset 6/20
  ! ReadBytes: negative length -22526 at offset 6/20
  ! ReadBytes: wanted 24578 byte(s) at offset 6, only 14 of 20 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = -1876901632
        4    2  Int16    Motto/size = -2046

### 0x0047 IN src 12  over=119 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 43168 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 43168 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 39038 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 21584

### 0x0017 IN src 12  over=18 threw=0 negative-length=2
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 5324, only 2 of 5326 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1932, only 6 of 1938 remain
  ! ReadBytes: negative length -22016 at offset 890/3254
  last reads before failure (of 677):
     5260    8  Int64    PlayerInfo/Player+1B0 = -729264825249768575
     5268    8  Int64    PlayerInfo/Player+1B0 = 72057594054705413
     5276    8  Int64    PlayerInfo/Player+1B0 = 0
     5284    8  Int64    PlayerInfo/Player+1B0 = 0
     5292    8  Int64    PlayerInfo/Player+1B0 = 0
     5300    8  Int64    PlayerInfo/Player+1B0 = 1099679399936
     5308    8  Int64    PlayerInfo/Player+1B0 = 27156154492649472
     5316    8  Int64    PlayerInfo/Player+1B0 = 1077885796352

### 0x0017 IN src 2528  over=18 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 5324, only 2 of 5326 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1932, only 6 of 1938 remain
  ! ReadBytes: wanted 65536 byte(s) at offset 685, only 2569 of 3254 remain
  last reads before failure (of 677):
     5260    8  Int64    PlayerInfo/Player+1B0 = -729264825249768575
     5268    8  Int64    PlayerInfo/Player+1B0 = 72057594054705413
     5276    8  Int64    PlayerInfo/Player+1B0 = 0
     5284    8  Int64    PlayerInfo/Player+1B0 = 0
     5292    8  Int64    PlayerInfo/Player+1B0 = 0
     5300    8  Int64    PlayerInfo/Player+1B0 = 1099679399936
     5308    8  Int64    PlayerInfo/Player+1B0 = 27156154492649472
     5316    8  Int64    PlayerInfo/Player+1B0 = 1077885796352

### 0x0017 IN src 2550  over=18 threw=0 negative-length=2
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 5324, only 2 of 5326 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1932, only 6 of 1938 remain
  ! ReadBytes: negative length -22016 at offset 890/3254
  last reads before failure (of 677):
     5260    8  Int64    PlayerInfo/Player+1B0 = -729264825249768575
     5268    8  Int64    PlayerInfo/Player+1B0 = 72057594054705413
     5276    8  Int64    PlayerInfo/Player+1B0 = 0
     5284    8  Int64    PlayerInfo/Player+1B0 = 0
     5292    8  Int64    PlayerInfo/Player+1B0 = 0
     5300    8  Int64    PlayerInfo/Player+1B0 = 1099679399936
     5308    8  Int64    PlayerInfo/Player+1B0 = 27156154492649472
     5316    8  Int64    PlayerInfo/Player+1B0 = 1077885796352

### 0x0061 IN src 12  over=17 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 827, only 1 of 828 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=15 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 16777216
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 0
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0
