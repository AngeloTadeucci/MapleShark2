# Harness — MATRIX -> 2516

scripts from build : (matrix, see src column)
packets from build : 2516
packets considered : 61.128
packets executed   : 32.604  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              1.940   6.0%
OkExact              13.333   40.9%
UnderRead            11.465   35.2%
OverRead              5.860   18.0%
Threw                     6   0.0%

of packets a script actually ran on (30.664):
  clean (consumed exactly) : 43.5%
  over-read (WRONG)        : 19.1%
  under-read (ambiguous)   : 37.4%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12      19.249     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0058  IN        12      18.822     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521      18.822     1.500    36.3%    63.7%     0.0%    0.0%          97% / 100%
0x0058  IN      2527      18.822     1.500    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x0024  IN        12       7.681     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       7.681     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       7.681     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN        12       5.073     1.500     1.1%     0.1%    98.9%    0.0%         100% / 100%
0x001C  IN      2507       5.073     1.500    92.9%     2.7%     4.3%    0.0%         100% / 100%
0x007E  IN         -       1.839         -                                     no script
0x0011  IN        12       1.073     1.073    50.7%    49.3%     0.0%    0.0%         100% / 100%
0x0023  IN        12         815       815     2.2%     0.0%    97.8%    0.0%         100% / 100%
0x0023  IN      2486         815       815     1.5%    98.5%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         815       815     1.5%    98.5%     0.0%    0.0%           11% / 11%
0x002E  IN        12         648       648     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521         648       648     6.9%    74.2%    18.8%    0.0%          19% / 100%
0x002E  IN      2528         648       648    81.3%    18.7%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         535       535   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12         385       385     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         385       385     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         385       385    99.7%     0.0%     0.3%    0.0%         100% / 100%
0x005E  IN        12         374       374     0.0%    98.4%     1.6%    0.0%           35% / 35%
0x005E  IN      2506         374       374   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12         347       347     0.0%    25.9%    74.1%    0.0%          90% / 100%
0x003D  IN      2512         347       347    74.4%    25.6%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         347       347    45.5%    53.6%     0.9%    0.0%           4% / 100%
0x00C7  IN        12         342       342     0.0%   100.0%     0.0%    0.0%           38% / 38%
0x0047  IN        12         307       307     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0021  IN        12         297       297     6.7%    65.7%    27.6%    0.0%          20% / 100%
0x0021  IN      2511         297       297     6.1%    87.2%     6.4%    0.3%           17% / 99%
0x0021  IN      2525         297       297    12.8%    86.9%     0.0%    0.3%          17% / 100%
0x0021  IN      2529         297       297    12.8%    86.9%     0.0%    0.3%          17% / 100%
0x0021  IN      2546         297       297    12.8%    86.9%     0.0%    0.3%          17% / 100%
0x0021  IN      2549         297       297    12.8%    86.9%     0.0%    0.3%          17% / 100%
0x0021  IN      2550         297       297    12.8%    86.9%     0.0%    0.3%          17% / 100%
0x0056  IN        12         262       262     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0052  IN        12         211       211     0.9%    88.2%    10.9%    0.0%           41% / 85%
0x0052  IN      2516         211       211    10.0%    64.5%    25.6%    0.0%           8% / 100%
0x002B  IN        12         138       138     0.0%     0.0%   100.0%    0.0%           93% / 99%
0x002B  IN      2530         138       138    89.1%     0.0%    10.9%    0.0%         100% / 100%
0x002B  IN      2531         138       138    89.1%     0.0%    10.9%    0.0%         100% / 100%
0x002C  IN        12         136       136   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12         131       131   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         131       131   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         131       131   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12         127       127     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         127       127     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         127       127   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         127       127   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         127       127   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12         120       120    10.8%    89.2%     0.0%    0.0%          53% / 100%
0x0075  IN        12         120       120     0.0%    99.2%     0.8%    0.0%             2% / 2%
0x0075  IN      2529         120       120   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12         105       105     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0022  OUT       12          95        95   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  IN        12          94        94     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          94        94    24.5%    75.5%     0.0%    0.0%           6% / 100%
0x004E  IN        12          89        89     3.4%     0.0%    96.6%    0.0%           18% / 18%
0x0080  OUT        -          72         -                                     no script
0x00B0  IN        12          60        60     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0048  IN        12          59        59     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          59        59   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          59        59   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12          54        54    92.6%     0.0%     7.4%    0.0%         100% / 100%
0x0020  OUT     2507          54        54    29.6%    70.4%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512          54        54    92.6%     0.0%     7.4%    0.0%         100% / 100%
0x0093  IN         -          44         -                                     no script
0x00A8  IN         -          43         -                                     no script
0x0017  IN        12          34        34     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          34        34     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          34        34     0.0%     5.9%    94.1%    0.0%         100% / 100%
0x0017  IN      2528          34        34     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          34        34     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  IN        12          33        33     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12          32        32    50.0%    50.0%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          32        32    68.8%    31.2%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          32        32    25.0%    75.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          32        32    31.2%    68.8%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          32        32    31.2%    68.8%     0.0%    0.0%          20% / 100%
0x0063  IN        12          30        30     0.0%    50.0%    50.0%    0.0%           19% / 27%
0x0063  IN      2507          30        30    20.0%    80.0%     0.0%    0.0%           3% / 100%
0x0063  IN      2518          30        30    20.0%    80.0%     0.0%    0.0%           3% / 100%
0x0069  IN        12          30        30     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          30        30     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2496          30        30     0.0%    66.7%    33.3%    0.0%           34% / 54%
0x0069  IN      2497          30        30     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2502          30        30     0.0%    66.7%    33.3%    0.0%           20% / 47%
0x0069  IN      2503          30        30     6.7%    93.3%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          30        30     6.7%    93.3%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          30        30    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546          30        30     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          30        30    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550          30        30    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x004F  OUT        -          27         -                                     no script
0x0103  IN         -          27         -                                     no script
0x0029  OUT       12          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12          23        23     0.0%    73.9%    26.1%    0.0%          46% / 100%
0x006B  IN      2507          23        23    69.6%    30.4%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          23        23     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          23        23    69.6%    30.4%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          23        23     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          23        23     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          23        23     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x0045  IN        12          22        22     0.0%    40.9%    59.1%    0.0%           98% / 98%
0x0073  IN        12          22        22     0.0%     0.0%   100.0%    0.0%           73% / 80%
0x0073  IN      2531          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0128  IN        12          22        22     9.1%    90.9%     0.0%    0.0%           14% / 14%
0x00B6  IN        12          21        21     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0033  IN        12          18        18     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0039  IN        12          18        18     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x005A  IN        12          18        18     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  OUT       12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005B  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EB  IN        12          17        17     5.9%     0.0%    94.1%    0.0%         100% / 100%
0x0005  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12          16        16    81.2%    18.8%     0.0%    0.0%         100% / 100%
0x0041  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0044  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008E  OUT        -          16         -                                     no script
0x0026  OUT       12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12          15        15     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00CB  IN        12          15        15     0.0%   100.0%     0.0%    0.0%             2% / 5%
0x0019  IN        12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          13        13    53.8%     0.0%    46.2%    0.0%         100% / 100%
0x006D  IN        12          13        13     0.0%   100.0%     0.0%    0.0%           14% / 14%
0x006F  IN        12          13        13     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0061  IN        12          12        12     0.0%     0.0%   100.0%    0.0%             0% / 0%
0x00CC  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x010A  IN        12          12        12     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          12         -                                     no script
0x012D  IN         -          12         -                                     no script
0x0038  OUT     2511          11        11     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          11        11    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x000F  OUT        -          10         -                                     no script
0x0010  OUT        -          10         -                                     no script
0x0016  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          10        10    20.0%    80.0%     0.0%    0.0%          62% / 100%
0x0035  IN        12          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004C  IN        12          10        10     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12          10        10     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -          10         -                                     no script
0x007D  IN        12          10        10     0.0%    20.0%    80.0%    0.0%           56% / 56%
0x007D  IN      2486          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CA  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -          10         -                                     no script
0x00E6  IN         -          10         -                                     no script
0x00F3  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x000C  IN        12           8         8    25.0%     0.0%    75.0%    0.0%         100% / 100%
0x000C  IN      2507           8         8    37.5%     0.0%    62.5%    0.0%         100% / 100%
0x000C  IN      2525           8         8    37.5%     0.0%    62.5%    0.0%         100% / 100%
0x0031  OUT       12           8         8     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00A5  IN         -           8         -                                     no script
0x00F4  IN        12           8         8     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0001  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  OUT        -           7         -                                     no script
0x0097  OUT        -           7         -                                     no script
0x00B0  OUT        -           7         -                                     no script
0x00B2  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             1% / 5%
0x00B3  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           7         -                                     no script
0x0125  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0004  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           6         -                                     no script
0x0015  IN        12           6         6     0.0%     0.0%   100.0%    0.0%          68% / 100%
0x0015  IN      2507           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0049  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x0049  IN      2529           6         6     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x0057  OUT        -           6         -                                     no script
0x006C  OUT        -           6         -                                     no script
0x0089  IN      2527           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           6         -                                     no script
0x00A7  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           6         -                                     no script
0x00B7  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           6         6     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           6         -                                     no script
0x00DF  IN         -           6         -                                     no script
0x00EE  IN         -           6         -                                     no script
0x0110  IN         -           6         -                                     no script
0x0126  IN         -           6         -                                     no script
0x0131  IN         -           6         -                                     no script
0x0137  IN         -           6         -                                     no script
0x0138  IN         -           6         -                                     no script
0x004F  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006E  IN      2486           5         5    40.0%     0.0%    60.0%    0.0%         100% / 100%
0x001D  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  OUT        -           4         -                                     no script
0x0066  IN        12           4         4     0.0%    25.0%    75.0%    0.0%            0% / 44%
0x0068  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486           4         4    50.0%    50.0%     0.0%    0.0%          17% / 100%
0x0010  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT       12           2         2    50.0%     0.0%    50.0%    0.0%          14% / 100%
0x0009  OUT     2525           2         2    50.0%     0.0%    50.0%    0.0%          14% / 100%
0x0025  IN        12           2         2     0.0%     0.0%   100.0%    0.0%             7% / 9%
0x0037  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502           2         2     0.0%   100.0%     0.0%    0.0%           73% / 73%
0x003C  OUT        -           2         -                                     no script
0x004D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x004D  IN      2503           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x004D  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           2         -                                     no script
0x00B1  IN         -           2         -                                     no script
0x00B8  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x00F7  IN         -           2         -                                     no script
0x00F9  IN         -           2         -                                     no script
0x0009  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             2% / 2%
0x000B  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%           76% / 76%
0x000E  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  OUT        -           1         -                                     no script
0x0016  OUT        -           1         -                                     no script
0x0026  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x003A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x0045  OUT        -           1         -                                     no script
0x0048  OUT        -           1         -                                     no script
0x0063  OUT        -           1         -                                     no script
0x006B  OUT        -           1         -                                     no script
0x0080  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0090  IN         -           1         -                                     no script
0x009F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x00AB  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00CF  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           1         -                                     no script
0x010F  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=130
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: wanted 32896 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       25    2  Int16    Segment 0/StateSync/Rotation = -40
       27    1  Byte     Segment 0/StateSync/Animation3 = 2
       28    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 3599
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 8
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -4864
       34    1  Byte     Segment 0/StateSync/Unknown = 244
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 6
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = -21613

### 0x001C IN src 12  over=1.483 threw=0 negative-length=90
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! ReadBytes: negative length -10744 at offset 30/32
  ! Read<Int32>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       18    2  Int16    StateSync/PositionCoordS/Z = 45
       20    2  Int16    StateSync/Rotation = -39
       22    1  Byte     StateSync/Animation3 = 2
       23    2  Int16    StateSync/SpeedCoordS/X = 899
       25    2  Int16    StateSync/SpeedCoordS/Y = 26
       27    2  Int16    StateSync/SpeedCoordS/Z = 1280
       29    1  Byte     StateSync/Unknown = 248
       30    2  Int16    StateSync/Rotation2 CoordS / 10 = 6

### 0x0023 IN src 12  over=797 threw=0
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

### 0x0047 IN src 12  over=307 threw=0 negative-length=51
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -64978 at offset 3/40
  ! ReadBytes: negative length -64978 at offset 3/40
  ! ReadBytes: negative length -64978 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -32489

### 0x0056 IN src 12  over=262 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 846149

### 0x003D IN src 12  over=257 threw=0 negative-length=14
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! ReadBytes: negative length -8704 at offset 63/70
  ! Read<Boolean>: wanted 1 byte(s) at offset 56, only 0 of 56 remain
  ! Read<Boolean>: wanted 1 byte(s) at offset 56, only 0 of 56 remain
  last reads before failure (of 20):
       41    4  Single   RotationCoordF/X = 3,5941469E-31
       45    4  Single   RotationCoordF/Y = -9,903823E+27
       49    4  Single   RotationCoordF/Z = NaN
       53    2  Int16    CoordS / 10 = -1
       55    1  Boolean  Unknown = True
       56    1  Boolean  Unknown = True
       57    4  Int32    Unknown = 16780521
       61    2  Int16    Unknown/size = -4352

### 0x002B IN src 12  over=138 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 221, only 3 of 224 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 221, only 3 of 224 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 221, only 3 of 224 remain
  last reads before failure (of 67):
      195    4  Single   Item: 30000125/Stats/Empowerment Stats 3/StatOption 0/FloatValue = 0
      199    2  Int16    Item: 30000125/Stats/Empowerment Stats 3/StatType = 0
      201    4  Int32    Item: 30000125/Stats/Empowerment Stats 3/StatOption 1/IntegerValue = 256
      205    4  Single   Item: 30000125/Stats/Empowerment Stats 3/StatOption 1/FloatValue = 0
      209    2  Int16    Item: 30000125/Stats/Empowerment Stats 3/StatType = 0
      211    4  Int32    Item: 30000125/Stats/Empowerment Stats 3/StatOption 2/IntegerValue = 0
      215    4  Single   Item: 30000125/Stats/Empowerment Stats 3/StatOption 2/FloatValue = 0
      219    2  Int16    Item: 30000125/Stats/Empowerment Stats 3/StatType = 0

### 0x002E IN src 2521  over=122 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2521\Inbound\0x002E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 78, only 0 of 78 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 78, only 0 of 78 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 78, only 0 of 78 remain
  last reads before failure (of 18):
       34    4  Int32    2 base = 0
       38    4  Int32    2 total = 100
       42    4  Int32    3 bonus = 100
       46    4  Int32    3 base = 100
       50    4  Int32    3 total = 100
       54    8  Int64    hp bonus long = 625
       62    8  Int64    hp base long = 476741369966
       70    8  Int64    hp total long = 429496729700

### 0x003F IN src 12  over=105 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003F.py
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  last reads before failure (of 2):
        0    8  Int64    SkillCastId = 63909289302448
        8    4  Int32    OwnerObjectId = 837635

### 0x004E IN src 12  over=86 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1632 byte(s) at offset 7, only 584 of 591 remain
  ! ReadBytes: wanted 1624 byte(s) at offset 3, only 14 of 17 remain
  ! ReadBytes: wanted 1616 byte(s) at offset 3, only 14 of 17 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 38
        5    2  Int16    FunctionCubeName/size = 816

### 0x0021 IN src 12  over=82 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0021.py
  ! Read<Int32>: wanted 4 byte(s) at offset 196, only 2 of 198 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 15, only 0 of 15 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 15, only 0 of 15 remain
  last reads before failure (of 59):
      170    4  Single   Item/Item: 30000125/Stats/Empowerment Stats 2/StatOption 0/FloatValue = 0
      174    2  Int16    Item/Item: 30000125/Stats/Empowerment Stats 2/StatType = 0
      176    4  Int32    Item/Item: 30000125/Stats/Empowerment Stats 2/StatOption 1/IntegerValue = 1
      180    4  Single   Item/Item: 30000125/Stats/Empowerment Stats 2/StatOption 1/FloatValue = 0
      184    2  Int16    Item/Item: 30000125/Stats/Empowerment Stats 2/StatType = 0
      186    4  Int32    Item/Item: 30000125/Stats/Empowerment Stats 2/StatOption 2/IntegerValue = 0
      190    4  Single   Item/Item: 30000125/Stats/Empowerment Stats 2/StatOption 2/FloatValue = 0
      194    2  Int16    Item/Item: 30000125/Stats/Empowerment Stats 2/StatType = 0

### 0x001C IN src 2507  over=65 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 4051
       13    2  Int16    coord x = 0
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = 363384199966621698
       30    2  Int16    speed x = 26
