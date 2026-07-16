# Harness — MATRIX -> 2496

scripts from build : (matrix, see src column)
packets from build : 2496
packets considered : 35.544
packets executed   : 26.056  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                767   2.9%
OkExact              12.215   46.9%
UnderRead             7.868   30.2%
OverRead              5.206   20.0%

of packets a script actually ran on (25.289):
  clean (consumed exactly) : 48.3%
  over-read (WRONG)        : 20.6%
  under-read (ambiguous)   : 31.1%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      16.260     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      16.260     1.500    68.1%    31.9%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      16.260     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12       8.910     1.500     0.0%     0.3%    99.7%    0.0%          95% / 100%
0x0024  IN        12       2.067     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       2.067     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       2.067     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN        12       1.644     1.500     1.8%     0.0%    98.2%    0.0%         100% / 100%
0x001C  IN      2507       1.644     1.500    52.4%     0.2%    47.4%    0.0%         100% / 100%
0x0011  IN        12       1.559     1.500    50.7%    49.3%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         777       777   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12         397       397     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521         397       397    24.9%    71.3%     3.8%    0.0%          32% / 100%
0x002E  IN      2528         397       397    99.0%     1.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -         352         -                                     no script
0x0021  IN        12         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2511         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         329       329     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0047  IN        12         208       208     0.0%     0.0%   100.0%    0.0%           23% / 23%
0x0006  IN        12         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12         174       174     0.0%    96.0%     4.0%    0.0%           20% / 26%
0x005E  IN      2506         174       174   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12         166       166     0.0%    99.4%     0.6%    0.0%             1% / 1%
0x0055  IN      2521         166       166     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         166       166   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         152       152     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0023  IN        12         148       148    14.2%     0.0%    85.8%    0.0%          99% / 100%
0x0023  IN      2486         148       148     9.5%    90.5%     0.0%    0.0%           16% / 20%
0x0023  IN      2502         148       148     9.5%    90.5%     0.0%    0.0%           10% / 20%
0x003D  IN        12         135       135     0.0%    11.1%    88.9%    0.0%           95% / 95%
0x003D  IN      2512         135       135    88.9%    11.1%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         135       135    22.2%    75.6%     2.2%    0.0%           3% / 100%
0x0051  IN        12         128       128     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0051  IN      2537         128       128     4.7%     0.0%    95.3%    0.0%         100% / 100%
0x0051  IN      2546         128       128     4.7%     0.0%    95.3%    0.0%         100% / 100%
0x0051  IN      2549         128       128     4.7%     0.0%    95.3%    0.0%         100% / 100%
0x0051  IN      2550         128       128     4.7%     0.0%    95.3%    0.0%         100% / 100%
0x0056  IN        12         123       123     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0020  OUT       12         106       106   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507         106       106    35.8%    64.2%     0.0%    0.0%          99% / 100%
0x0020  OUT     2512         106       106   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -          78         -                                     no script
0x0093  IN         -          62         -                                     no script
0x003C  IN        12          59        59     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506          59        59     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507          59        59   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512          59        59   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520          59        59   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12          49        49     0.0%    98.0%     2.0%    0.0%           48% / 48%
0x0048  IN      2504          49        49    98.0%     2.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          49        49    98.0%     2.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          49         -                                     no script
0x00A8  IN         -          49         -                                     no script
0x0052  IN        12          45        45     0.0%   100.0%     0.0%    0.0%           11% / 20%
0x0052  IN      2516          45        45    53.3%    46.7%     0.0%    0.0%         100% / 100%
0x0037  IN        12          36        36     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0021  OUT       12          34        34   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12          33        33     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x006C  IN        12          28        28     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0069  IN        12          27        27     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2486          27        27    25.9%    74.1%     0.0%    0.0%          20% / 100%
0x0069  IN      2496          27        27    48.1%    51.9%     0.0%    0.0%          57% / 100%
0x0069  IN      2497          27        27    25.9%    74.1%     0.0%    0.0%          20% / 100%
0x0069  IN      2502          27        27    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503          27        27     3.7%    92.6%     3.7%    0.0%            3% / 20%
0x0069  IN      2504          27        27     3.7%    92.6%     3.7%    0.0%            3% / 20%
0x0069  IN      2521          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546          27        27     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2549          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12          26        26     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12          26        26    19.2%    80.8%     0.0%    0.0%          11% / 100%
0x006A  IN      2486          26        26    73.1%    26.9%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          26        26    23.1%    76.9%     0.0%    0.0%          10% / 100%
0x006A  IN      2502          26        26    42.3%    57.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          26        26    42.3%    57.7%     0.0%    0.0%          20% / 100%
0x001D  IN        12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0053  IN        12          23        23     0.0%    95.7%     4.3%    0.0%             2% / 5%
0x0061  IN        12          23        23     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006B  IN        12          21        21     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507          21        21    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          21        21    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          21        21     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          21        21     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x00CC  IN        12          21        21     0.0%    85.7%    14.3%    0.0%           20% / 50%
0x0128  IN        12          21        21    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0045  IN        12          19        19     0.0%    15.8%    84.2%    0.0%           98% / 98%
0x0063  IN        12          18        18     0.0%     0.0%   100.0%    0.0%           16% / 50%
0x0063  IN      2507          18        18    55.6%    44.4%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          18        18    55.6%    44.4%     0.0%    0.0%         100% / 100%
0x0075  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          14        14    50.0%    14.3%    35.7%    0.0%         100% / 100%
0x006D  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          14         -                                     no script
0x0005  IN        12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  OUT       12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  IN        12          13        13     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x006E  IN      2486          13        13    23.1%    69.2%     7.7%    0.0%           3% / 100%
0x0044  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00F4  IN        12          12        12     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x00F6  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             0% / 7%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          11        11     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          11        11     0.0%   100.0%     0.0%    0.0%           18% / 56%
0x0017  IN      2528          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x008A  IN      2511          11        11     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          11        11    81.8%     0.0%    18.2%    0.0%         100% / 100%
0x00E6  IN         -          11         -                                     no script
0x0055  OUT        -          10         -                                     no script
0x0036  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x000C  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x00A5  IN         -           8         -                                     no script
0x0001  IN        12           7         7    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           7         -                                     no script
0x000F  OUT        -           7         -                                     no script
0x0010  OUT        -           7         -                                     no script
0x0014  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12           7         7    42.9%     0.0%    57.1%    0.0%          47% / 100%
0x0054  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x006F  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           7         7     0.0%    57.1%    42.9%    0.0%          56% / 100%
0x007D  IN      2486           7         7    28.6%     0.0%    71.4%    0.0%         100% / 100%
0x007D  IN      2502           7         7    71.4%    28.6%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           7         7    71.4%    28.6%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           7         7    71.4%    28.6%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           7         7    71.4%    28.6%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           7         7    71.4%    28.6%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           7         -                                     no script
0x009E  IN         -           7         -                                     no script
0x00A7  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           7         -                                     no script
0x00B0  OUT        -           7         -                                     no script
0x00B2  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             2% / 3%
0x00B3  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           7         -                                     no script
0x00B7  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           7         -                                     no script
0x00CA  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             6% / 8%
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
0x0011  OUT        -           6         -                                     no script
0x0065  OUT        -           6         -                                     no script
0x0137  IN         -           6         -                                     no script
0x005A  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 2%
0x004F  IN      2507           4         4    50.0%     0.0%    50.0%    0.0%          16% / 100%
0x001E  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002C  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A1  IN         -           3         -                                     no script
0x00C1  IN         -           3         -                                     no script
0x004B  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x004D  IN      2503           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           2         2     0.0%   100.0%     0.0%    0.0%            9% / 11%
0x004D  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0068  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0109  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           98% / 98%
0x0123  IN         -           2         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2531           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002C  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           69% / 69%
0x003B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           50% / 50%
0x0042  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x005B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0066  OUT        -           1         -                                     no script
0x0078  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           96% / 96%
0x0078  IN      2506           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0095  OUT     2520           1         1     0.0%   100.0%     0.0%    0.0%           69% / 69%
0x00A4  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00D6  IN         -           1         -                                     no script
0x011F  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.495 threw=0 negative-length=175
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: wanted 23256 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 21):
       27    1  Byte     Segment 0/StateSync/Animation3 = 2
       28    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 1799
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 5
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -1536
       34    1  Byte     Segment 0/StateSync/Unknown = 11
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 10
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = -6685
       39    2  Int16    Segment 0/StateSync/AnimationString?/size = 11628

### 0x001C IN src 12  over=1.473 threw=0 negative-length=10
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 767
       23    1  Byte     StateSync/Unknown = 68
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 11532
       26    2  Int16    StateSync/CoordS / 1000 = 1
       28    4  Int32    StateSync/Unknown = 2891275

### 0x001C IN src 2507  over=711 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 6751
       13    2  Int16    coord x = 3140
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = 2164824050932401154
       30    2  Int16    speed x = 44

### 0x0047 IN src 12  over=208 threw=0 negative-length=142
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 57784 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 57784 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 57784 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 28892

### 0x00B0 IN src 12  over=152 threw=0 negative-length=120
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: wanted 10244 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 12292 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: negative length -20478 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = -1876876032
        4    2  Int16    Motto/size = 5122

### 0x0023 IN src 12  over=127 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  last reads before failure (of 63):
      180    8  Int64    Item: 50100013/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100013/ItemEnchant/Unknown = 16777216
      192    4  Int32    Item: 50100013/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100013/ItemEnchant/CanRepackage = False
      197    4  Int32    Item: 50100013/ItemEnchant/EnchantCharges = 0
      201    1  Byte     Item: 50100013/ItemEnchant/EnchantStats/EnchantStatCount = 0
      202    4  Int32    Item: 50100013/LimitBreak/LimitBreakLevel = 0
      206    4  Int32    Item: 50100013/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x0056 IN src 12  over=123 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 6113587

### 0x0051 IN src 2537  over=122 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2537\Inbound\0x0051.py
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 344, only 0 of 344 remain
  last reads before failure (of 90):
      268    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 7,2E-43
      274    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      276    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      280    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      282    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      286    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      288    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 8/Value = 0

### 0x0051 IN src 2546  over=122 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2546\Inbound\0x0051.py
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 344, only 0 of 344 remain
  last reads before failure (of 90):
      268    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 7,2E-43
      274    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      276    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      280    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      282    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      286    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      288    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 8/Value = 0

### 0x0051 IN src 2549  over=122 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2549\Inbound\0x0051.py
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 344, only 0 of 344 remain
  last reads before failure (of 90):
      268    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 7,2E-43
      274    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      276    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      280    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      282    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      286    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      288    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 8/Value = 0

### 0x0051 IN src 2550  over=122 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0051.py
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 292, only 0 of 292 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 344, only 0 of 344 remain
  last reads before failure (of 90):
      268    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 7,2E-43
      274    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      276    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      280    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      282    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      286    2  Int16    Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/StatType = 0
      288    4  Single   Item 0/Item: 11220512/LimitBreak/LimitBreakSpecialOption/SpecialOption 8/Value = 0

### 0x003D IN src 12  over=120 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Single>: wanted 4 byte(s) at offset 45, only 2 of 47 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  last reads before failure (of 3):
        0    8  Int64    SkillUseUid = 5
        8    4  Int32    ServerTick = 3137536
       12    4  Int32    ObjectId = 3137536
