# Harness — MATRIX -> 2489

scripts from build : (matrix, see src column)
packets from build : 2489
packets considered : 26.626
packets executed   : 20.682  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                723   3.5%
OkExact               8.681   42.0%
UnderRead             8.220   39.7%
OverRead              3.053   14.8%
Threw                     5   0.0%

of packets a script actually ran on (19.959):
  clean (consumed exactly) : 43.5%
  over-read (WRONG)        : 15.3%
  under-read (ambiguous)   : 41.2%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      13.222     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      13.222     1.500    59.5%    40.5%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      13.222     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12       6.614     1.500     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0011  IN        12         903       903    51.3%    48.7%     0.0%    0.0%         100% / 100%
0x002E  IN        12         567       567     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521         567       567    36.5%    61.9%     1.6%    0.0%          32% / 100%
0x002E  IN      2528         567       567   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12         474       474   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507         474       474    49.6%    50.4%     0.0%    0.0%          99% / 100%
0x0020  OUT     2512         474       474   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         447       447   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -         372         -                                     no script
0x0047  IN        12         367       367     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0024  IN        12         344       344   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         344       344   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         344       344   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  OUT       12         343       343     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x0021  IN        12         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2511         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         317       317     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x003D  IN        12         239       239     0.0%     1.3%    98.7%    0.0%           96% / 98%
0x003D  IN      2512         239       239    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         239       239    48.5%    25.5%    25.9%    0.0%         100% / 100%
0x00B0  IN        12         180       180     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x003C  IN        12         168       168     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         168       168     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         168       168   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         168       168   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         168       168   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12         166       166     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         166       166     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         166       166   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12          84        84   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          84        84   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          84        84   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  OUT       12          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN        12          78        78     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x0051  IN      2537          78        78     2.6%     0.0%    97.4%    0.0%         100% / 100%
0x0051  IN      2546          78        78     2.6%     0.0%    97.4%    0.0%         100% / 100%
0x0051  IN      2549          78        78     2.6%     0.0%    97.4%    0.0%         100% / 100%
0x0051  IN      2550          78        78     2.6%     0.0%    97.4%    0.0%         100% / 100%
0x005E  IN        12          77        77     0.0%    89.6%    10.4%    0.0%           26% / 35%
0x005E  IN      2506          77        77   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12          74        74     0.0%    98.6%     1.4%    0.0%           48% / 48%
0x0048  IN      2504          74        74    98.6%     1.4%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          74        74    98.6%     1.4%     0.0%    0.0%         100% / 100%
0x0075  IN        12          72        72     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529          72        72   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          56         -                                     no script
0x0023  IN        12          48        48    50.0%     0.0%    50.0%    0.0%          99% / 100%
0x0023  IN      2486          48        48    33.3%    66.7%     0.0%    0.0%          16% / 100%
0x0023  IN      2502          48        48    33.3%    66.7%     0.0%    0.0%          10% / 100%
0x0052  IN        12          47        47     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0052  IN      2516          47        47    48.9%    51.1%     0.0%    0.0%          20% / 100%
0x0063  IN        12          44        44     0.0%     0.0%   100.0%    0.0%           16% / 50%
0x0063  IN      2507          44        44    65.9%    34.1%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          44        44    65.9%    34.1%     0.0%    0.0%         100% / 100%
0x0093  IN         -          39         -                                     no script
0x0056  IN        12          37        37     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004E  IN        12          36        36     2.8%     0.0%    97.2%    0.0%           27% / 70%
0x008A  IN      2511          34        34     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x008A  IN      2524          34        34    85.3%     0.0%     0.0%   14.7%         100% / 100%
0x006C  IN        12          32        32     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12          31        31     6.5%    93.5%     0.0%    0.0%            8% / 33%
0x006A  IN      2486          31        31    74.2%    25.8%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          31        31    19.4%    80.6%     0.0%    0.0%           3% / 100%
0x006A  IN      2502          31        31    41.9%    58.1%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          31        31    41.9%    58.1%     0.0%    0.0%          20% / 100%
0x0069  IN        12          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          24        24    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496          24        24    33.3%    66.7%     0.0%    0.0%          82% / 100%
0x0069  IN      2497          24        24    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502          24        24    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546          24        24     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12          24        24     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507          24        24    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          24        24     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          24        24    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          24        24     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          24        24     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          24        24     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          24        24     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0128  IN        12          23        23    30.4%    69.6%     0.0%    0.0%          14% / 100%
0x002F  IN        12          22        22     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004F  OUT        -          22         -                                     no script
0x0045  IN        12          21        21     0.0%    14.3%    85.7%    0.0%           98% / 98%
0x0061  IN        12          21        21     0.0%     0.0%   100.0%    0.0%            0% / 99%
0x00CC  IN        12          19        19     0.0%    94.7%     5.3%    0.0%           20% / 50%
0x0005  IN        12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011C  IN         -          17         -                                     no script
0x0019  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          16        16    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0044  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004C  IN        12          16        16     0.0%    62.5%    37.5%    0.0%           2% / 100%
0x004C  IN      2512          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12          16        16     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00A5  IN         -          16         -                                     no script
0x010A  IN        12          16        16     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x012D  IN         -          16         -                                     no script
0x0080  OUT        -          14         -                                     no script
0x00F4  IN        12          14        14     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0014  IN        12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0017  IN        12          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          10        10     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          10        10     0.0%   100.0%     0.0%    0.0%           41% / 48%
0x0017  IN      2528          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001C  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN      2507          10        10     0.0%   100.0%     0.0%    0.0%           64% / 64%
0x0034  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -          10         -                                     no script
0x00E6  IN         -          10         -                                     no script
0x000C  OUT       12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0001  IN        12           8         8    62.5%    37.5%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           8         -                                     no script
0x000F  OUT        -           8         -                                     no script
0x0010  OUT        -           8         -                                     no script
0x0015  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN        12           8         8     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530           8         8    37.5%     0.0%    62.5%    0.0%          99% / 100%
0x002B  IN      2531           8         8    37.5%     0.0%    62.5%    0.0%          99% / 100%
0x0033  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0035  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           8         8     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           8         8     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0066  OUT        -           8         -                                     no script
0x0066  IN        12           8         8     0.0%    37.5%    62.5%    0.0%            0% / 44%
0x006F  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           8         8     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           8         8     0.0%    87.5%    12.5%    0.0%           11% / 56%
0x007D  IN      2486           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
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
0x00CB  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00D1  IN         -           8         -                                     no script
0x00DF  IN         -           8         -                                     no script
0x00EB  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           8         -                                     no script
0x00F3  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           8         -                                     no script
0x011B  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           8         -                                     no script
0x0131  IN         -           8         -                                     no script
0x000D  OUT        -           7         -                                     no script
0x000F  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x004D  IN      2503           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           6         6     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x004D  IN      2507           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0136  IN         -           5         -                                     no script
0x0037  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x005A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0082  OUT       12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           3         -                                     no script
0x00F1  IN         -           3         -                                     no script
0x001D  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  OUT       12           2         2    50.0%    50.0%     0.0%    0.0%          17% / 100%
0x0031  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0040  OUT        -           2         -                                     no script
0x004F  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0065  OUT        -           2         -                                     no script
0x006E  IN      2486           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0079  IN        12           2         2     0.0%     0.0%   100.0%    0.0%            3% / 12%
0x0079  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0021  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0042  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x005B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x005F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A1  IN         -           1         -                                     no script
0x00F2  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 90
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 45
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -40
       28    1  Byte     Segment 0/StateSync/Unknown = 2
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2699
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 4
       33    4  Int32    Segment 0/StateSync/Unknown = 652069
       37    4  Int32    Segment 0/ClientTicks = 352525928

### 0x0047 IN src 12  over=367 threw=0 negative-length=360
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -12044 at offset 3/40
  ! ReadBytes: negative length -12044 at offset 3/40
  ! ReadBytes: negative length -12044 at offset 3/13
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -6022

### 0x003D IN src 12  over=236 threw=0 negative-length=5
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  last reads before failure (of 3):
        0    8  Int64    SkillUseUid = 5
        8    4  Int32    ServerTick = 8203008
       12    4  Int32    ObjectId = 8203008

### 0x00B0 IN src 12  over=180 threw=0 negative-length=180
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -22014 at offset 6/20
  ! ReadBytes: negative length -63486 at offset 6/20
  ! ReadBytes: negative length -43518 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037568
        4    2  Int16    Motto/size = -11007

### 0x0051 IN src 2537  over=76 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2537\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 276, only 1 of 277 remain
  ! Read<Single>: wanted 4 byte(s) at offset 324, only 2 of 326 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 316, only 0 of 316 remain
  last reads before failure (of 89):
      252    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      256    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      258    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      262    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      264    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      268    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      274    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0051 IN src 2546  over=76 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2546\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 276, only 1 of 277 remain
  ! Read<Single>: wanted 4 byte(s) at offset 324, only 2 of 326 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 316, only 0 of 316 remain
  last reads before failure (of 89):
      252    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      256    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      258    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      262    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      264    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      268    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      274    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0051 IN src 2549  over=76 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2549\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 276, only 1 of 277 remain
  ! Read<Single>: wanted 4 byte(s) at offset 324, only 2 of 326 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 316, only 0 of 316 remain
  last reads before failure (of 89):
      252    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      256    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      258    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      262    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      264    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      268    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      274    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0051 IN src 2550  over=76 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 276, only 1 of 277 remain
  ! Read<Single>: wanted 4 byte(s) at offset 324, only 2 of 326 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 316, only 0 of 316 remain
  last reads before failure (of 89):
      252    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      256    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      258    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      262    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      264    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      268    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0
      270    4  Single   Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      274    2  Int16    Item 0/Item: 50600159/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x003D IN src 2520  over=62 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2520\Inbound\0x003D.py
  ! Read<Byte>: wanted 1 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 42, only 0 of 42 remain
  last reads before failure (of 14):
       19    4  Int32    target object id = 8251514
       23    1  Byte     ? = 0
       24    2  Int16    coord/x = -900
       26    2  Int16    coord/y = 450
       28    2  Int16    coord/z = 2850
       30    4  Single   velocity/x = -0,9999778
       34    4  Single   velocity/y = 0
       38    4  Single   velocity/z = 0,0066665187

### 0x0063 IN src 12  over=44 threw=0 negative-length=24
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 25192 byte(s) at offset 27, only 842 of 869 remain
  ! ReadBytes: negative length -45136 at offset 27/167
  ! ReadBytes: negative length -45136 at offset 27/167
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 7077125476874977304
        9    8  Int64    Entry/CharacterId = 3546356241711511346
       17    8  Int64    Entry/AccountId = 4051094737450710114
       25    2  Int16    Entry/Name/size = 12596

### 0x0056 IN src 12  over=37 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 30084

### 0x004E IN src 12  over=35 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 3 of 10 remain
  ! ReadBytes: wanted 1200 byte(s) at offset 7, only 13 of 20 remain
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 3 of 10 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 1
        5    2  Int16    FunctionCubeName/size = 601
