# Harness — MATRIX -> 2492

scripts from build : (matrix, see src column)
packets from build : 2492
packets considered : 26.600
packets executed   : 23.627  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              1.643   7.0%
OkExact              10.495   44.4%
UnderRead             8.275   35.0%
OverRead              3.212   13.6%
Threw                     2   0.0%

of packets a script actually ran on (21.984):
  clean (consumed exactly) : 47.7%
  over-read (WRONG)        : 14.6%
  under-read (ambiguous)   : 37.6%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      10.078     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      10.078     1.500    64.7%    35.3%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      10.078     1.500    97.3%     2.7%     0.0%    0.0%         100% / 100%
0x0012  OUT       12       6.925     1.500     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0024  IN        12       2.308     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       2.308     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       2.308     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -       1.349         -                                     no script
0x0041  OUT       12       1.181     1.181     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x001C  IN        12         742       742   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN      2507         742       742    27.8%     0.0%    72.2%    0.0%          95% / 100%
0x0011  IN        12         677       677    51.1%    48.9%     0.0%    0.0%         100% / 100%
0x0023  IN        12         405       405     3.7%     0.0%    96.3%    0.0%           99% / 99%
0x0023  IN      2486         405       405     2.5%    97.5%     0.0%    0.0%           16% / 16%
0x0023  IN      2502         405       405     2.5%    97.5%     0.0%    0.0%           10% / 10%
0x000B  OUT       12         336       336   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12         309       309     1.3%    96.8%     1.9%    0.0%           17% / 20%
0x0021  IN      2511         309       309     0.0%    98.7%     1.3%    0.0%            8% / 20%
0x0021  IN      2525         309       309     0.0%    99.0%     1.0%    0.0%            8% / 20%
0x0021  IN      2529         309       309     0.0%    99.0%     1.0%    0.0%            8% / 20%
0x0021  IN      2546         309       309     0.0%    99.0%     1.0%    0.0%            8% / 20%
0x0021  IN      2549         309       309     0.0%    99.0%     1.0%    0.0%            8% / 20%
0x0021  IN      2550         309       309     0.0%    99.0%     1.0%    0.0%            8% / 20%
0x0055  IN        12         221       221     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         221       221     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         221       221    99.5%     0.0%     0.5%    0.0%         100% / 100%
0x005E  IN        12         210       210     0.0%    97.6%     2.4%    0.0%           26% / 35%
0x005E  IN      2506         210       210   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12         172       172     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0048  IN        12         143       143     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504         143       143   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         143       143   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0056  IN        12         115       115     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002E  IN        12          92        92     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521          92        92    30.4%    66.3%     3.3%    0.0%          32% / 100%
0x002E  IN      2528          92        92    98.9%     1.1%     0.0%    0.0%         100% / 100%
0x003D  IN        12          69        69     0.0%     1.4%    98.6%    0.0%           84% / 95%
0x003D  IN      2512          69        69    97.1%     1.4%     1.4%    0.0%         100% / 100%
0x003D  IN      2520          69        69    76.8%    23.2%     0.0%    0.0%         100% / 100%
0x0006  IN        12          65        65   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          65        65   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          65        65   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN        12          54        54     0.0%    98.1%     1.9%    0.0%            6% / 33%
0x0051  IN      2537          54        54    33.3%     0.0%    66.7%    0.0%         100% / 100%
0x0051  IN      2546          54        54    33.3%     0.0%    66.7%    0.0%         100% / 100%
0x0051  IN      2549          54        54    33.3%     0.0%    66.7%    0.0%         100% / 100%
0x0051  IN      2550          54        54    33.3%     0.0%    66.7%    0.0%         100% / 100%
0x0052  IN        12          38        38     0.0%   100.0%     0.0%    0.0%            1% / 20%
0x0052  IN      2516          38        38    55.3%    42.1%     2.6%    0.0%         100% / 100%
0x00A8  IN         -          38         -                                     no script
0x0080  OUT        -          34         -                                     no script
0x0093  IN         -          30         -                                     no script
0x0020  OUT       12          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507          29        29    41.4%    58.6%     0.0%    0.0%          99% / 100%
0x0020  OUT     2512          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12          25        25    24.0%    76.0%     0.0%    0.0%           3% / 100%
0x006A  IN      2486          25        25    72.0%    28.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          25        25    16.0%    84.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          25        25    32.0%    68.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          25        25    32.0%    68.0%     0.0%    0.0%          20% / 100%
0x0037  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0063  IN        12          22        22     0.0%     0.0%   100.0%    0.0%           16% / 29%
0x0063  IN      2507          22        22    59.1%    40.9%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          22        22    59.1%    40.9%     0.0%    0.0%         100% / 100%
0x006C  IN        12          22        22     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0128  IN        12          21        21    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0017  IN        12          19        19     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          19        19     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          19        19     0.0%   100.0%     0.0%    0.0%           22% / 42%
0x0017  IN      2528          19        19     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          19        19     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0045  IN        12          19        19     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12          19        19     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          19        19    36.8%    63.2%     0.0%    0.0%          20% / 100%
0x0069  IN      2496          19        19    36.8%    63.2%     0.0%    0.0%          76% / 100%
0x0069  IN      2497          19        19    36.8%    63.2%     0.0%    0.0%          20% / 100%
0x0069  IN      2502          19        19    36.8%    63.2%     0.0%    0.0%          20% / 100%
0x0069  IN      2503          19        19     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          19        19     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546          19        19     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011C  IN         -          19         -                                     no script
0x006B  IN        12          17        17     0.0%    70.6%    29.4%    0.0%          11% / 100%
0x006B  IN      2507          17        17    64.7%    29.4%     5.9%    0.0%         100% / 100%
0x006B  IN      2511          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2524          17        17    64.7%    29.4%     5.9%    0.0%         100% / 100%
0x006B  IN      2525          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2546          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2549          17        17     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2550          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12          17        17     0.0%    82.4%    17.6%    0.0%           20% / 50%
0x001D  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  OUT       12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008A  IN      2511          15        15     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524          15        15    86.7%     0.0%     0.0%   13.3%         100% / 100%
0x00B6  IN        12          15        15     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0061  IN        12          14        14     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x00F6  IN        12          13        13     0.0%    92.3%     7.7%    0.0%             0% / 0%
0x00F6  IN      2520          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN        12          12        12     0.0%     0.0%   100.0%    0.0%           93% / 99%
0x002B  IN      2530          12        12    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x002B  IN      2531          12        12    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0044  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0034  OUT       12          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          10        10    50.0%    20.0%    30.0%    0.0%         100% / 100%
0x002C  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12          10        10    40.0%    60.0%     0.0%    0.0%          53% / 100%
0x003C  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506          10        10     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          10         -                                     no script
0x006D  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x0123  IN         -          10         -                                     no script
0x012D  IN         -          10         -                                     no script
0x0011  OUT        -           9         -                                     no script
0x001C  OUT        -           9         -                                     no script
0x0033  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x004C  IN        12           9         9     0.0%    55.6%    44.4%    0.0%           2% / 100%
0x004C  IN      2512           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -           9         -                                     no script
0x005A  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0039  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x004B  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507           8         8     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x004E  IN        12           8         8    62.5%     0.0%    37.5%    0.0%         100% / 100%
0x00CB  IN        12           8         8     0.0%   100.0%     0.0%    0.0%            2% / 35%
0x000F  OUT        -           7         -                                     no script
0x0010  OUT        -           7         -                                     no script
0x0014  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           7         7     0.0%    57.1%    42.9%    0.0%           11% / 56%
0x007D  IN      2486           7         7    14.3%     0.0%    85.7%    0.0%         100% / 100%
0x007D  IN      2502           7         7    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           7         7    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           7         7    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           7         7    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           7         7    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           7         -                                     no script
0x00CA  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -           7         -                                     no script
0x00EB  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F3  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x004D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            1% / 21%
0x004D  IN      2503           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           6         6     0.0%   100.0%     0.0%    0.0%            9% / 79%
0x004D  IN      2507           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005B  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0094  IN         -           6         -                                     no script
0x00A5  IN         -           6         -                                     no script
0x00E6  IN         -           6         -                                     no script
0x0001  IN        12           5         5    60.0%    40.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           5         -                                     no script
0x0013  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           5         5     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x006F  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0089  IN      2527           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           5         -                                     no script
0x00A7  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           5         5     0.0%    20.0%    80.0%    0.0%         100% / 100%
0x00AD  IN         -           5         -                                     no script
0x00B0  OUT        -           5         -                                     no script
0x00B2  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           5         5     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           5         -                                     no script
0x00B7  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           5         5     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           5         -                                     no script
0x00DF  IN         -           5         -                                     no script
0x00EE  IN         -           5         -                                     no script
0x00F4  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           5         -                                     no script
0x0125  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           5         -                                     no script
0x0131  IN         -           5         -                                     no script
0x0026  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0028  OUT       12           3         3     0.0%   100.0%     0.0%    0.0%             8% / 8%
0x004F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x004F  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0136  IN         -           3         -                                     no script
0x0031  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x003F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x006C  OUT        -           2         -                                     no script
0x0071  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0079  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00CD  IN        12           2         2     0.0%     0.0%   100.0%    0.0%          77% / 100%
0x010E  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x000D  OUT        -           1         -                                     no script
0x001D  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             7% / 7%
0x0040  OUT        -           1         -                                     no script
0x0065  OUT        -           1         -                                     no script
0x0066  OUT        -           1         -                                     no script
0x0079  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             3% / 3%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0090  IN         -           1         -                                     no script
0x0092  OUT        -           1         -                                     no script
0x00A1  IN         -           1         -                                     no script
0x00A4  IN         -           1         -                                     no script
0x00D6  IN         -           1         -                                     no script
0x0103  IN         -           1         -                                     no script
0x0109  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           97% / 97%

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
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2249
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 8
       33    4  Int32    Segment 0/StateSync/Unknown = 921857
       37    4  Int32    Segment 0/ClientTicks = 597618368

### 0x001C IN src 2507  over=536 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 36, only 2 of 38 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = -17924
       13    2  Int16    coord x = 17931
       15    2  Int16    coord y = 2309
       17    2  Int16    coord z = 90
       19    2  Int16    rotation = 45
       21    1  Byte     animation3 = 217
       22    8  Int64    2x float = -361975497111502081
       30    2  Int16    speed x = 19

### 0x0023 IN src 12  over=390 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  last reads before failure (of 63):
      180    8  Int64    Item: 50100000/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100000/ItemEnchant/Unknown = 16777216
      192    4  Int32    Item: 50100000/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100000/ItemEnchant/CanRepackage = False
      197    4  Int32    Item: 50100000/ItemEnchant/EnchantCharges = 0
      201    1  Byte     Item: 50100000/ItemEnchant/EnchantStats/EnchantStatCount = 0
      202    4  Int32    Item: 50100000/LimitBreak/LimitBreakLevel = 0
      206    4  Int32    Item: 50100000/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x0047 IN src 12  over=172 threw=0 negative-length=104
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -31836 at offset 3/40
  ! ReadBytes: negative length -31836 at offset 3/40
  ! ReadBytes: negative length -31836 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -15918

### 0x0056 IN src 12  over=115 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 29889

### 0x003D IN src 12  over=68 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Single>: wanted 4 byte(s) at offset 37, only 2 of 39 remain
  ! Read<Single>: wanted 4 byte(s) at offset 37, only 2 of 39 remain
  ! Read<Single>: wanted 4 byte(s) at offset 37, only 2 of 39 remain
  last reads before failure (of 11):
       16    4  Int32    SkillId = 33280918
       20    2  Int16    SkillLevel = 9728
       22    1  Byte     MotionPoint = 233
       23    2  Int16    PositionCoordS/X = 5250
       25    2  Int16    PositionCoordS/Y = 2250
       27    2  Int16    PositionCoordS/Z = -2959
       29    4  Single   DirectionCoordF/X = 1,8615713E-11
       33    4  Single   DirectionCoordF/Y = -1,3987655E-35

### 0x0051 IN src 2537  over=36 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2537\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  last reads before failure (of 89):
      249    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      253    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      255    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      259    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      261    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      265    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      267    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      271    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0051 IN src 2546  over=36 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2546\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  last reads before failure (of 89):
      249    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      253    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      255    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      259    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      261    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      265    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      267    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      271    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0051 IN src 2549  over=36 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2549\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  last reads before failure (of 89):
      249    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      253    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      255    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      259    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      261    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      265    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      267    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      271    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0051 IN src 2550  over=36 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0051.py
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  ! Read<Single>: wanted 4 byte(s) at offset 273, only 1 of 274 remain
  last reads before failure (of 89):
      249    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 4/Value = 2,3509887E-38
      253    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      255    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 5/Value = 0
      259    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      261    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 6/Value = 0
      265    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0
      267    4  Single   Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/SpecialOption 7/Value = 0
      271    2  Int16    Item 0/Item: 39000035/LimitBreak/LimitBreakSpecialOption/StatType = 0

### 0x0063 IN src 12  over=22 threw=0 negative-length=9
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 25290 byte(s) at offset 27, only 158 of 185 remain
  ! ReadBytes: wanted 25194 byte(s) at offset 12, only 30 of 42 remain
  ! ReadBytes: wanted 24774 byte(s) at offset 7, only 30 of 37 remain
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 4049017677421740037
        9    8  Int64    Entry/CharacterId = 7378648129965929264
       17    8  Int64    Entry/AccountId = 3846748294536771123
       25    2  Int16    Entry/Name/size = 12645

### 0x0017 IN src 12  over=19 threw=0 negative-length=4
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 51200 byte(s) at offset 991, only 4419 of 5410 remain
  ! ReadBytes: negative length -10694 at offset 1631/6273
  ! ReadBytes: wanted 53900 byte(s) at offset 2647, only 2851 of 5498 remain
  last reads before failure (of 221):
      958    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = -2147466484
      962    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 17377
      970    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = 2522015791327477760
      978    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
      979    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 7782220156096217121
      987    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = 0
      989    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/UUID = 
      989    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/size = 25600
