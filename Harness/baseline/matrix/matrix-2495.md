# Harness — MATRIX -> 2495

scripts from build : (matrix, see src column)
packets from build : 2495
packets considered : 40.793
packets executed   : 46.282  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              1.700   3.7%
OkExact              17.888   38.7%
UnderRead            18.817   40.7%
OverRead              7.876   17.0%
Threw                     1   0.0%

of packets a script actually ran on (44.582):
  clean (consumed exactly) : 40.1%
  over-read (WRONG)        : 17.7%
  under-read (ambiguous)   : 42.2%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      12.111     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521      12.111     1.500    44.2%    55.8%     0.0%    0.0%          97% / 100%
0x0058  IN      2527      12.111     1.500    96.3%     3.7%     0.0%    0.0%         100% / 100%
0x0012  OUT       12       8.316     1.500     0.1%     0.1%    99.9%    0.0%          95% / 100%
0x0024  IN        12       3.239     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       3.239     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       3.239     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN        12       1.956     1.500     0.0%    13.9%    86.1%    0.0%         100% / 100%
0x001C  IN      2507       1.956     1.500     7.1%    90.9%     2.0%    0.0%           76% / 76%
0x003D  IN        12       1.798     1.500     0.0%     0.0%   100.0%    0.0%           84% / 84%
0x003D  IN      2512       1.798     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520       1.798     1.500    89.8%     9.7%     0.5%    0.0%         100% / 100%
0x002E  IN        12       1.226     1.226     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521       1.226     1.226    15.6%    79.4%     5.0%    0.0%          19% / 100%
0x002E  IN      2528       1.226     1.226    98.0%     1.2%     0.8%    0.0%         100% / 100%
0x0011  IN        12       1.157     1.157    51.0%    49.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12       1.101     1.101     0.0%    99.2%     0.8%    0.0%           16% / 26%
0x005E  IN      2506       1.101     1.101   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12       1.035     1.035     2.6%     0.0%    97.4%    0.0%           99% / 99%
0x0023  IN      2486       1.035     1.035     1.7%    98.3%     0.0%    0.0%           16% / 16%
0x0023  IN      2502       1.035     1.035     1.7%    98.3%     0.0%    0.0%           10% / 10%
0x0047  IN        12         826       826     0.0%     0.0%   100.0%    0.0%           23% / 23%
0x0021  IN        12         763       763     6.4%    90.3%     3.3%    0.0%            0% / 20%
0x0021  IN      2511         763       763     0.0%    98.7%     1.3%    0.0%            0% / 20%
0x0021  IN      2525         763       763     0.0%    98.7%     1.3%    0.0%            0% / 20%
0x0021  IN      2529         763       763     0.0%    98.7%     1.3%    0.0%            0% / 20%
0x0021  IN      2546         763       763     0.0%    98.7%     1.3%    0.0%            0% / 20%
0x0021  IN      2549         763       763     0.0%    98.7%     1.3%    0.0%            0% / 20%
0x0021  IN      2550         763       763     0.0%    98.7%     1.3%    0.0%            0% / 20%
0x007E  IN         -         632         -                                     no script
0x0020  OUT       12         590       590   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507         590       590    31.4%    68.6%     0.0%    0.0%          99% / 100%
0x0020  OUT     2512         590       590   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         574       574   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  OUT       12         487       487     0.0%    60.0%    40.0%    0.0%            7% / 88%
0x002B  IN        12         351       351     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530         351       351    48.1%     0.0%    51.9%    0.0%          99% / 100%
0x002B  IN      2531         351       351    48.1%     0.0%    51.9%    0.0%          99% / 100%
0x002D  IN        12         346       346    48.8%    51.2%     0.0%    0.0%          56% / 100%
0x002C  IN        12         345       345   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  OUT        -         290         -                                     no script
0x0055  IN        12         262       262     0.0%    99.2%     0.8%    0.0%             1% / 1%
0x0055  IN      2521         262       262     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         262       262    99.6%     0.0%     0.4%    0.0%         100% / 100%
0x0056  IN        12         207       207     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x003C  IN        12         201       201     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         201       201     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         201       201   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         201       201   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         201       201   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12         200       200     0.0%    95.5%     4.5%    0.0%             5% / 5%
0x011C  IN         -         196         -                                     no script
0x0037  IN        12         193       193     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x0094  IN         -         162         -                                     no script
0x0039  IN        12         160       160     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0006  IN        12         133       133   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         133       133   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         133       133   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          87        87     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          87        87    67.8%    31.0%     1.1%    0.0%         100% / 100%
0x0075  IN        12          84        84     0.0%    91.7%     8.3%    0.0%             2% / 2%
0x0075  IN      2529          84        84   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          63         -                                     no script
0x004C  IN        12          53        53     0.0%    67.9%    32.1%    0.0%           2% / 100%
0x004C  IN      2512          53        53   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12          53        53     0.0%     3.8%    96.2%    0.0%           19% / 29%
0x0063  IN      2507          53        53     9.4%    90.6%     0.0%    0.0%             3% / 3%
0x0063  IN      2518          53        53     9.4%    90.6%     0.0%    0.0%             3% / 3%
0x0093  IN         -          50         -                                     no script
0x004E  IN        12          47        47    12.8%     0.0%    87.2%    0.0%          18% / 100%
0x001D  OUT       12          42        42   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12          37        37     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0048  IN        12          35        35     0.0%    85.7%    14.3%    0.0%           48% / 90%
0x0048  IN      2504          35        35    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          35        35    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x006A  IN        12          34        34    41.2%    58.8%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          34        34    70.6%    29.4%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          34        34    29.4%    70.6%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          34        34    41.2%    58.8%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          34        34    41.2%    58.8%     0.0%    0.0%          20% / 100%
0x0061  IN        12          30        30     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x00F6  IN        12          30        30     0.0%    90.0%    10.0%    0.0%             0% / 0%
0x00F6  IN      2520          30        30   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12          29        29     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12          29        29     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          29        29    34.5%    65.5%     0.0%    0.0%          20% / 100%
0x0069  IN      2496          29        29    48.3%    51.7%     0.0%    0.0%          57% / 100%
0x0069  IN      2497          29        29    34.5%    65.5%     0.0%    0.0%          20% / 100%
0x0069  IN      2502          29        29    34.5%    65.5%     0.0%    0.0%          20% / 100%
0x0069  IN      2503          29        29     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          29        29     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546          29        29     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          29        29     0.0%    62.1%    37.9%    0.0%           24% / 80%
0x006B  IN        12          28        28     0.0%    67.9%    32.1%    0.0%          46% / 100%
0x006B  IN      2507          28        28    67.9%    32.1%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          28        28    67.9%    32.1%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -          28         -                                     no script
0x0026  OUT       12          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0128  IN        12          27        27    25.9%    74.1%     0.0%    0.0%          14% / 100%
0x004F  OUT        -          24         -                                     no script
0x0103  IN         -          22         -                                     no script
0x001A  IN        12          21        21    57.1%    33.3%     9.5%    0.0%         100% / 100%
0x003F  IN        12          20        20     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12          20        20     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0044  IN        12          19        19     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0123  IN         -          19         -                                     no script
0x0019  IN        12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN        12          18        18     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          18        18     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x00C4  IN         -          17         -                                     no script
0x002F  IN        12          16        16     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  OUT       12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12          14        14     0.0%     0.0%   100.0%    0.0%          41% / 100%
0x0017  IN      2500          14        14     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          14        14     0.0%   100.0%     0.0%    0.0%           10% / 52%
0x0017  IN      2528          14        14     0.0%     0.0%   100.0%    0.0%          41% / 100%
0x0017  IN      2550          14        14     0.0%     0.0%   100.0%    0.0%          41% / 100%
0x008A  IN      2511          14        14     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x008A  IN      2524          14        14    78.6%     0.0%    21.4%    0.0%         100% / 100%
0x0005  IN        12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  OUT       12          12        12     0.0%   100.0%     0.0%    0.0%            5% / 10%
0x004D  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           21% / 23%
0x004D  IN      2503          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          12        12     0.0%   100.0%     0.0%    0.0%           77% / 79%
0x004D  IN      2507          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CB  IN        12          11        11     0.0%   100.0%     0.0%    0.0%            5% / 19%
0x00E6  IN         -          11         -                                     no script
0x000F  OUT        -          10         -                                     no script
0x0010  OUT        -          10         -                                     no script
0x0016  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0035  IN        12          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511          10        10     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -          10         -                                     no script
0x0073  IN        12          10        10     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          10        10     0.0%    40.0%    60.0%    0.0%           56% / 56%
0x007D  IN      2486          10        10     0.0%    20.0%    80.0%    0.0%         100% / 100%
0x007D  IN      2502          10        10    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          10        10    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          10        10    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          10        10    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          10        10    80.0%    20.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -          10         -                                     no script
0x00CA  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -          10         -                                     no script
0x00EB  IN        12          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F3  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0001  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           9         -                                     no script
0x0013  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x006F  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0071  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0089  IN      2527           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           9         -                                     no script
0x00A5  IN         -           9         -                                     no script
0x00A7  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           9         9     0.0%    33.3%    66.7%    0.0%         100% / 100%
0x00AD  IN         -           9         -                                     no script
0x00B0  OUT        -           9         -                                     no script
0x00B2  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x00B3  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           9         9     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           9         -                                     no script
0x00B7  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00DF  IN         -           9         -                                     no script
0x00EE  IN         -           9         -                                     no script
0x00F4  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           9         -                                     no script
0x0125  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           9         -                                     no script
0x0131  IN         -           9         -                                     no script
0x0136  IN         -           9         -                                     no script
0x0040  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0022  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  OUT        -           6         -                                     no script
0x0109  IN        12           6         6     0.0%    66.7%    33.3%    0.0%           93% / 97%
0x0021  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  OUT        -           4         -                                     no script
0x00CD  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0100  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           3% / 100%
0x0011  OUT        -           3         -                                     no script
0x001E  IN        12           3         3     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x005B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0075  OUT       12           3         3     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0079  IN        12           3         3     0.0%    33.3%    66.7%    0.0%           29% / 43%
0x00A4  IN         -           3         -                                     no script
0x00B0  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x00C8  IN         -           3         -                                     no script
0x00C9  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          15% / 100%
0x010E  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0016  OUT        -           2         -                                     no script
0x0018  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x006E  IN      2486           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0076  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%            4% / 11%
0x00A4  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00FF  IN         -           2         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001B  IN        12           1         1     0.0%     0.0%     0.0%  100.0%           19% / 19%
0x0025  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             6% / 6%
0x0026  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0057  OUT        -           1         -                                     no script
0x0060  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           47% / 47%
0x0066  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x006C  OUT        -           1         -                                     no script
0x0090  IN         -           1         -                                     no script
0x00F0  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x00FB  IN         -           1         -                                     no script
0x011F  IN         -           1         -                                     no script

## Sample failures

### 0x003D IN src 12  over=1.500 threw=0 negative-length=22
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! ReadBytes: wanted 15360 byte(s) at offset 63, only 49 of 112 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  last reads before failure (of 20):
       41    4  Single   RotationCoordF/X = 0,02278615
       45    4  Single   RotationCoordF/Y = -0,00012207405
       49    4  Single   RotationCoordF/Z = NaN
       53    2  Int16    CoordS / 10 = -1
       55    1  Boolean  Unknown = True
       56    1  Boolean  Unknown = True
       57    4  Int32    Unknown = 16858298
       61    2  Int16    Unknown/size = 7680

### 0x0012 OUT src 12  over=1.498 threw=0 negative-length=217
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int16>: wanted 2 byte(s) at offset 51, only 0 of 51 remain
  ! ReadBytes: wanted 46440 byte(s) at offset 41, only 0 of 41 remain
  ! ReadBytes: negative length -21508 at offset 35/41
  last reads before failure (of 23):
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 16
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4359
       34    1  Byte     Segment 0/StateSync/Unknown = 219
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 1220
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = -9436
       39    4  Single   Segment 0/StateSync/UnknownCoordF/X = 9,3545E-41
       43    4  Single   Segment 0/StateSync/UnknownCoordF/Y = NaN
       47    4  Single   Segment 0/StateSync/UnknownCoordF/Z = 2,5554854E+16

### 0x001C IN src 12  over=1.291 threw=0 negative-length=334
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 767
       23    1  Byte     StateSync/Unknown = 84
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 14086
       26    2  Int16    StateSync/CoordS / 1000 = 1
       28    4  Int32    StateSync/Unknown = 1495013

### 0x0023 IN src 12  over=1.008 threw=0
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

### 0x0047 IN src 12  over=826 threw=0 negative-length=456
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 60490 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 60490 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 60490 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 30245

### 0x002B IN src 12  over=351 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 238, only 2 of 240 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 238, only 2 of 240 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 238, only 2 of 240 remain
  last reads before failure (of 72):
      211    1  Byte     Item: 33000103/ItemEnchant/EnchantBasedChargeExp = 0
      212    8  Int64    Item: 33000103/ItemEnchant/Unknown = 281474976710656
      220    4  Int32    Item: 33000103/ItemEnchant/Unknown = 0
      224    4  Int32    Item: 33000103/ItemEnchant/Unknown = 0
      228    1  Boolean  Item: 33000103/ItemEnchant/CanRepackage = False
      229    4  Int32    Item: 33000103/ItemEnchant/EnchantCharges = 0
      233    1  Byte     Item: 33000103/ItemEnchant/EnchantStats/EnchantStatCount = 0
      234    4  Int32    Item: 33000103/LimitBreak/LimitBreakLevel = 0

### 0x0056 IN src 12  over=207 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 27096

### 0x0041 OUT src 12  over=195 threw=0 negative-length=6
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0041.py
  ! ReadBytes: wanted 6638 byte(s) at offset 36, only 5 of 41 remain
  ! ReadBytes: wanted 6638 byte(s) at offset 36, only 5 of 41 remain
  ! ReadBytes: wanted 6638 byte(s) at offset 36, only 5 of 41 remain
  last reads before failure (of 8):
        0    1  Byte     Function = 0
        1    1  Byte     type = 107
        2    4  Int32    MountId = 1714872838
        6    4  Int32    RideOnActionUseItem+20 = 16780213
       10    8  Int64    RideOnActionUseItem+28 = 562944159421956353
       18    8  Int64    MountUid = -2882254281983328256
       26    8  Int64    CUgcItemLook/Uid = -648517044966259969
       34    2  Int16    CUgcItemLook/UUID/size = 3319

### 0x002B IN src 2530  over=182 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2530\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 237, only 3 of 240 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 237, only 3 of 240 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 237, only 3 of 240 remain
  last reads before failure (of 71):
      207    8  Int64    Item: 33000103/ItemEnchant/Unknown = 0
      215    4  Int32    Item: 33000103/ItemEnchant/Unknown = 16777216
      219    4  Int32    Item: 33000103/ItemEnchant/Unknown = 0
      223    1  Boolean  Item: 33000103/ItemEnchant/CanRepackage = False
      224    4  Int32    Item: 33000103/ItemEnchant/EnchantCharges = 0
      228    1  Byte     Item: 33000103/ItemEnchant/EnchantStats/EnchantStatCount = 0
      229    4  Int32    Item: 33000103/LimitBreak/LimitBreakLevel = 0
      233    4  Int32    Item: 33000103/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x002B IN src 2531  over=182 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2531\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 237, only 3 of 240 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 237, only 3 of 240 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 237, only 3 of 240 remain
  last reads before failure (of 71):
      207    8  Int64    Item: 33000103/ItemEnchant/Unknown = 0
      215    4  Int32    Item: 33000103/ItemEnchant/Unknown = 16777216
      219    4  Int32    Item: 33000103/ItemEnchant/Unknown = 0
      223    1  Boolean  Item: 33000103/ItemEnchant/CanRepackage = False
      224    4  Int32    Item: 33000103/ItemEnchant/EnchantCharges = 0
      228    1  Byte     Item: 33000103/ItemEnchant/EnchantStats/EnchantStatCount = 0
      229    4  Int32    Item: 33000103/LimitBreak/LimitBreakLevel = 0
      233    4  Int32    Item: 33000103/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x002E IN src 2521  over=61 threw=0
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
       54    8  Int64    hp bonus long = 16340
       62    8  Int64    hp base long = 450971566191
       70    8  Int64    hp total long = 429496729700

### 0x0063 IN src 12  over=51 threw=0 negative-length=4
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 50790 byte(s) at offset 27, only 3966 of 3993 remain
  ! ReadBytes: wanted 26730 byte(s) at offset 27, only 3970 of 3997 remain
  ! ReadBytes: wanted 52336 byte(s) at offset 27, only 3334 of 3361 remain
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 7221522139927543908
        9    8  Int64    Entry/CharacterId = 3847025387794150755
       17    8  Int64    Entry/AccountId = 7149519801586824241
       25    2  Int16    Entry/Name/size = 25395
