# Harness — MATRIX -> 2506

scripts from build : (matrix, see src column)
packets from build : 2506
packets considered : 114.480
packets executed   : 55.772  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              2.881   5.2%
OkExact              19.358   34.7%
UnderRead            23.203   41.6%
OverRead             10.327   18.5%
Threw                     3   0.0%

of packets a script actually ran on (52.891):
  clean (consumed exactly) : 36.6%
  over-read (WRONG)        : 19.5%
  under-read (ambiguous)   : 43.9%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12      27.536     1.500     0.0%     0.2%    99.8%    0.0%          95% / 100%
0x001C  IN        12      26.549     1.500     1.9%     0.1%    98.0%    0.0%         100% / 100%
0x001C  IN      2507      26.549     1.500    84.5%     3.8%    11.7%    0.0%         100% / 100%
0x0024  IN        12      13.416     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      13.416     1.500    98.5%     1.5%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      13.416     1.500    98.5%     1.5%     0.0%    0.0%         100% / 100%
0x0058  IN        12      10.822     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      10.822     1.500    71.3%    28.7%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      10.822     1.500    98.1%     1.9%     0.0%    0.0%         100% / 100%
0x003D  IN        12       8.181     1.500     0.1%     1.3%    98.6%    0.0%           84% / 84%
0x003D  IN      2512       8.181     1.500    98.6%     1.4%     0.0%    0.0%         100% / 100%
0x003D  IN      2520       8.181     1.500    97.3%     1.9%     0.8%    0.0%         100% / 100%
0x0011  IN        12       4.690     1.500    51.3%    48.7%     0.0%    0.0%         100% / 100%
0x0023  IN        12       3.847     1.500     2.1%     0.0%    97.9%    0.0%         100% / 100%
0x0023  IN      2486       3.847     1.500     1.5%    98.5%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       3.847     1.500     1.5%    98.5%     0.0%    0.0%           11% / 11%
0x007E  IN         -       2.694         -                                     no script
0x004E  IN        12       2.589     1.500     0.7%     2.1%    97.1%    0.0%           18% / 18%
0x000B  OUT       12       2.334     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CB  IN        12       1.575     1.500     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0021  IN        12       1.431     1.431     0.4%    99.0%     0.6%    0.0%            0% / 20%
0x0021  IN      2511       1.431     1.431     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2525       1.431     1.431     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2529       1.431     1.431     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2546       1.431     1.431     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2549       1.431     1.431     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2550       1.431     1.431     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x002E  IN        12         995       995     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521         995       995    14.4%    71.0%    14.7%    0.0%          19% / 100%
0x002E  IN      2528         995       995    85.3%    14.7%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         701       701     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0047  IN        12         692       692     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x005E  IN        12         597       597     0.0%    96.1%     3.9%    0.0%           20% / 35%
0x005E  IN      2506         597       597   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12         430       430   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         430       430   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         428       428   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -         308         -                                     no script
0x0052  IN        12         214       214     0.0%   100.0%     0.0%    0.0%            1% / 41%
0x0052  IN      2516         214       214    56.5%    43.5%     0.0%    0.0%         100% / 100%
0x0041  OUT       12         198       198     0.0%     1.5%    98.5%    0.0%           88% / 88%
0x00A8  IN         -         165         -                                     no script
0x0093  IN         -         164         -                                     no script
0x0048  IN        12         117       117     0.0%    94.9%     5.1%    0.0%           48% / 48%
0x0048  IN      2504         117       117    94.9%     5.1%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         117       117    94.9%     5.1%     0.0%    0.0%         100% / 100%
0x0020  OUT       12         116       116    84.5%     2.6%    12.9%    0.0%         100% / 100%
0x0020  OUT     2507         116       116    42.2%    57.8%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         116       116    84.5%     2.6%    12.9%    0.0%         100% / 100%
0x004F  OUT        -         106         -                                     no script
0x003C  IN        12         104       104     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         104       104     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         104       104   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         104       104   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         104       104   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          97        97     0.0%    79.4%    20.6%    0.0%            0% / 99%
0x00F6  IN      2520          97        97   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12          96        96     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512          96        96   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12          95        95     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0061  IN        12          94        94     0.0%     0.0%   100.0%    0.0%          93% / 100%
0x006C  IN        12          92        92     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12          81        81    40.7%    59.3%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          81        81    71.6%    28.4%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          81        81    25.9%    74.1%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          81        81    40.7%    59.3%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          81        81    40.7%    59.3%     0.0%    0.0%          20% / 100%
0x0017  IN        12          80        80     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          80        80     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          80        80     0.0%    97.5%     2.5%    0.0%           19% / 63%
0x0017  IN      2528          80        80     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          80        80     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006B  IN        12          73        73     0.0%    68.5%    31.5%    0.0%          46% / 100%
0x006B  IN      2507          73        73    63.0%    37.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          73        73     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          73        73    63.0%    37.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          73        73     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          73        73     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          73        73     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          73        73   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12          70        70     0.0%    67.1%    32.9%    0.0%           24% / 80%
0x001D  IN        12          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN        12          69        69     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          69        69    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2496          69        69    40.6%    59.4%     0.0%    0.0%          51% / 100%
0x0069  IN      2497          69        69    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2502          69        69    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2503          69        69     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          69        69     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546          69        69     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12          66        66     0.0%     9.1%    90.9%    0.0%           98% / 98%
0x0055  IN        12          62        62     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          62        62     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          62        62    98.4%     1.6%     0.0%    0.0%         100% / 100%
0x0128  IN        12          62        62    25.8%    74.2%     0.0%    0.0%          14% / 100%
0x011C  IN         -          58         -                                     no script
0x00CC  IN        12          56        56     0.0%    91.1%     8.9%    0.0%           20% / 50%
0x008A  IN      2511          54        54     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524          54        54    75.9%     0.0%    24.1%    0.0%         100% / 100%
0x002F  IN        12          50        50     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0063  IN        12          48        48     0.0%     8.3%    91.7%    0.0%           16% / 27%
0x0063  IN      2507          48        48    70.8%    29.2%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          48        48    70.8%    29.2%     0.0%    0.0%         100% / 100%
0x0019  IN        12          46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          46        46    50.0%    26.1%    23.9%    0.0%         100% / 100%
0x0060  IN        12          46        46     0.0%    60.9%    39.1%    0.0%           45% / 94%
0x006D  IN        12          46        46     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00F4  IN        12          46        46     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x010A  IN        12          46        46     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x0123  IN         -          43         -                                     no script
0x0033  IN        12          42        42     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0044  IN        12          42        42     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0036  IN        12          41        41     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0005  IN        12          40        40   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN        12          38        38   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C3  IN        12          38        38     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0011  OUT        -          35         -                                     no script
0x00E6  IN         -          32         -                                     no script
0x0034  OUT       12          30        30   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN        12          29        29     0.0%     0.0%   100.0%    0.0%             8% / 9%
0x0014  IN        12          28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  IN        12          28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  OUT     2511          27        27     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          27        27    85.2%    14.8%     0.0%    0.0%         100% / 100%
0x0054  IN        12          26        26     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -          26         -                                     no script
0x00A5  IN         -          26         -                                     no script
0x00EB  IN        12          26        26     0.0%     7.7%    92.3%    0.0%         100% / 100%
0x000C  OUT       12          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12          24        24     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x008E  OUT        -          24         -                                     no script
0x0001  IN        12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          23         -                                     no script
0x000F  OUT        -          23         -                                     no script
0x0010  OUT        -          23         -                                     no script
0x0015  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          23        23     4.3%    95.7%     0.0%    0.0%           62% / 62%
0x0035  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0039  OUT       12          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  IN        12          23        23     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          23        23     0.0%    52.2%    47.8%    0.0%           11% / 56%
0x007D  IN      2486          23        23     0.0%    47.8%    52.2%    0.0%         100% / 100%
0x007D  IN      2502          23        23    52.2%    47.8%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          23        23    52.2%    47.8%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          23        23    52.2%    47.8%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          23        23    52.2%    47.8%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          23        23    52.2%    47.8%     0.0%    0.0%         100% / 100%
0x0089  IN      2527          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          23         -                                     no script
0x00A7  IN        12          23        23     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          23        23     0.0%    39.1%    60.9%    0.0%         100% / 100%
0x00AD  IN         -          23         -                                     no script
0x00B0  OUT        -          23         -                                     no script
0x00B2  IN        12          23        23     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12          23        23     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          23        23     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          23         -                                     no script
0x00B7  IN        12          23        23     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          23        23     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          23         -                                     no script
0x00CA  IN        12          23        23     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -          23         -                                     no script
0x00DF  IN         -          23         -                                     no script
0x00EE  IN         -          23         -                                     no script
0x00F3  IN        12          23        23     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -          23         -                                     no script
0x011B  IN        12          23        23     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0125  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -          23         -                                     no script
0x0131  IN         -          23         -                                     no script
0x0138  IN         -          23         -                                     no script
0x005A  IN        12          18        18     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12          16        16     0.0%   100.0%     0.0%    0.0%            3% / 23%
0x004D  IN      2503          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          16        16     0.0%   100.0%     0.0%    0.0%           11% / 79%
0x004D  IN      2507          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003E  IN        12          15        15     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0053  IN        12          14        14     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x00A4  OUT       12          13        13     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0056  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00C1  IN         -          10         -                                     no script
0x0075  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529           7         7     0.0%   100.0%     0.0%    0.0%             1% / 3%
0x004F  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  IN         -           7         -                                     no script
0x0010  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0078  IN        12           5         5     0.0%     0.0%   100.0%    0.0%             0% / 0%
0x0078  IN      2506           5         5     0.0%     0.0%   100.0%    0.0%          39% / 100%
0x0079  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C2  IN         -           5         -                                     no script
0x001B  IN        12           4         4    25.0%     0.0%     0.0%   75.0%          35% / 100%
0x002C  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0042  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x004B  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507           4         4    50.0%    50.0%     0.0%    0.0%          33% / 100%
0x0066  IN        12           4         4     0.0%    25.0%    75.0%    0.0%            0% / 44%
0x006C  OUT        -           4         -                                     no script
0x00E9  IN         -           4         -                                     no script
0x00F9  IN         -           4         -                                     no script
0x0022  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0046  OUT        -           3         -                                     no script
0x005F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0066  OUT        -           3         -                                     no script
0x0069  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0023  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT     2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x003A  OUT        -           2         -                                     no script
0x0051  OUT        -           2         -                                     no script
0x0079  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           29% / 29%
0x0082  IN        12           2         2     0.0%     0.0%   100.0%    0.0%            0% / 80%
0x00A2  OUT     2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F8  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           55% / 61%
0x0103  IN         -           2         -                                     no script
0x010C  IN      2502           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0029  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x0030  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0038  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0040  OUT        -           1         -                                     no script
0x0040  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0049  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0072  OUT        -           1         -                                     no script
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.497 threw=0 negative-length=228
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -11776
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 5,0752468E+11

### 0x003D IN src 12  over=1.479 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  last reads before failure (of 3):
        0    8  Int64    SkillUseUid = 5
        8    4  Int32    ServerTick = 164075008
       12    4  Int32    ObjectId = 164075008

### 0x001C IN src 12  over=1.470 threw=0 negative-length=71
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       18    2  Int16    StateSync/PositionCoordS/Z = 45
       20    2  Int16    StateSync/Rotation = -39
       22    1  Byte     StateSync/Animation3 = 2
       23    2  Int16    StateSync/SpeedCoordS/X = 3599
       25    2  Int16    StateSync/SpeedCoordS/Y = 16
       27    2  Int16    StateSync/SpeedCoordS/Z = -12032
       29    1  Byte     StateSync/Unknown = 224
       30    2  Int16    StateSync/Rotation2 CoordS / 10 = 18

### 0x0023 IN src 12  over=1.468 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50400046/Stats/Unknown = 0
      171    4  Int32    Item: 50400046/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50400046/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50400046/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50400046/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50400046/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50400046/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50400046/ItemEnchant/CanRepackage = False

### 0x004E IN src 12  over=1.457 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 4000 byte(s) at offset 7, only 30 of 37 remain
  ! ReadBytes: wanted 47324 byte(s) at offset 11, only 22 of 33 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 17, only 0 of 17 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 2000

### 0x00B0 IN src 12  over=701 threw=0 negative-length=431
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -9212 at offset 6/20
  ! ReadBytes: negative length -4092 at offset 6/20
  ! ReadBytes: negative length -12798 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = -1876901632
        4    2  Int16    Motto/size = -4606

### 0x0047 IN src 12  over=692 threw=0 negative-length=434
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -1234 at offset 3/40
  ! ReadBytes: negative length -1234 at offset 3/40
  ! ReadBytes: negative length -9556 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -617

### 0x0041 OUT src 12  over=195 threw=0 negative-length=10
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0041.py
  ! ReadBytes: wanted 1536 byte(s) at offset 36, only 5 of 41 remain
  ! ReadBytes: wanted 1536 byte(s) at offset 36, only 5 of 41 remain
  ! ReadBytes: wanted 1536 byte(s) at offset 36, only 5 of 41 remain
  last reads before failure (of 8):
        0    1  Byte     Function = 0
        1    1  Byte     type = 56
        2    4  Int32    MountId = -2056893149
        6    4  Int32    RideOnActionUseItem+20 = 16782289
       10    8  Int64    RideOnActionUseItem+28 = 182958417004855553
       18    8  Int64    MountUid = -2882254281983327356
       26    8  Int64    CUgcItemLook/Uid = -216171489269644545
       34    2  Int16    CUgcItemLook/UUID/size = 768

### 0x001C IN src 2507  over=176 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 2101
       13    2  Int16    coord x = 0
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -369576639304040446
       30    2  Int16    speed x = 13

### 0x002E IN src 2521  over=146 threw=0
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
       54    8  Int64    hp bonus long = 1529
       62    8  Int64    hp base long = 429496729700
       70    8  Int64    hp total long = 429496729700

### 0x0061 IN src 12  over=94 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 835, only 1 of 836 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0017 IN src 12  over=80 threw=0 negative-length=11
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 5132, only 0 of 5132 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1778, only 3 of 1781 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1636, only 0 of 1636 remain
  last reads before failure (of 653):
     5068    8  Int64    PlayerInfo/Player+1B0 = 73735316197008816
     5076    8  Int64    PlayerInfo/Player+1B0 = 1099511628032
     5084    8  Int64    PlayerInfo/Player+1B0 = 0
     5092    8  Int64    PlayerInfo/Player+1B0 = 0
     5100    8  Int64    PlayerInfo/Player+1B0 = -7451306738554241024
     5108    8  Int64    PlayerInfo/Player+1B0 = 16779776
     5116    8  Int64    PlayerInfo/Player+1B0 = 414370033152
     5124    8  Int64    PlayerInfo/Player+1B0 = 16514048
