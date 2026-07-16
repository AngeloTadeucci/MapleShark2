# Harness — MATRIX -> 2504

scripts from build : (matrix, see src column)
packets from build : 2504
packets considered : 133.096
packets executed   : 45.485  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              2.069   4.5%
OkExact              13.598   29.9%
UnderRead            20.967   46.1%
OverRead              8.851   19.5%

of packets a script actually ran on (43.416):
  clean (consumed exactly) : 31.3%
  over-read (WRONG)        : 20.4%
  under-read (ambiguous)   : 48.3%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x007A  IN        12      87.216     1.500     0.0%     6.5%    93.5%    0.0%           78% / 78%
0x0047  IN        12       9.473     1.500     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x0041  OUT       12       9.231     1.500     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0058  IN        12       5.575     1.500     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0058  IN      2521       5.575     1.500     5.3%    94.7%     0.0%    0.0%           88% / 92%
0x0058  IN      2527       5.575     1.500     5.4%    94.6%     0.0%    0.0%           88% / 97%
0x0012  OUT       12       5.133     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0024  IN        12       2.743     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       2.743     1.500    89.1%    10.9%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       2.743     1.500    89.1%    10.9%     0.0%    0.0%         100% / 100%
0x002E  IN        12       1.634     1.500     0.0%   100.0%     0.0%    0.0%           10% / 26%
0x002E  IN      2521       1.634     1.500    10.8%    39.5%    49.7%    0.0%         100% / 100%
0x002E  IN      2528       1.634     1.500    51.1%    48.9%     0.1%    0.0%         100% / 100%
0x007E  IN         -       1.465         -                                     no script
0x0011  IN        12       1.390     1.390    50.9%    49.1%     0.0%    0.0%         100% / 100%
0x001C  IN        12       1.047     1.047     1.1%     0.0%    98.9%    0.0%         100% / 100%
0x001C  IN      2507       1.047     1.047    99.9%     0.0%     0.1%    0.0%         100% / 100%
0x0023  IN        12         918       918    32.2%     0.0%    67.8%    0.0%         100% / 100%
0x0023  IN      2486         918       918     2.0%    98.0%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         918       918    30.0%    70.0%     0.0%    0.0%          11% / 100%
0x000B  OUT       12         691       691   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12         526       526    17.3%     3.2%    79.5%    0.0%         100% / 100%
0x003D  IN      2512         526       526    43.9%    20.5%    35.6%    0.0%          98% / 100%
0x003D  IN      2520         526       526    63.1%    36.9%     0.0%    0.0%         100% / 100%
0x0021  IN        12         481       481     0.4%    98.8%     0.8%    0.0%           17% / 20%
0x0021  IN      2511         481       481     0.4%    99.6%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         481       481     0.4%    99.6%     0.0%    0.0%           17% / 20%
0x0021  IN      2529         481       481     0.4%    99.6%     0.0%    0.0%           17% / 20%
0x0021  IN      2546         481       481     0.4%    99.6%     0.0%    0.0%           17% / 20%
0x0021  IN      2549         481       481     0.4%    99.6%     0.0%    0.0%           17% / 20%
0x0021  IN      2550         481       481     0.4%    99.6%     0.0%    0.0%           17% / 20%
0x00B6  IN        12         410       410     0.0%    97.6%     2.4%    0.0%           24% / 36%
0x003C  IN        12         372       372     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         372       372     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         372       372   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         372       372   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         372       372   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN        12         317       317     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x0069  IN      2486         317       317     3.2%    96.8%     0.0%    0.0%             7% / 7%
0x0069  IN      2496         317       317     4.7%    95.3%     0.0%    0.0%            7% / 10%
0x0069  IN      2497         317       317     3.2%    96.8%     0.0%    0.0%             7% / 7%
0x0069  IN      2502         317       317     4.1%    95.9%     0.0%    0.0%             7% / 7%
0x0069  IN      2503         317       317     1.9%    98.1%     0.0%    0.0%             7% / 7%
0x0069  IN      2504         317       317     1.9%    98.1%     0.0%    0.0%             7% / 7%
0x0069  IN      2521         317       317   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546         317       317     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x0069  IN      2549         317       317   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550         317       317   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12         307       307     0.0%    97.1%     2.9%    0.0%           26% / 35%
0x005E  IN      2506         307       307   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12         273       273     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x003E  IN        12         272       272     0.0%    99.3%     0.7%    0.0%             1% / 1%
0x0079  IN        12         233       233     0.0%     0.0%   100.0%    0.0%           10% / 29%
0x0020  OUT       12         199       199    99.5%     0.5%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507         199       199    38.2%    61.8%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         199       199    99.5%     0.5%     0.0%    0.0%         100% / 100%
0x0006  IN        12         141       141   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         141       141   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         141       141   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12         114       114    14.9%     1.8%    83.3%    0.0%          18% / 100%
0x0033  IN        12         101       101     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0068  IN        12          91        91     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0068  IN      2486          91        91   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12          90        90     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0014  IN        12          89        89   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  IN        12          85        85     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x005D  IN        12          85        85     0.0%     0.0%   100.0%    0.0%           73% / 73%
0x00A3  IN         -          85         -                                     no script
0x00A6  IN        12          85        85     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0055  IN        12          84        84     0.0%    98.8%     1.2%    0.0%             1% / 1%
0x0055  IN      2521          84        84     0.0%   100.0%     0.0%    0.0%           72% / 99%
0x0055  IN      2528          84        84    44.0%    56.0%     0.0%    0.0%          73% / 100%
0x0037  IN        12          69        69     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0056  IN        12          67        67     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0052  IN        12          65        65     0.0%   100.0%     0.0%    0.0%            1% / 20%
0x0052  IN      2516          65        65    58.5%    41.5%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          63         -                                     no script
0x004D  IN        12          52        52     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          52        52     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0093  IN         -          51         -                                     no script
0x0080  OUT        -          50         -                                     no script
0x00F6  IN        12          48        48     0.0%    79.2%    20.8%    0.0%           0% / 100%
0x00F6  IN      2520          48        48   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN        12          46        46     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530          46        46     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002B  IN      2531          46        46     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002C  IN        12          46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          43        43   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN        12          43        43     0.0%    65.1%    34.9%    0.0%          48% / 100%
0x0048  IN      2504          43        43    65.1%    34.9%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          43        43    65.1%    34.9%     0.0%    0.0%         100% / 100%
0x005F  IN        12          37        37     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x006A  IN        12          37        37    35.1%    64.9%     0.0%    0.0%          50% / 100%
0x006A  IN      2486          37        37    73.0%    27.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          37        37    27.0%    73.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          37        37    45.9%    54.1%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          37        37    45.9%    54.1%     0.0%    0.0%          20% / 100%
0x006C  IN        12          37        37     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0075  IN        12          37        37     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529          37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          34         -                                     no script
0x004C  IN        12          29        29     0.0%    55.2%    44.8%    0.0%           2% / 100%
0x004C  IN      2512          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12          29        29     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006B  IN        12          28        28     0.0%    67.9%    32.1%    0.0%          46% / 100%
0x006B  IN      2507          28        28    67.9%    32.1%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          28        28    67.9%    32.1%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          28        28     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12          27        27     0.0%     0.0%   100.0%    0.0%          94% / 100%
0x00CC  IN        12          27        27     0.0%    85.2%    14.8%    0.0%           20% / 50%
0x0128  IN        12          27        27    25.9%    74.1%     0.0%    0.0%          14% / 100%
0x0045  IN        12          26        26     0.0%    11.5%    88.5%    0.0%           98% / 98%
0x006C  OUT        -          25         -                                     no script
0x006F  IN        12          24        24     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0094  IN         -          22         -                                     no script
0x0017  IN        12          19        19     0.0%     0.0%   100.0%    0.0%          54% / 100%
0x0017  IN      2500          19        19     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          19        19     0.0%   100.0%     0.0%    0.0%            9% / 66%
0x0017  IN      2528          19        19     0.0%     0.0%   100.0%    0.0%          54% / 100%
0x0017  IN      2550          19        19     0.0%     0.0%   100.0%    0.0%          54% / 100%
0x001E  IN        12          19        19     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x011C  IN         -          19         -                                     no script
0x0019  IN        12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          18        18    50.0%    11.1%    38.9%    0.0%         100% / 100%
0x006D  IN        12          18        18     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12          18        18     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x003A  OUT        -          17         -                                     no script
0x0090  OUT     2504          17        17    47.1%    52.9%     0.0%    0.0%          80% / 100%
0x002D  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0044  IN        12          16        16     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0005  IN        12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008A  IN      2511          15        15     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          15        15    80.0%     6.7%    13.3%    0.0%         100% / 100%
0x00EB  IN        12          15        15     0.0%    13.3%    86.7%    0.0%         100% / 100%
0x0037  OUT       12          14        14    92.9%     7.1%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502          14        14     7.1%    92.9%     0.0%    0.0%           20% / 73%
0x0090  IN         -          14         -                                     no script
0x008E  OUT        -          13         -                                     no script
0x0026  OUT       12          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00E6  IN         -          12         -                                     no script
0x00F4  IN        12          12        12     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x00CB  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             3% / 4%
0x000F  OUT        -          10         -                                     no script
0x0010  OUT        -          10         -                                     no script
0x0016  IN        12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0034  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12          10        10     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511          10        10     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -          10         -                                     no script
0x0063  IN        12          10        10     0.0%    50.0%    50.0%    0.0%           27% / 27%
0x0063  IN      2507          10        10     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0063  IN      2518          10        10     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0066  IN        12          10        10    20.0%    50.0%    30.0%    0.0%           6% / 100%
0x0073  IN        12          10        10     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          10        10     0.0%    50.0%    50.0%    0.0%            2% / 56%
0x007D  IN      2486          10        10    20.0%    50.0%    30.0%    0.0%          73% / 100%
0x007D  IN      2502          10        10    30.0%    70.0%     0.0%    0.0%          72% / 100%
0x007D  IN      2503          10        10    30.0%    70.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          10        10    30.0%    70.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          10        10    30.0%    70.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          10        10    30.0%    70.0%     0.0%    0.0%         100% / 100%
0x00A2  IN         -          10         -                                     no script
0x00A5  IN         -          10         -                                     no script
0x00CA  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           10% / 20%
0x00D1  IN         -          10         -                                     no script
0x00F3  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           20% / 20%
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
0x0089  IN      2527           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           9         -                                     no script
0x00A7  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           9         -                                     no script
0x00B0  OUT        -           9         -                                     no script
0x00B2  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           9         9     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           9         -                                     no script
0x00B7  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           9         -                                     no script
0x00DF  IN         -           9         -                                     no script
0x00EA  IN        12           9         9     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00EA  IN      2504           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EA  IN      2507           9         9     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00EE  IN         -           9         -                                     no script
0x0110  IN         -           9         -                                     no script
0x0125  IN        12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           9         -                                     no script
0x0131  IN         -           9         -                                     no script
0x0137  IN         -           9         -                                     no script
0x0138  IN         -           9         -                                     no script
0x0060  IN        12           7         7     0.0%    85.7%    14.3%    0.0%           54% / 80%
0x0011  OUT        -           6         -                                     no script
0x0018  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  OUT       12           6         6     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0036  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006E  IN      2486           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             4% / 5%
0x005A  IN      2490           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0123  IN         -           4         -                                     no script
0x001C  OUT        -           3         -                                     no script
0x004B  OUT       12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0010  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x000D  OUT        -           1         -                                     no script
0x002B  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0042  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0057  OUT        -           1         -                                     no script
0x0061  OUT        -           1         -                                     no script
0x0066  OUT        -           1         -                                     no script
0x0072  OUT        -           1         -                                     no script
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00A4  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00C1  IN         -           1         -                                     no script
0x00C3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x00D6  IN         -           1         -                                     no script
0x00F0  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x00FB  IN         -           1         -                                     no script
0x00FF  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=297
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: wanted 59626 byte(s) at offset 39, only 2 of 41 remain
  ! ReadBytes: negative length -2 at offset 35/41
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 23040
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 0
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 512
       28    1  Byte     Segment 0/StateSync/Unknown = 8
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 1543
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = 29813

### 0x0047 IN src 12  over=1.500 threw=0 negative-length=1.500
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -29730 at offset 3/36
  ! ReadBytes: negative length -29468 at offset 3/36
  ! ReadBytes: negative length -29738 at offset 3/36
  last reads before failure (of 2):
        0    1  Byte     function = 2
        1    2  Int16    message/size = -14865

### 0x007A IN src 12  over=1.402 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x007A.py
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  last reads before failure (of 4):
        0    8  Int64    CharacterId = 4906673997365888495
        8    1  Boolean  Bool = True
        9    8  Int64    Unknown = 6488005944190695973
       17    8  Int64    CharacterId = 506672555298390016

### 0x001C IN src 12  over=1.036 threw=0 negative-length=76
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! ReadBytes: negative length -8160 at offset 30/32
  ! ReadBytes: negative length -8160 at offset 30/32
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 0
       19    2  Int16    StateSync/SpeedCoordS/Y = 11264
       21    2  Int16    StateSync/SpeedCoordS/Z = 4097
       23    1  Byte     StateSync/Unknown = 0
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = -26112
       26    2  Int16    StateSync/CoordS / 1000 = 0
       28    2  Int16    StateSync/AnimationString?/size = -4080

### 0x002E IN src 2521  over=745 threw=0
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
       54    8  Int64    hp bonus long = 9827
       62    8  Int64    hp base long = 429496729703
       70    8  Int64    hp total long = 429496729700

### 0x0023 IN src 12  over=622 threw=0
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

### 0x003D IN src 12  over=418 threw=0 negative-length=2
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Boolean>: wanted 1 byte(s) at offset 56, only 0 of 56 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  last reads before failure (of 17):
       29    4  Single   DirectionCoordF/X = -2,4496607E+19
       33    4  Single   DirectionCoordF/Y = 2,524E-42
       37    4  Single   DirectionCoordF/Z = 1,6346718E-38
       41    4  Single   RotationCoordF/X = -1,9503403E+18
       45    4  Single   RotationCoordF/Y = -516,0156
       49    4  Single   RotationCoordF/Z = -1,8737616E+38
       53    2  Int16    CoordS / 10 = -1
       55    1  Boolean  Unknown = True

### 0x002F IN src 12  over=273 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 14538648
        4    1  Byte     Function = 1

### 0x0079 IN src 12  over=233 threw=0 negative-length=49
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0079.py
  ! ReadBytes: wanted 12288 byte(s) at offset 2, only 19 of 21 remain
  ! ReadBytes: wanted 23552 byte(s) at offset 2, only 19 of 21 remain
  ! ReadBytes: wanted 27904 byte(s) at offset 2, only 19 of 21 remain
  last reads before failure (of 1):
        0    2  Int16    EntityId/size = 12288

### 0x003D IN src 2512  over=187 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2512\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 40, only 1 of 41 remain
  last reads before failure (of 14):
       20    1  Byte     AttackPoint = 0
       21    2  Int16    ImpactPositionCoordS/X = -282
       23    2  Int16    ImpactPositionCoordS/Y = -615
       25    2  Int16    ImpactPositionCoordS/Z = 901
       27    4  Single   ImpactDirectionCoordF/X = -8,742278E-08
       31    4  Single   ImpactDirectionCoordF/Y = 1
       35    4  Single   ImpactDirectionCoordF/Z = -0
       39    1  Byte     Unknown = 0

### 0x004E IN src 12  over=95 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 6200 byte(s) at offset 7, only 2012 of 2019 remain
  ! ReadBytes: wanted 10000 byte(s) at offset 3, only 8 of 11 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 11, only 0 of 11 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 141
        5    2  Int16    FunctionCubeName/size = 3100

### 0x00B0 IN src 12  over=90 threw=0 negative-length=90
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -63486 at offset 6/20
  ! ReadBytes: negative length -43518 at offset 6/20
  ! ReadBytes: negative length -22014 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593039360
        4    2  Int16    Motto/size = -31743
