# Harness — MATRIX -> 2512

scripts from build : (matrix, see src column)
packets from build : 2512
packets considered : 926.106
packets executed   : 141.391  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              9.861   7.0%
OkExact              53.142   37.6%
UnderRead            54.894   38.8%
OverRead             23.435   16.6%
Threw                    59   0.0%

of packets a script actually ran on (131.530):
  clean (consumed exactly) : 40.4%
  over-read (WRONG)        : 17.8%
  under-read (ambiguous)   : 41.7%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12     290.409     1.500     0.3%     0.7%    99.0%    0.0%          95% / 100%
0x0058  IN        12     260.666     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521     260.666     1.500    37.0%    63.0%     0.0%    0.0%          97% / 100%
0x0058  IN      2527     260.666     1.500    89.2%    10.7%     0.1%    0.0%         100% / 100%
0x002E  IN        12      92.055     1.500     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521      92.055     1.500    13.5%    82.7%     3.9%    0.0%          19% / 100%
0x002E  IN      2528      92.055     1.500    99.9%     0.0%     0.1%    0.0%         100% / 100%
0x003D  IN        12      33.477     1.500     0.0%     7.1%    92.9%    0.0%          96% / 100%
0x003D  IN      2512      33.477     1.500    79.8%    18.8%     1.4%    0.0%         100% / 100%
0x003D  IN      2520      33.477     1.500    56.0%    40.7%     3.3%    0.0%         100% / 100%
0x007E  IN         -      27.589         -                                     no script
0x0047  IN        12      23.013     1.500     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0020  OUT       12      22.108     1.500    93.9%     6.1%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507      22.108     1.500    37.3%    62.7%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512      22.108     1.500    93.9%     6.1%     0.0%    0.0%         100% / 100%
0x0011  IN        12      20.853     1.500    51.5%    48.5%     0.0%    0.0%         100% / 100%
0x005E  IN        12      14.833     1.500     0.0%    99.7%     0.3%    0.0%           20% / 35%
0x005E  IN      2506      14.833     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12      12.031     1.500     0.0%    51.9%    48.1%    0.0%           2% / 100%
0x004C  IN      2512      12.031     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN        12      11.022     1.500     0.7%     0.7%    98.6%    0.0%         100% / 100%
0x001C  IN      2507      11.022     1.500    63.6%    28.8%     7.6%    0.0%         100% / 100%
0x000B  OUT       12      10.404     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12      10.099     1.500     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529      10.099     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12       9.004     1.500     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506       9.004     1.500     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507       9.004     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512       9.004     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520       9.004     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN        12       8.898     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       8.898     1.500    99.9%     0.1%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       8.898     1.500    99.9%     0.1%     0.0%    0.0%         100% / 100%
0x0055  IN        12       7.504     1.500     0.0%    99.5%     0.5%    0.0%             1% / 1%
0x0055  IN      2521       7.504     1.500     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528       7.504     1.500    99.5%     0.2%     0.3%    0.0%         100% / 100%
0x0056  IN        12       4.999     1.500     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0026  OUT       12       3.681     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12       3.586     1.500     6.3%     0.3%    93.5%    0.0%           18% / 47%
0x0080  OUT        -       3.512         -                                     no script
0x002B  IN        12       3.327     1.500     0.0%     0.0%   100.0%    0.0%           93% / 99%
0x002B  IN      2530       3.327     1.500    52.3%     0.0%    47.7%    0.0%         100% / 100%
0x002B  IN      2531       3.327     1.500    52.3%     0.0%    47.7%    0.0%         100% / 100%
0x0021  IN        12       3.263     1.500    12.3%    76.0%    11.7%    0.0%          20% / 100%
0x0021  IN      2511       3.263     1.500     0.8%    95.7%     2.9%    0.6%           17% / 20%
0x0021  IN      2525       3.263     1.500     3.7%    95.7%     0.0%    0.6%           17% / 20%
0x0021  IN      2529       3.263     1.500     3.7%    95.7%     0.0%    0.6%           17% / 20%
0x0021  IN      2546       3.263     1.500     3.7%    95.7%     0.0%    0.6%           17% / 20%
0x0021  IN      2549       3.263     1.500     3.7%    95.7%     0.0%    0.6%           17% / 20%
0x0021  IN      2550       3.263     1.500     3.7%    95.7%     0.0%    0.6%           17% / 20%
0x002C  IN        12       3.218     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12       2.618     1.500    45.9%    54.1%     0.0%    0.0%          53% / 100%
0x0006  IN        12       2.553     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486       2.553     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486       2.548     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  OUT       12       2.241     1.500     0.0%   100.0%     0.0%    0.0%            2% / 35%
0x0045  IN        12       1.977     1.500     0.0%     3.0%    97.0%    0.0%           86% / 98%
0x011C  IN         -       1.842         -                                     no script
0x0037  IN        12       1.781     1.500     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x0052  IN        12       1.717     1.500     0.1%    93.3%     6.7%    0.0%            8% / 85%
0x0052  IN      2516       1.717     1.500    17.7%    43.1%    39.3%    0.0%         100% / 100%
0x0099  OUT        -       1.662         -                                     no script
0x0023  IN        12       1.511     1.500    10.4%     0.0%    89.6%    0.0%         100% / 100%
0x0023  IN      2486       1.511     1.500     6.7%    93.3%     0.0%    0.0%           17% / 20%
0x0023  IN      2502       1.511     1.500     6.7%    93.3%     0.0%    0.0%           11% / 20%
0x001C  OUT        -       1.463         -                                     no script
0x0039  IN        12       1.446     1.446     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0022  OUT       12       1.167     1.167   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  OUT       12       1.110     1.110   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  IN        12       1.081     1.081     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507       1.081     1.081    12.0%    88.0%     0.0%    0.0%           6% / 100%
0x00B0  IN        12       1.026     1.026     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0048  IN        12         996       996     0.0%    97.1%     2.9%    0.0%           48% / 48%
0x0048  IN      2504         996       996    97.1%     2.9%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         996       996    97.1%     2.9%     0.0%    0.0%         100% / 100%
0x0063  IN        12         993       993     0.0%    12.5%    87.5%    0.0%           16% / 50%
0x0063  IN      2507         993       993    51.1%    48.9%     0.0%    0.0%         100% / 100%
0x0063  IN      2518         993       993    51.1%    48.9%     0.0%    0.0%         100% / 100%
0x008A  IN      2511         799       799     0.0%   100.0%     0.0%    0.0%             1% / 8%
0x008A  IN      2524         799       799    82.7%    14.6%     2.6%    0.0%         100% / 100%
0x00CC  IN        12         738       738     0.0%    96.1%     3.9%    0.0%            5% / 40%
0x003F  IN        12         615       615     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12         604       604     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0021  OUT       12         589       589   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12         569       569     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0034  OUT       12         528       528   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  IN        12         492       492    36.4%    28.5%    35.2%    0.0%           6% / 100%
0x006A  IN        12         477       477    58.7%    41.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2486         477       477    66.9%    33.1%     0.0%    0.0%         100% / 100%
0x006A  IN      2500         477       477    33.1%    66.9%     0.0%    0.0%          20% / 100%
0x006A  IN      2502         477       477    33.8%    66.2%     0.0%    0.0%          20% / 100%
0x006A  IN      2503         477       477    33.8%    66.2%     0.0%    0.0%          20% / 100%
0x0128  IN        12         443       443    28.7%    71.3%     0.0%    0.0%          14% / 100%
0x0069  IN        12         410       410     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2486         410       410     0.0%    61.5%    38.5%    0.0%           20% / 47%
0x0069  IN      2496         410       410     4.9%    56.6%    38.5%    0.0%           43% / 82%
0x0069  IN      2497         410       410     0.0%    61.5%    38.5%    0.0%           20% / 47%
0x0069  IN      2502         410       410     1.7%    59.8%    38.5%    0.0%           20% / 47%
0x0069  IN      2503         410       410     0.2%    99.8%     0.0%    0.0%            3% / 20%
0x0069  IN      2504         410       410     0.2%    99.8%     0.0%    0.0%            3% / 20%
0x0069  IN      2521         410       410    61.5%     0.0%    38.5%    0.0%         100% / 100%
0x0069  IN      2546         410       410     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0069  IN      2549         410       410    61.5%     0.0%    38.5%    0.0%         100% / 100%
0x0069  IN      2550         410       410    61.5%     0.0%    38.5%    0.0%         100% / 100%
0x00A8  IN         -         389         -                                     no script
0x00F6  IN        12         385       385     0.0%    97.7%     2.3%    0.0%             0% / 4%
0x00F6  IN      2520         385       385   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12         344       344     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  IN        12         314       314     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x006B  IN        12         263       263     0.0%    80.2%    19.8%    0.0%          46% / 100%
0x006B  IN      2507         263       263    79.8%    20.2%     0.0%    0.0%         100% / 100%
0x006B  IN      2511         263       263     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524         263       263    79.8%    20.2%     0.0%    0.0%         100% / 100%
0x006B  IN      2525         263       263     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546         263       263     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549         263       263     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550         263       263   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12         261       261   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0053  IN        12         255       255     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0029  OUT       12         215       215    86.0%     4.2%     9.8%    0.0%         100% / 100%
0x0044  IN        12         215       215     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0031  OUT       12         204       204     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0033  IN        12         193       193     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0017  IN        12         189       189     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500         189       189     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503         189       189     0.0%    98.4%     1.6%    0.0%           45% / 84%
0x0017  IN      2528         189       189     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550         189       189     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0014  IN        12         182       182   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  IN        12         178       178     0.0%   100.0%     0.0%    0.0%             0% / 2%
0x004F  IN      2507         178       178    68.0%     0.0%    32.0%    0.0%         100% / 100%
0x0036  IN        12         174       174     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x00EB  IN        12         170       170     0.0%     0.6%    99.4%    0.0%         100% / 100%
0x008E  OUT        -         169         -                                     no script
0x0035  IN        12         162       162     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12         162       162     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531         162       162   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  OUT     2511         159       159     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550         159       159    99.4%     0.6%     0.0%    0.0%         100% / 100%
0x011B  IN        12         159       159     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x000F  OUT        -         158         -                                     no script
0x0010  OUT        -         158         -                                     no script
0x0016  IN        12         158       158   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546         158       158   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549         158       158   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550         158       158   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12         158       158     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0039  OUT       12         158       158   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12         158       158     0.0%     1.3%    98.7%    0.0%           56% / 56%
0x007D  IN      2486         158       158     1.9%     0.0%    98.1%    0.0%         100% / 100%
0x007D  IN      2502         158       158    98.1%     1.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2503         158       158    98.1%     1.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2546         158       158    98.1%     1.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2549         158       158    98.1%     1.9%     0.0%    0.0%         100% / 100%
0x007D  IN      2550         158       158    98.1%     1.9%     0.0%    0.0%         100% / 100%
0x00CA  IN        12         158       158     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -         158         -                                     no script
0x00F3  IN        12         158       158     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00B6  IN        12         156       156     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x00F4  IN        12         130       130     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x0051  IN        12         126       126     0.0%   100.0%     0.0%    0.0%           17% / 33%
0x0051  IN      2537         126       126   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2546         126       126   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2549         126       126   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2550         126       126   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN        12         125       125   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500         125       125   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12         119       119    56.3%     5.9%    37.8%    0.0%         100% / 100%
0x00E6  IN         -         110         -                                     no script
0x006D  IN        12         104       104     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12         104       104     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x0055  OUT        -          96         -                                     no script
0x005A  IN        12          93        93     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          93        93   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          93        93   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  OUT        -          88         -                                     no script
0x0094  IN         -          84         -                                     no script
0x000C  OUT       12          83        83   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12          83        83   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  OUT        -          81         -                                     no script
0x0071  IN        12          80        80     0.0%   100.0%     0.0%    0.0%             1% / 6%
0x004B  OUT       12          69        69     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006F  IN        12          69        69     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002F  OUT       12          67        67    95.5%     4.5%     0.0%    0.0%         100% / 100%
0x0054  IN        12          64        64     3.1%     4.7%    92.2%    0.0%          90% / 100%
0x00C3  IN        12          62        62     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0042  IN        12          61        61     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A5  IN         -          53         -                                     no script
0x0001  IN        12          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          52         -                                     no script
0x0015  IN        12          52        52     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527          52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          52         -                                     no script
0x00A7  IN        12          52        52     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          52        52     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -          52         -                                     no script
0x00B0  OUT        -          52         -                                     no script
0x00B2  IN        12          52        52     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x00B3  IN        12          52        52     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN      2502          52        52     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          52         -                                     no script
0x00B7  IN        12          52        52     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          52        52     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          52        52     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          52         -                                     no script
0x00DF  IN         -          52         -                                     no script
0x00EE  IN         -          52         -                                     no script
0x0110  IN         -          52         -                                     no script
0x0125  IN        12          52        52     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -          52         -                                     no script
0x0131  IN         -          52         -                                     no script
0x0138  IN         -          52         -                                     no script
0x005B  IN        12          51        51     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0103  IN         -          49         -                                     no script
0x0026  IN        12          48        48   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN        12          47        47     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x0079  OUT       12          42        42   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          34        34   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT       12          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502          32        32     6.2%    93.8%     0.0%    0.0%           20% / 20%
0x0049  IN        12          31        31     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529          31        31    32.3%    67.7%     0.0%    0.0%           1% / 100%
0x0010  IN        12          30        30   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004A  OUT       12          27        27     0.0%     0.0%   100.0%    0.0%           17% / 17%
0x0084  IN        12          27        27     0.0%     0.0%   100.0%    0.0%             0% / 0%
0x0090  IN         -          26         -                                     no script
0x00C1  IN         -          25         -                                     no script
0x0048  OUT        -          23         -                                     no script
0x0018  IN        12          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A2  OUT     2502          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x010C  IN      2502          19        19    57.9%    42.1%     0.0%    0.0%         100% / 100%
0x0025  OUT       12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT     2502          18        18    55.6%    44.4%     0.0%    0.0%         100% / 100%
0x005F  IN        12          18        18     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0027  OUT       12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0080  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0035  OUT       12          12        12     0.0%     0.0%   100.0%    0.0%          94% / 100%
0x0040  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x005A  OUT        -          12         -                                     no script
0x0068  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0068  IN      2486          11        11    90.9%     9.1%     0.0%    0.0%         100% / 100%
0x00F1  IN         -          11         -                                     no script
0x002B  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  IN        12          10        10     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0040  OUT        -          10         -                                     no script
0x0079  IN        12          10        10     0.0%     0.0%   100.0%    0.0%            3% / 29%
0x00FF  IN         -          10         -                                     no script
0x0096  IN         -           9         -                                     no script
0x002D  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00FB  IN         -           8         -                                     no script
0x001F  OUT        -           7         -                                     no script
0x0034  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0046  OUT        -           7         -                                     no script
0x005D  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           73% / 73%
0x00A6  IN        12           7         7     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0011  OUT        -           6         -                                     no script
0x0030  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  OUT        -           5         -                                     no script
0x001B  IN        12           5         5     0.0%     0.0%     0.0%  100.0%           25% / 32%
0x0065  IN        12           5         5     0.0%    80.0%    20.0%    0.0%           12% / 50%
0x00F0  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0100  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0087  OUT        -           4         -                                     no script
0x0019  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0078  OUT        -           3         -                                     no script
0x007A  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           78% / 78%
0x00F2  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x000D  OUT        -           2         -                                     no script
0x0036  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  OUT        -           2         -                                     no script
0x0069  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006E  IN      2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AC  OUT        -           2         -                                     no script
0x00DB  IN         -           2         -                                     no script
0x001A  OUT        -           1         -                                     no script
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x003B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           83% / 83%
0x003C  OUT        -           1         -                                     no script
0x004D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x004D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x004D  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           1         -                                     no script
0x0070  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           25% / 25%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AC  IN         -           1         -                                     no script
0x00AD  OUT        -           1         -                                     no script
0x00CF  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           1         -                                     no script
0x010B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x011F  IN         -           1         -                                     no script

## Sample failures

### 0x002B IN src 12  over=1.500 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 3 of 45 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 221, only 3 of 224 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 3 of 45 remain
  last reads before failure (of 11):
       12    1  Boolean  flag = True
       13    8  Int64    Uid = 10157979656843784
       21    4  Single   positionCoordF/X = 1,811269E-38
       25    4  Single   positionCoordF/Y = 1,8110269E-38
       29    4  Single   positionCoordF/Z = 51533696
       33    4  Int32    ownerObjectId = 13907
       37    4  Int32    Unknown = 1
       41    1  Byte     Unknown = 21

### 0x0047 IN src 12  over=1.500 threw=0 negative-length=758
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -15528 at offset 3/40
  ! ReadBytes: negative length -15528 at offset 3/44
  ! ReadBytes: negative length -47536 at offset 3/13
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -7764

### 0x0056 IN src 12  over=1.500 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 1804720

### 0x0012 OUT src 12  over=1.485 threw=0 negative-length=303
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 49, only 0 of 49 remain
  ! ReadBytes: wanted 2440 byte(s) at offset 45, only 14 of 59 remain
  last reads before failure (of 20):
       25    2  Int16    Segment 0/StateSync/Rotation = -40
       27    1  Byte     Segment 0/StateSync/Animation3 = 2
       28    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 2700
       30    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = 6
       32    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = -512
       34    1  Byte     Segment 0/StateSync/Unknown = 17
       35    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 10
       37    2  Int16    Segment 0/StateSync/CoordS / 1000 = -4601

### 0x001C IN src 12  over=1.479 threw=0 negative-length=224
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 67
       17    2  Int16    StateSync/SpeedCoordS/X = 22784
       19    2  Int16    StateSync/SpeedCoordS/Y = 0
       21    2  Int16    StateSync/SpeedCoordS/Z = 512
       23    1  Byte     StateSync/Unknown = 132
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 2307
       26    2  Int16    StateSync/CoordS / 1000 = 0
       28    4  Single   StateSync/UnknownCoordF/X = 2,655696E-39

### 0x0045 IN src 12  over=1.455 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 167772160
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 768
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0

### 0x004E IN src 12  over=1.402 threw=0 negative-length=8
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 632 byte(s) at offset 3, only 14 of 17 remain
  ! ReadBytes: wanted 16222 byte(s) at offset 3, only 14 of 17 remain
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 8 of 15 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 3
        1    2  Int16    FunctionCubeName/size = 316

### 0x003D IN src 12  over=1.393 threw=0 negative-length=45
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Byte>: wanted 1 byte(s) at offset 22, only 0 of 22 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  last reads before failure (of 5):
        0    8  Int64    SkillUseUid = 3958914762030558211
        8    4  Int32    ServerTick = 624346112
       12    4  Int32    ObjectId = -5570560
       16    4  Int32    SkillId = -1
       20    2  Int16    SkillLevel = -1

### 0x0023 IN src 12  over=1.344 threw=0
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

### 0x00B0 IN src 12  over=1.026 threw=0 negative-length=673
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: wanted 60930 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: negative length -11774 at offset 6/20
  ! ReadBytes: wanted 21506 byte(s) at offset 6, only 14 of 20 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = -1165875968
        4    2  Int16    Motto/size = 30465

### 0x0063 IN src 12  over=869 threw=0 negative-length=328
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 26222 byte(s) at offset 27, only 158 of 185 remain
  ! ReadBytes: wanted 28362 byte(s) at offset 27, only 158 of 185 remain
  ! ReadBytes: negative length -21690 at offset 27/167
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 3703366406021054469
        9    8  Int64    Entry/CharacterId = 3834875981976647265
       17    8  Int64    Entry/AccountId = 7017278261070947942
       25    2  Int16    Entry/Name/size = 13111

### 0x004C IN src 12  over=722 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004C.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 1
        1    4  Int32    ObjectId = 3608284
