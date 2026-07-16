# Harness — MATRIX -> 2507

scripts from build : (matrix, see src column)
packets from build : 2507
packets considered : 131.459
packets executed   : 71.435  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              4.341   6.1%
OkExact              24.059   33.7%
UnderRead            33.145   46.4%
OverRead              9.890   13.8%

of packets a script actually ran on (67.094):
  clean (consumed exactly) : 35.9%
  over-read (WRONG)        : 14.7%
  under-read (ambiguous)   : 49.4%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12      29.921     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      29.921     1.500    98.9%     1.1%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      29.921     1.500    98.9%     1.1%     0.0%    0.0%         100% / 100%
0x0058  IN        12      28.785     1.500     0.0%   100.0%     0.0%    0.0%           12% / 13%
0x0058  IN      2521      28.785     1.500    49.3%    50.7%     0.0%    0.0%          97% / 100%
0x0058  IN      2527      28.785     1.500    94.1%     5.9%     0.0%    0.0%         100% / 100%
0x0012  OUT       12      22.734     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x001C  IN        12       6.718     1.500     1.4%     0.0%    98.6%    0.0%         100% / 100%
0x001C  IN      2507       6.718     1.500    84.9%     4.8%    10.3%    0.0%         100% / 100%
0x0023  IN        12       6.274     1.500     4.1%     0.0%    95.9%    0.0%         100% / 100%
0x0023  IN      2486       6.274     1.500     2.1%    97.9%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       6.274     1.500     3.2%    96.8%     0.0%    0.0%           11% / 11%
0x0011  IN        12       6.251     1.500    50.1%    49.9%     0.0%    0.0%         100% / 100%
0x0021  IN        12       3.823     1.500     2.3%    97.3%     0.4%    0.0%           17% / 20%
0x0021  IN      2511       3.823     1.500     0.2%    99.8%     0.0%    0.0%           11% / 20%
0x0021  IN      2525       3.823     1.500     0.2%    99.8%     0.0%    0.0%           11% / 20%
0x0021  IN      2529       3.823     1.500     0.2%    99.8%     0.0%    0.0%           11% / 20%
0x0021  IN      2546       3.823     1.500     0.2%    99.8%     0.0%    0.0%           11% / 20%
0x0021  IN      2549       3.823     1.500     0.2%    99.8%     0.0%    0.0%           11% / 20%
0x0021  IN      2550       3.823     1.500     0.2%    99.8%     0.0%    0.0%           11% / 20%
0x007E  IN         -       3.129         -                                     no script
0x000B  OUT       12       3.100     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12       1.417     1.417     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521       1.417     1.417    20.0%    73.4%     6.6%    0.0%          19% / 100%
0x002E  IN      2528       1.417     1.417    96.5%     2.9%     0.6%    0.0%         100% / 100%
0x0047  IN        12       1.195     1.195     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x005E  IN        12         896       896     0.0%    92.9%     7.1%    0.0%            2% / 35%
0x005E  IN      2506         896       896   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CB  IN        12         877       877     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0006  IN        12         666       666   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         666       666   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         665       665   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         618       618     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x003D  IN        12         609       609     2.8%     3.3%    93.9%    0.0%          96% / 100%
0x003D  IN      2512         609       609    84.4%    15.6%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         609       609    19.4%    80.0%     0.7%    0.0%           4% / 100%
0x0041  OUT       12         564       564     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x0052  IN        12         541       541     0.2%    97.6%     2.2%    0.0%            2% / 20%
0x0052  IN      2516         541       541    52.1%    44.4%     3.5%    0.0%         100% / 100%
0x0055  IN        12         525       525     0.0%    99.6%     0.4%    0.0%             1% / 1%
0x0055  IN      2521         525       525     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         525       525    97.7%     1.0%     1.3%    0.0%         100% / 100%
0x0048  IN        12         460       460     0.0%    97.4%     2.6%    0.0%           48% / 48%
0x0048  IN      2504         460       460    97.4%     2.6%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         460       460    97.4%     2.6%     0.0%    0.0%         100% / 100%
0x00A8  IN         -         449         -                                     no script
0x0090  OUT     2504         404       404     2.0%    98.0%     0.0%    0.0%             2% / 2%
0x0037  IN        12         373       373     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0069  IN        12         275       275     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486         275       275    24.0%    76.0%     0.0%    0.0%          20% / 100%
0x0069  IN      2496         275       275    25.8%    74.2%     0.0%    0.0%          20% / 100%
0x0069  IN      2497         275       275    24.0%    76.0%     0.0%    0.0%           7% / 100%
0x0069  IN      2502         275       275    34.2%    65.8%     0.0%    0.0%          20% / 100%
0x0069  IN      2503         275       275    10.2%    89.8%     0.0%    0.0%           4% / 100%
0x0069  IN      2504         275       275    10.2%    89.8%     0.0%    0.0%           4% / 100%
0x0069  IN      2521         275       275   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546         275       275     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549         275       275   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550         275       275   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN        12         262       262     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0093  IN         -         250         -                                     no script
0x006A  IN        12         245       245    28.6%    71.4%     0.0%    0.0%          50% / 100%
0x006A  IN      2486         245       245    73.1%    26.9%     0.0%    0.0%         100% / 100%
0x006A  IN      2500         245       245    21.2%    78.8%     0.0%    0.0%          20% / 100%
0x006A  IN      2502         245       245    40.4%    59.6%     0.0%    0.0%          20% / 100%
0x006A  IN      2503         245       245    40.4%    59.6%     0.0%    0.0%          20% / 100%
0x0061  IN        12         237       237     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x008A  IN      2511         232       232     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x008A  IN      2524         232       232    83.6%     0.4%    15.9%    0.0%         100% / 100%
0x0020  OUT       12         219       219    86.3%    13.7%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507         219       219    28.8%    71.2%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         219       219    86.3%    13.7%     0.0%    0.0%         100% / 100%
0x00CC  IN        12         201       201     0.0%    85.6%    14.4%    0.0%           10% / 50%
0x006B  IN        12         199       199     0.0%    67.3%    32.7%    0.0%          46% / 100%
0x006B  IN      2507         199       199    66.3%    33.7%     0.0%    0.0%         100% / 100%
0x006B  IN      2511         199       199     0.5%    99.5%     0.0%    0.0%            8% / 20%
0x006B  IN      2524         199       199    66.3%    33.7%     0.0%    0.0%         100% / 100%
0x006B  IN      2525         199       199     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546         199       199     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549         199       199     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550         199       199   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12         195       195     0.0%    66.2%    33.8%    0.0%           24% / 80%
0x004E  IN        12         193       193     3.6%     0.0%    96.4%    0.0%          27% / 100%
0x0128  IN        12         187       187    29.4%    70.6%     0.0%    0.0%          14% / 100%
0x0045  IN        12         186       186     0.0%    15.1%    84.9%    0.0%           98% / 98%
0x00F6  IN        12         185       185     0.0%    90.3%     9.7%    0.0%             0% / 1%
0x00F6  IN      2520         185       185   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007A  IN        12         178       178     0.0%     0.0%   100.0%    0.0%           78% / 78%
0x004F  OUT        -         157         -                                     no script
0x004D  IN        12         153       153     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503         153       153    88.9%    11.1%     0.0%    0.0%         100% / 100%
0x004D  IN      2504         153       153     0.0%    88.9%    11.1%    0.0%           79% / 79%
0x004D  IN      2507         153       153    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x004D  IN      2546         153       153    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x004D  IN      2549         153       153    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x004D  IN      2550         153       153    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x004B  IN        12         146       146     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507         146       146     8.9%    91.1%     0.0%    0.0%             6% / 6%
0x0022  OUT       12         145       145   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12         137       137     0.0%     0.0%   100.0%    0.0%          94% / 100%
0x011C  IN         -         130         -                                     no script
0x006D  IN        12         129       129     0.0%   100.0%     0.0%    0.0%           14% / 14%
0x0019  IN        12         128       128   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500         128       128   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12         128       128    50.0%    27.3%    22.7%    0.0%         100% / 100%
0x010A  IN        12         128       128     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x003C  IN        12         117       117     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         117       117     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         117       117   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         117       117   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         117       117   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -         116         -                                     no script
0x0056  IN        12         113       113     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN        12         105       105     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500         105       105     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503         105       105     0.0%    99.0%     1.0%    0.0%           20% / 65%
0x0017  IN      2528         105       105     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550         105       105     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0044  IN        12         103       103     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00EB  IN        12          97        97     1.0%    44.3%    54.6%    0.0%         100% / 100%
0x001D  IN        12          94        94   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0097  OUT        -          92         -                                     no script
0x0063  IN        12          87        87     0.0%     3.4%    96.6%    0.0%           16% / 42%
0x0063  IN      2507          87        87    54.0%    46.0%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          87        87    54.0%    46.0%     0.0%    0.0%         100% / 100%
0x00A5  IN         -          87         -                                     no script
0x00F4  IN        12          84        84     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0005  IN        12          83        83   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12          80        80   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT       12          79        79   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502          79        79     2.5%    97.5%     0.0%    0.0%           20% / 73%
0x00AD  IN         -          79         -                                     no script
0x008E  OUT        -          76         -                                     no script
0x0123  IN         -          75         -                                     no script
0x00E6  IN         -          74         -                                     no script
0x0034  OUT       12          72        72   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  OUT        -          72         -                                     no script
0x0033  IN        12          70        70     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0039  OUT       12          70        70    98.6%     1.4%     0.0%    0.0%         100% / 100%
0x00CA  IN        12          69        69     0.0%    95.7%     4.3%    0.0%           10% / 20%
0x0038  OUT     2511          68        68     1.5%    98.5%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          68        68    98.5%     0.0%     1.5%    0.0%         100% / 100%
0x0035  IN        12          67        67     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006F  IN        12          67        67     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D1  IN         -          67         -                                     no script
0x00F3  IN        12          67        67     0.0%    98.5%     1.5%    0.0%           50% / 50%
0x0001  IN        12          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000F  OUT        -          66         -                                     no script
0x0010  OUT        -          66         -                                     no script
0x0016  IN        12          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          66        66     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0036  IN        12          66        66     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0073  IN        12          66        66     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          66        66     0.0%    63.6%    36.4%    0.0%           11% / 56%
0x007D  IN      2486          66        66    18.2%    34.8%    47.0%    0.0%         100% / 100%
0x007D  IN      2502          66        66    47.0%    53.0%     0.0%    0.0%          99% / 100%
0x007D  IN      2503          66        66    47.0%    53.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          66        66    47.0%    53.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          66        66    47.0%    53.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          66        66    47.0%    53.0%     0.0%    0.0%         100% / 100%
0x011B  IN        12          66        66     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00B3  IN        12          65        65     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          65        65     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          65         -                                     no script
0x00C4  IN         -          65         -                                     no script
0x0125  IN        12          65        65     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0004  IN        12          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          64         -                                     no script
0x0013  IN        12          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12          64        64     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x0015  IN      2507          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12          64        64     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0089  IN      2527          64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          64         -                                     no script
0x00A7  IN        12          64        64     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          64        64     0.0%     7.8%    92.2%    0.0%         100% / 100%
0x00B0  OUT        -          64         -                                     no script
0x00B2  IN        12          64        64     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B7  IN        12          64        64     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          64        64     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          64        64     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00DF  IN         -          64         -                                     no script
0x00EE  IN         -          64         -                                     no script
0x0110  IN         -          64         -                                     no script
0x0126  IN         -          64         -                                     no script
0x0131  IN         -          64         -                                     no script
0x0137  IN         -          64         -                                     no script
0x0138  IN         -          64         -                                     no script
0x005A  IN        12          63        63     0.0%   100.0%     0.0%    0.0%             4% / 5%
0x005A  IN      2490          63        63   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          63        63   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  IN        12          61        61     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004C  IN        12          57        57     0.0%    50.9%    49.1%    0.0%           2% / 100%
0x004C  IN      2512          57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  IN        12          49        49    10.2%    53.1%    36.7%    0.0%           6% / 100%
0x002E  OUT       12          47        47     0.0%   100.0%     0.0%    0.0%           25% / 25%
0x002B  IN        12          37        37     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530          37        37    32.4%     0.0%    67.6%    0.0%         100% / 100%
0x002B  IN      2531          37        37    32.4%     0.0%    67.6%    0.0%         100% / 100%
0x00EA  IN        12          33        33     0.0%   100.0%     0.0%    0.0%             2% / 3%
0x00EA  IN      2504          33        33    24.2%     6.1%    69.7%    0.0%          77% / 100%
0x00EA  IN      2507          33        33     3.0%    97.0%     0.0%    0.0%             2% / 6%
0x0071  IN        12          32        32     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0011  OUT        -          31         -                                     no script
0x002C  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12          28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0029  OUT       12          26        26    92.3%     7.7%     0.0%    0.0%         100% / 100%
0x002F  IN        12          25        25     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0066  OUT        -          23         -                                     no script
0x006E  IN      2486          23        23    82.6%     0.0%    17.4%    0.0%         100% / 100%
0x002D  IN        12          21        21    85.7%    14.3%     0.0%    0.0%         100% / 100%
0x0068  IN        12          20        20     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12          20        20     0.0%    90.0%    10.0%    0.0%             2% / 2%
0x0075  IN      2529          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  OUT       12          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F1  IN         -          18         -                                     no script
0x0103  IN         -          18         -                                     no script
0x001C  OUT        -          17         -                                     no script
0x0039  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0078  OUT        -          16         -                                     no script
0x00CD  IN        12          16        16     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004B  OUT       12          15        15     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004F  IN        12          15        15     0.0%   100.0%     0.0%    0.0%             0% / 1%
0x004F  IN      2507          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  OUT        -          14         -                                     no script
0x003F  IN        12          12        12     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0026  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  OUT        -          10         -                                     no script
0x0109  IN        12          10        10     0.0%    60.0%    40.0%    0.0%            3% / 97%
0x0096  IN         -           9         -                                     no script
0x00C1  IN         -           9         -                                     no script
0x00F7  IN         -           8         -                                     no script
0x0010  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  IN        12           7         7    71.4%     0.0%    28.6%    0.0%         100% / 100%
0x0031  OUT       12           7         7     0.0%   100.0%     0.0%    0.0%           10% / 17%
0x005B  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0075  OUT       12           7         7     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0079  IN        12           7         7     0.0%     0.0%   100.0%    0.0%            3% / 29%
0x00C8  IN         -           7         -                                     no script
0x0051  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           19% / 33%
0x0051  IN      2537           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2546           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2549           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN      2550           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005F  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x006C  OUT        -           6         -                                     no script
0x0082  OUT       12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           6         -                                     no script
0x0018  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0042  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A4  IN         -           5         -                                     no script
0x00A4  OUT       12           5         5     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x000C  IN        12           4         4    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x000C  IN      2507           4         4    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x000C  IN      2525           4         4    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x0041  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0043  OUT       12           4         4     0.0%    50.0%    50.0%    0.0%          20% / 100%
0x0018  OUT       12           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x001D  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN        12           3         3     0.0%     0.0%   100.0%    0.0%             7% / 7%
0x0026  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x003A  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x0040  OUT        -           3         -                                     no script
0x0049  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x007C  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            4% / 26%
0x007C  IN      2507           3         3     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x00C7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 8%
0x00F2  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0003  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x0009  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  OUT        -           2         -                                     no script
0x0063  OUT        -           2         -                                     no script
0x007B  OUT        -           2         -                                     no script
0x0080  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x009F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x00C6  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x00CF  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x010E  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0009  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT     2525           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             2% / 2%
0x000B  IN      2507           1         1     0.0%   100.0%     0.0%    0.0%           76% / 76%
0x000E  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  OUT        -           1         -                                     no script
0x0017  OUT        -           1         -                                     no script
0x001F  OUT        -           1         -                                     no script
0x002F  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           17% / 17%
0x0034  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x003A  OUT        -           1         -                                     no script
0x003B  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x004D  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0051  OUT        -           1         -                                     no script
0x005D  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           73% / 73%
0x0065  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0070  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           25% / 25%
0x00A6  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00AF  IN         -           1         -                                     no script
0x00B8  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x00DC  IN         -           1         -                                     no script
0x0105  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x010B  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x010F  IN         -           1         -                                     no script
0x011F  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=286
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 7
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2055
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = -9,8126695E-31

### 0x001C IN src 12  over=1.479 threw=0 negative-length=86
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! ReadBytes: negative length -8724 at offset 30/32
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 4607
       23    1  Byte     StateSync/Unknown = 8
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 1287
       26    2  Int16    StateSync/CoordS / 1000 = 0
       28    2  Int16    StateSync/AnimationString?/size = -4362

### 0x0023 IN src 12  over=1.439 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int16>: wanted 2 byte(s) at offset 545, only 0 of 545 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 164):
      517    4  Int32    Item: 50100385/Stats/Empowerment Stats 4/StatOption 35/IntegerValue = 0
      521    4  Single   Item: 50100385/Stats/Empowerment Stats 4/StatOption 35/FloatValue = 9,1835E-41
      525    2  Int16    Item: 50100385/Stats/Empowerment Stats 4/StatType = 0
      527    4  Int32    Item: 50100385/Stats/Empowerment Stats 4/StatOption 36/IntegerValue = 0
      531    4  Single   Item: 50100385/Stats/Empowerment Stats 4/StatOption 36/FloatValue = 0
      535    2  Int16    Item: 50100385/Stats/Empowerment Stats 4/StatType = 0
      537    4  Int32    Item: 50100385/Stats/Empowerment Stats 4/StatOption 37/IntegerValue = 0
      541    4  Single   Item: 50100385/Stats/Empowerment Stats 4/StatOption 37/FloatValue = 0

### 0x0047 IN src 12  over=1.195 threw=0 negative-length=602
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 5980 byte(s) at offset 3, only 41 of 44 remain
  ! ReadBytes: wanted 5980 byte(s) at offset 3, only 41 of 44 remain
  ! ReadBytes: negative length -62386 at offset 3/44
  last reads before failure (of 2):
        0    1  Byte     function = 2
        1    2  Int16    message/size = 2990

### 0x00B0 IN src 12  over=618 threw=0 negative-length=581
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -8702 at offset 6/20
  ! ReadBytes: negative length -54782 at offset 6/20
  ! ReadBytes: negative length -8702 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037312
        4    2  Int16    Motto/size = -4351

### 0x003D IN src 12  over=572 threw=0 negative-length=6
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 4907280924604508676
        8    4  Int32    ServerTick = 1914160896
       12    4  Int32    ObjectId = -1698037759
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0061 IN src 12  over=237 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 821, only 1 of 822 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x004E IN src 12  over=186 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 8 of 15 remain
  ! ReadBytes: wanted 10600 byte(s) at offset 7, only 408 of 415 remain
  ! ReadBytes: wanted 16000 byte(s) at offset 3, only 8 of 11 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 601

### 0x007A IN src 12  over=178 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x007A.py
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  last reads before failure (of 4):
        0    8  Int64    CharacterId = 439103166987975559
        8    1  Boolean  Bool = True
        9    8  Int64    Unknown = 6488011742357224936
       17    8  Int64    CharacterId = 886665967462001920

### 0x0045 IN src 12  over=158 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 0
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 0
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0

### 0x001C IN src 2507  over=154 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 1801
       13    2  Int16    coord x = 2690
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = 1086211940277715458
       30    2  Int16    speed x = 11

### 0x0035 OUT src 12  over=137 threw=0 negative-length=39
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0035.py
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! ReadBytes: wanted 30408 byte(s) at offset 32, only 2 of 34 remain
  last reads before failure (of 18):
       15    2  Int16    StateSync/SpeedCoordS/X = 0
       17    2  Int16    StateSync/SpeedCoordS/Y = 0
       19    2  Int16    StateSync/SpeedCoordS/Z = 4352
       21    1  Byte     StateSync/Unknown = 0
       22    2  Int16    StateSync/Rotation2 CoordS / 10 = 20736
       24    2  Int16    StateSync/CoordS / 1000 = 0
       26    4  Single   StateSync/UnknownCoordF/X = NaN
       30    4  Single   StateSync/UnknownCoordF/Y = 4,9394323E-08
