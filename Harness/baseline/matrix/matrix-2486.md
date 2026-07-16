# Harness — MATRIX -> 2486

scripts from build : (matrix, see src column)
packets from build : 2486
packets considered : 317.668
packets executed   : 101.784  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              4.481   4.4%
OkExact              39.441   38.7%
UnderRead            45.685   44.9%
OverRead             12.143   11.9%
Threw                    34   0.0%

of packets a script actually ran on (97.303):
  clean (consumed exactly) : 40.5%
  over-read (WRONG)        : 12.5%
  under-read (ambiguous)   : 47.0%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      86.379     1.500     0.0%   100.0%     0.0%    0.0%           12% / 13%
0x0058  IN      2521      86.379     1.500    35.0%    65.0%     0.0%    0.0%          95% / 100%
0x0058  IN      2527      86.379     1.500    61.5%    38.5%     0.0%    0.0%         100% / 100%
0x0012  OUT       12      75.842     1.500     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0024  IN        12      27.722     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502      27.722     1.500    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x0024  IN      2507      27.722     1.500    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x002E  IN        12      15.444     1.500     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521      15.444     1.500    11.7%    78.9%     9.4%    0.0%          19% / 100%
0x002E  IN      2528      15.444     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12      14.513     1.500     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0075  IN        12      13.998     1.500     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529      13.998     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        12       9.928     1.500    50.5%    49.5%     0.0%    0.0%         100% / 100%
0x001C  IN        12       7.795     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN      2507       7.795     1.500    18.3%    66.9%    14.9%    0.0%          64% / 100%
0x003D  IN        12       7.732     1.500     1.1%     0.5%    98.3%    0.0%          96% / 100%
0x003D  IN      2512       7.732     1.500    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x003D  IN      2520       7.732     1.500     8.5%    87.5%     4.0%    0.0%           4% / 100%
0x007E  IN         -       7.372         -                                     no script
0x00CB  IN        12       7.168     1.500     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0020  OUT       12       5.301     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507       5.301     1.500    32.1%    67.9%     0.0%    0.0%          99% / 100%
0x0020  OUT     2512       5.301     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  OUT       12       4.951     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  OUT       12       4.459     1.500     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0023  IN        12       3.260     1.500    30.7%     0.0%    69.3%    0.0%          99% / 100%
0x0023  IN      2486       3.260     1.500     2.5%    97.5%     0.0%    0.0%           16% / 16%
0x0023  IN      2502       3.260     1.500    11.9%    88.1%     0.0%    0.0%          10% / 100%
0x005E  IN        12       2.873     1.500     0.0%    99.1%     0.9%    0.0%           11% / 26%
0x005E  IN      2506       2.873     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12       2.415     1.500     8.1%    88.7%     3.1%    0.0%          17% / 100%
0x0021  IN      2511       2.415     1.500     0.1%    98.2%     1.7%    0.1%            7% / 20%
0x0021  IN      2525       2.415     1.500     0.1%    98.2%     1.7%    0.1%            7% / 20%
0x0021  IN      2529       2.415     1.500     0.1%    98.2%     1.7%    0.1%            7% / 20%
0x0021  IN      2546       2.415     1.500     0.1%    98.2%     1.7%    0.1%            7% / 20%
0x0021  IN      2549       2.415     1.500     0.1%    98.2%     1.7%    0.1%            7% / 20%
0x0021  IN      2550       2.415     1.500     0.1%    98.2%     1.7%    0.1%            7% / 20%
0x003C  IN        12       1.616     1.500     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506       1.616     1.500     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507       1.616     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512       1.616     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520       1.616     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12       1.475     1.475     0.0%    99.8%     0.2%    0.0%             1% / 1%
0x0055  IN      2521       1.475     1.475     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528       1.475     1.475    99.0%     0.6%     0.4%    0.0%         100% / 100%
0x00B0  IN        12       1.340     1.340     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0006  IN        12       1.131     1.131   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486       1.131     1.131   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486       1.130     1.130   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0056  IN        12       1.120     1.120     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00C5  IN        12         838       838     0.0%     0.2%    99.8%    0.0%           40% / 40%
0x0094  IN         -         815         -                                     no script
0x0069  IN        12         654       654     0.2%    99.8%     0.0%    0.0%            7% / 33%
0x0069  IN      2486         654       654     8.0%    92.0%     0.0%    0.0%            7% / 96%
0x0069  IN      2496         654       654     8.9%    91.1%     0.0%    0.0%            7% / 82%
0x0069  IN      2497         654       654     8.0%    92.0%     0.0%    0.0%            7% / 33%
0x0069  IN      2502         654       654    26.8%    73.2%     0.0%    0.0%          20% / 100%
0x0069  IN      2503         654       654    14.1%    85.8%     0.2%    0.0%           7% / 100%
0x0069  IN      2504         654       654    14.1%    85.8%     0.2%    0.0%           7% / 100%
0x0069  IN      2521         654       654    99.2%     0.0%     0.8%    0.0%         100% / 100%
0x0069  IN      2546         654       654     0.2%    99.8%     0.0%    0.0%            7% / 33%
0x0069  IN      2549         654       654    99.2%     0.0%     0.8%    0.0%         100% / 100%
0x0069  IN      2550         654       654    99.2%     0.0%     0.8%    0.0%         100% / 100%
0x0026  OUT       12         516       516   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12         506       506     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0048  IN        12         501       501     0.0%    98.8%     1.2%    0.0%           48% / 48%
0x0048  IN      2504         501       501    98.8%     1.2%     0.0%    0.0%         100% / 100%
0x0048  IN      2507         501       501    98.8%     1.2%     0.0%    0.0%         100% / 100%
0x004D  IN        12         387       387     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503         387       387    93.8%     6.2%     0.0%    0.0%         100% / 100%
0x004D  IN      2504         387       387     0.0%    93.8%     6.2%    0.0%           79% / 79%
0x004D  IN      2507         387       387    93.8%     5.9%     0.3%    0.0%         100% / 100%
0x004D  IN      2546         387       387    93.8%     5.9%     0.3%    0.0%         100% / 100%
0x004D  IN      2549         387       387    93.8%     5.9%     0.3%    0.0%         100% / 100%
0x004D  IN      2550         387       387    93.8%     5.9%     0.3%    0.0%         100% / 100%
0x004C  IN        12         385       385     0.0%    51.4%    48.6%    0.0%           2% / 100%
0x004C  IN      2512         385       385   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12         373       373     0.0%   100.0%     0.0%    0.0%            1% / 20%
0x0052  IN      2516         373       373    55.0%    36.5%     8.6%    0.0%         100% / 100%
0x0093  IN         -         318         -                                     no script
0x004E  IN        12         304       304    14.1%     2.0%    83.9%    0.0%          18% / 100%
0x004F  OUT        -         234         -                                     no script
0x00A8  IN         -         232         -                                     no script
0x008A  IN      2511         222       222     0.0%   100.0%     0.0%    0.0%             0% / 5%
0x008A  IN      2524         222       222    78.8%     7.7%     0.9%   12.6%         100% / 100%
0x0080  OUT        -         204         -                                     no script
0x0035  OUT       12         190       190     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0037  OUT       12         186       186   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502         186       186    17.7%    82.3%     0.0%    0.0%          33% / 100%
0x006A  IN        12         149       149    27.5%    72.5%     0.0%    0.0%          22% / 100%
0x006A  IN      2486         149       149    72.5%    27.5%     0.0%    0.0%         100% / 100%
0x006A  IN      2500         149       149    19.5%    80.5%     0.0%    0.0%          20% / 100%
0x006A  IN      2502         149       149    36.9%    63.1%     0.0%    0.0%          20% / 100%
0x006A  IN      2503         149       149    36.9%    63.1%     0.0%    0.0%          20% / 100%
0x006C  IN        12         146       146     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0063  IN        12         144       144     0.0%     0.0%   100.0%    0.0%           16% / 50%
0x0063  IN      2507         144       144    62.5%    37.5%     0.0%    0.0%         100% / 100%
0x0063  IN      2518         144       144    62.5%    37.5%     0.0%    0.0%         100% / 100%
0x0045  IN        12         138       138     0.0%     1.4%    98.6%    0.0%           98% / 98%
0x00CC  IN        12         137       137     0.0%    77.4%    22.6%    0.0%            8% / 50%
0x001D  IN        12         129       129   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0128  IN        12         117       117    29.9%    70.1%     0.0%    0.0%          14% / 100%
0x006B  IN        12         105       105     0.0%    70.5%    29.5%    0.0%          46% / 100%
0x006B  IN      2507         105       105    67.6%    31.4%     1.0%    0.0%         100% / 100%
0x006B  IN      2511         105       105     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524         105       105    67.6%    31.4%     1.0%    0.0%         100% / 100%
0x006B  IN      2525         105       105     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546         105       105     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549         105       105     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550         105       105   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12         103       103     0.0%    64.1%    35.9%    0.0%           24% / 80%
0x0051  IN        12         100       100     0.0%    98.0%     2.0%    0.0%            6% / 33%
0x0051  IN      2537         100       100    35.0%     1.0%    64.0%    0.0%         100% / 100%
0x0051  IN      2546         100       100    35.0%     1.0%    64.0%    0.0%         100% / 100%
0x0051  IN      2549         100       100    35.0%     1.0%    64.0%    0.0%         100% / 100%
0x0051  IN      2550         100       100    35.0%     1.0%    64.0%    0.0%         100% / 100%
0x0061  IN        12         100       100     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x00F6  IN        12          96        96     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00F6  IN      2520          96        96   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C4  IN         -          95         -                                     no script
0x002F  IN        12          86        86     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0005  IN        12          85        85   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12          79        79     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          79        79   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          79        79   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN        12          78        78     0.0%    17.9%    82.1%    0.0%           80% / 94%
0x001E  IN        12          77        77     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x00F4  IN        12          77        77     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x011C  IN         -          74         -                                     no script
0x0044  IN        12          72        72     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN        12          69        69     0.0%     0.0%   100.0%    0.0%          50% / 100%
0x0017  IN      2500          69        69     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          69        69     0.0%    98.6%     1.4%    0.0%            9% / 48%
0x0017  IN      2528          69        69     0.0%     0.0%   100.0%    0.0%          50% / 100%
0x0017  IN      2550          69        69     0.0%     0.0%   100.0%    0.0%          50% / 100%
0x001A  IN        12          68        68    51.5%    39.7%     8.8%    0.0%         100% / 100%
0x0039  IN        12          67        67     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0053  IN        12          67        67     4.5%    88.1%     7.5%    0.0%            4% / 50%
0x00EB  IN        12          67        67     0.0%    50.7%    49.3%    0.0%          69% / 100%
0x012D  IN         -          67         -                                     no script
0x0019  IN        12          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x010A  IN        12          66        66     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x006D  IN        12          62        62     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00E6  IN         -          61         -                                     no script
0x0034  OUT       12          59        59   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12          55        55     3.6%     5.5%    90.9%    0.0%          90% / 100%
0x0055  OUT        -          54         -                                     no script
0x0039  OUT       12          51        51    94.1%     5.9%     0.0%    0.0%         100% / 100%
0x008E  OUT        -          51         -                                     no script
0x0123  IN         -          47         -                                     no script
0x002B  IN        12          44        44     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002B  IN      2530          44        44    13.6%     0.0%    86.4%    0.0%          99% / 100%
0x002B  IN      2531          44        44    13.6%     0.0%    86.4%    0.0%          99% / 100%
0x0033  IN        12          43        43     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12          43        43     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x000F  OUT        -          41         -                                     no script
0x0010  OUT        -          41         -                                     no script
0x0016  IN        12          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12          41        41     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511          41        41     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12          41        41     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0073  IN        12          41        41     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          41        41     0.0%    63.4%    36.6%    0.0%           11% / 56%
0x007D  IN      2486          41        41    31.7%     0.0%    68.3%    0.0%         100% / 100%
0x007D  IN      2502          41        41    68.3%    31.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2503          41        41    68.3%    31.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2546          41        41    68.3%    31.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2549          41        41    68.3%    31.7%     0.0%    0.0%         100% / 100%
0x007D  IN      2550          41        41    68.3%    31.7%     0.0%    0.0%         100% / 100%
0x00CA  IN        12          41        41     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -          41         -                                     no script
0x00F3  IN        12          41        41     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x011B  IN        12          41        41     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x002C  IN        12          40        40   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12          40        40    87.5%    12.5%     0.0%    0.0%         100% / 100%
0x0014  IN        12          38        38   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12          37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  OUT        -          37         -                                     no script
0x006F  IN        12          37        37     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00A5  IN         -          36         -                                     no script
0x006E  IN      2486          35        35    54.3%     0.0%    45.7%    0.0%         100% / 100%
0x0103  IN         -          34         -                                     no script
0x0089  IN      2527          33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -          33         -                                     no script
0x00A9  IN        12          33        33     0.0%    12.1%    87.9%    0.0%         100% / 100%
0x00B2  IN        12          33        33     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12          33        33     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          33        33     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B7  IN        12          33        33     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          33        33     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00DF  IN         -          33         -                                     no script
0x00EE  IN         -          33         -                                     no script
0x0126  IN         -          33         -                                     no script
0x0131  IN         -          33         -                                     no script
0x004A  OUT       12          32        32     0.0%     9.4%    90.6%    0.0%           17% / 17%
0x0084  IN        12          32        32     0.0%     9.4%    90.6%    0.0%             0% / 2%
0x0001  IN        12          31        31    48.4%    51.6%     0.0%    0.0%          66% / 100%
0x0001  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          31         -                                     no script
0x0015  IN        12          31        31     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12          31        31   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A7  IN        12          31        31     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00AD  IN         -          31         -                                     no script
0x00B0  OUT        -          31         -                                     no script
0x00B5  OUT        -          31         -                                     no script
0x00BD  IN        12          31        31     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x0110  IN         -          31         -                                     no script
0x0125  IN        12          31        31     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00C3  IN        12          30        30     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00CD  IN        12          28        28     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  OUT        -          27         -                                     no script
0x0022  IN        12          25        25    64.0%     0.0%    36.0%    0.0%         100% / 100%
0x002E  OUT       12          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005F  OUT       12          24        24     0.0%    91.7%     8.3%    0.0%           11% / 22%
0x0098  IN        12          24        24     0.0%    87.5%    12.5%    0.0%            6% / 38%
0x005B  IN        12          23        23     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0109  IN        12          23        23     0.0%    26.1%    73.9%    0.0%           91% / 98%
0x004F  IN        12          21        21     0.0%   100.0%     0.0%    0.0%             0% / 1%
0x004F  IN      2507          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0099  OUT        -          21         -                                     no script
0x0022  OUT       12          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  OUT        -          20         -                                     no script
0x007F  IN        12          20        20     0.0%     0.0%   100.0%    0.0%           13% / 67%
0x0029  OUT       12          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0042  IN        12          17        17     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x004B  OUT       12          17        17     0.0%    35.3%    64.7%    0.0%         100% / 100%
0x0036  OUT       12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12          16        16     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0068  IN        12          16        16     0.0%     0.0%   100.0%    0.0%           10% / 60%
0x0068  IN      2486          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  OUT       12          16        16     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0136  IN         -          15         -                                     no script
0x0018  OUT       12          14        14    78.6%    21.4%     0.0%    0.0%         100% / 100%
0x0041  IN        12          14        14     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0028  OUT       12          13        13     7.7%    92.3%     0.0%    0.0%            8% / 20%
0x004B  IN        12          12        12     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          12        12     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0090  IN         -          12         -                                     no script
0x002C  OUT       12          11        11    81.8%     9.1%     9.1%    0.0%         100% / 100%
0x0025  IN        12           9         9     0.0%     0.0%   100.0%    0.0%             7% / 8%
0x005B  OUT       12           9         9     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006E  OUT        -           8         -                                     no script
0x00BB  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0010  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003B  IN        12           7         7     0.0%     0.0%   100.0%    0.0%           83% / 83%
0x00C1  IN         -           7         -                                     no script
0x010E  IN        12           7         7     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0040  OUT        -           6         -                                     no script
0x0079  IN        12           6         6     0.0%     0.0%   100.0%    0.0%            3% / 29%
0x0099  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           11% / 20%
0x009D  IN         -           6         -                                     no script
0x0018  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  OUT        -           5         -                                     no script
0x0066  OUT        -           5         -                                     no script
0x006C  OUT        -           5         -                                     no script
0x007B  IN        12           5         5    40.0%    60.0%     0.0%    0.0%           0% / 100%
0x00AC  IN         -           5         -                                     no script
0x0016  OUT        -           4         -                                     no script
0x0026  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0021  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  OUT     2502           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x002B  OUT       12           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x002D  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  OUT        -           3         -                                     no script
0x0049  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0049  IN      2529           3         3     0.0%   100.0%     0.0%    0.0%             1% / 3%
0x00A2  OUT     2502           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B4  OUT        -           3         -                                     no script
0x010C  IN      2502           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0011  OUT        -           2         -                                     no script
0x0017  OUT        -           2         -                                     no script
0x001D  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0031  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  OUT        -           2         -                                     no script
0x0051  OUT        -           2         -                                     no script
0x0063  OUT        -           2         -                                     no script
0x0065  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0080  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x0081  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x009F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%           94% / 94%
0x00C7  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            0% / 56%
0x00F0  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x00FF  IN         -           2         -                                     no script
0x003A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x003B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%           50% / 50%
0x003D  OUT        -           1         -                                     no script
0x004D  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0057  OUT        -           1         -                                     no script
0x005F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0069  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  OUT        -           1         -                                     no script
0x0072  OUT        -           1         -                                     no script
0x0074  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0078  OUT        -           1         -                                     no script
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0085  OUT        -           1         -                                     no script
0x0097  OUT        -           1         -                                     no script
0x00AC  OUT        -           1         -                                     no script
0x00AE  IN         -           1         -                                     no script
0x00B1  IN         -           1         -                                     no script
0x00CF  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           1         -                                     no script
0x00DC  IN         -           1         -                                     no script
0x00F7  IN         -           1         -                                     no script
0x00FB  IN         -           1         -                                     no script
0x011F  IN         -           1         -                                     no script

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
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2700
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 6
       33    4  Int32    Segment 0/StateSync/Unknown = 1508349
       37    4  Int32    Segment 0/ClientTicks = 1796968691

### 0x0047 IN src 12  over=1.500 threw=0 negative-length=63
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 61024 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 33848 byte(s) at offset 3, only 41 of 44 remain
  ! ReadBytes: wanted 38816 byte(s) at offset 3, only 33 of 36 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 30512

### 0x003D IN src 12  over=1.475 threw=0 negative-length=22
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  ! Read<Single>: wanted 4 byte(s) at offset 49, only 2 of 51 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 2 of 18 remain
  last reads before failure (of 12):
       20    2  Int16    SkillLevel = -22271
       22    1  Byte     MotionPoint = 164
       23    2  Int16    PositionCoordS/X = 155
       25    2  Int16    PositionCoordS/Y = 5
       27    2  Int16    PositionCoordS/Z = 0
       29    4  Single   DirectionCoordF/X = -7,044502E+37
       33    4  Single   DirectionCoordF/Y = 1,0932E-41
       37    4  Single   DirectionCoordF/Z = 2,6815965E-38

### 0x00B0 IN src 12  over=1.340 threw=0 negative-length=938
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -8702 at offset 6/20
  ! ReadBytes: negative length -54782 at offset 6/20
  ! ReadBytes: negative length -8702 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037312
        4    2  Int16    Motto/size = -4351

### 0x0056 IN src 12  over=1.120 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 29854

### 0x0023 IN src 12  over=1.040 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 210, only 3 of 213 remain
  last reads before failure (of 63):
      180    8  Int64    Item: 50100190/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100190/ItemEnchant/Unknown = 16777216
      192    4  Int32    Item: 50100190/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100190/ItemEnchant/CanRepackage = False
      197    4  Int32    Item: 50100190/ItemEnchant/EnchantCharges = 0
      201    1  Byte     Item: 50100190/ItemEnchant/EnchantStats/EnchantStatCount = 0
      202    4  Int32    Item: 50100190/LimitBreak/LimitBreakLevel = 0
      206    4  Int32    Item: 50100190/LimitBreak/LimitBreakStatOption/LimitBreakStatOptionCount = 0

### 0x00C5 IN src 12  over=836 threw=0 negative-length=253
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00C5.py
  ! Read<Int16>: wanted 2 byte(s) at offset 0, only 1 of 1 remain
  ! ReadBytes: wanted 57346 byte(s) at offset 2, only 3 of 5 remain
  ! ReadBytes: negative length -16382 at offset 2/5
  last reads before failure (of 0):

### 0x004E IN src 12  over=255 threw=0 negative-length=2
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 204 byte(s) at offset 7, only 13 of 20 remain
  ! ReadBytes: wanted 204 byte(s) at offset 7, only 13 of 20 remain
  ! ReadBytes: wanted 1202 byte(s) at offset 7, only 3 of 10 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 3
        5    2  Int16    FunctionCubeName/size = 102

### 0x001C IN src 2507  over=223 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 36, only 2 of 38 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = -17927
       13    2  Int16    coord x = 17419
       15    2  Int16    coord y = 2316
       17    2  Int16    coord z = 90
       19    2  Int16    rotation = 45
       21    1  Byte     animation3 = 217
       22    8  Int64    2x float = -723952338518932737
       30    2  Int16    speed x = 19

### 0x0035 OUT src 12  over=190 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0035.py
  ! Read<Int32>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  last reads before failure (of 18):
       15    2  Int16    StateSync/SpeedCoordS/X = 0
       17    2  Int16    StateSync/SpeedCoordS/Y = 0
       19    2  Int16    StateSync/SpeedCoordS/Z = 0
       21    1  Byte     StateSync/Unknown = 17
       22    2  Int16    StateSync/Rotation2 CoordS / 10 = 0
       24    2  Int16    StateSync/CoordS / 1000 = 395
       26    4  Int32    StateSync/Unknown = 2147483647
       30    4  Int32    ClientTick = 1508880359

### 0x004C IN src 12  over=187 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004C.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 1
        1    4  Int32    ObjectId = 7687789

### 0x0063 IN src 12  over=144 threw=0 negative-length=48
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 25290 byte(s) at offset 27, only 158 of 185 remain
  ! ReadBytes: wanted 29298 byte(s) at offset 27, only 1122 of 1149 remain
  ! ReadBytes: wanted 25290 byte(s) at offset 27, only 158 of 185 remain
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 4049017677421740037
        9    8  Int64    Entry/CharacterId = 7378648129965929264
       17    8  Int64    Entry/AccountId = 3846748294536771123
       25    2  Int16    Entry/Name/size = 12645
