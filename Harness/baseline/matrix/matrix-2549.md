# Harness — MATRIX -> 2549

scripts from build : (matrix, see src column)
packets from build : 2549
packets considered : 27.561
packets executed   : 51.756  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              1.149   2.2%
OkExact              17.829   34.4%
UnderRead            28.690   55.4%
OverRead              4.088   7.9%

of packets a script actually ran on (50.607):
  clean (consumed exactly) : 35.2%
  over-read (WRONG)        : 8.1%
  under-read (ambiguous)   : 56.7%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0023  IN        12       5.609     1.500     8.9%     0.0%    91.1%    0.0%         100% / 100%
0x0023  IN      2486       5.609     1.500     0.9%    99.1%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       5.609     1.500     6.3%    93.7%     0.0%    0.0%           11% / 11%
0x0012  OUT       12       4.408     1.500     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0024  IN        12       3.400     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       3.400     1.500    99.0%     1.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       3.400     1.500    99.0%     1.0%     0.0%    0.0%         100% / 100%
0x0069  IN        12       2.736     1.500     0.0%   100.0%     0.0%    0.0%             2% / 7%
0x0069  IN      2486       2.736     1.500     0.0%    99.5%     0.5%    0.0%             2% / 7%
0x0069  IN      2496       2.736     1.500     0.0%    99.5%     0.5%    0.0%             2% / 7%
0x0069  IN      2497       2.736     1.500     0.0%    99.5%     0.5%    0.0%             2% / 7%
0x0069  IN      2502       2.736     1.500    31.8%    67.7%     0.5%    0.0%           7% / 100%
0x0069  IN      2503       2.736     1.500    49.3%    50.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2504       2.736     1.500    49.3%    50.7%     0.0%    0.0%          20% / 100%
0x0069  IN      2521       2.736     1.500    99.5%     0.0%     0.5%    0.0%         100% / 100%
0x0069  IN      2546       2.736     1.500     0.1%    99.9%     0.0%    0.0%             2% / 7%
0x0069  IN      2549       2.736     1.500    99.5%     0.0%     0.5%    0.0%         100% / 100%
0x0069  IN      2550       2.736     1.500    99.5%     0.0%     0.5%    0.0%         100% / 100%
0x0011  IN        12       2.346     1.500    51.9%    48.1%     0.0%    0.0%         100% / 100%
0x0021  IN        12       1.620     1.500     0.0%    99.8%     0.2%    0.0%            0% / 20%
0x0021  IN      2511       1.620     1.500     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2525       1.620     1.500     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2529       1.620     1.500     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2546       1.620     1.500     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2549       1.620     1.500     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2550       1.620     1.500     0.1%    99.9%     0.0%    0.0%            0% / 20%
0x0058  IN        12       1.296     1.296     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521       1.296     1.296    54.8%    45.2%     0.0%    0.0%         100% / 100%
0x0058  IN      2527       1.296     1.296    90.7%     9.3%     0.0%    0.0%         100% / 100%
0x000B  OUT       12       1.164     1.164   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12         329       329     0.0%     0.0%   100.0%    0.0%          94% / 100%
0x005E  IN        12         312       312     0.0%    94.6%     5.4%    0.0%            0% / 10%
0x005E  IN      2506         312       312   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT       12         277       277    97.1%     2.9%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502         277       277    67.5%    32.5%     0.0%    0.0%         100% / 100%
0x0006  IN        12         198       198   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         198       198   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         198       198   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12         187       187     0.0%   100.0%     0.0%    0.0%             0% / 8%
0x0052  IN      2516         187       187    72.7%    27.3%     0.0%    0.0%         100% / 100%
0x00B0  IN        12         152       152     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x007E  IN         -         151         -                                     no script
0x004F  OUT        -         145         -                                     no script
0x0037  IN        12         143       143     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0047  IN        12         139       139     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x00F6  IN        12         138       138     0.0%    75.4%    24.6%    0.0%           0% / 100%
0x00F6  IN      2520         138       138   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -         119         -                                     no script
0x006C  IN        12         101       101     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0123  IN         -          85         -                                     no script
0x0093  IN         -          82         -                                     no script
0x0061  IN        12          71        71     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x008A  IN      2511          70        70     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524          70        70    75.7%    24.3%     0.0%    0.0%         100% / 100%
0x002E  IN        12          69        69     0.0%   100.0%     0.0%    0.0%            2% / 26%
0x002E  IN      2521          69        69    73.9%    26.1%     0.0%    0.0%         100% / 100%
0x002E  IN      2528          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12          67        67    25.4%    74.6%     0.0%    0.0%          50% / 100%
0x006A  IN      2486          67        67    74.6%    25.4%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          67        67    20.9%    79.1%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          67        67    44.8%    55.2%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          67        67    44.8%    55.2%     0.0%    0.0%          20% / 100%
0x006B  IN        12          54        54     0.0%    68.5%    31.5%    0.0%          46% / 100%
0x006B  IN      2507          54        54    63.0%    37.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          54        54     1.9%    98.1%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          54        54    63.0%    37.0%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          54        54     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          54        54     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          54        54     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          54        54   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12          51        51    64.7%    35.3%     0.0%    0.0%         100% / 100%
0x0045  IN        12          51        51     0.0%    33.3%    66.7%    0.0%           98% / 98%
0x00B6  IN        12          51        51     0.0%    66.7%    33.3%    0.0%           14% / 24%
0x0128  IN        12          51        51    31.4%    64.7%     3.9%    0.0%          14% / 100%
0x013B  IN         -          51         -                                     no script
0x0048  IN        12          47        47     0.0%    89.4%    10.6%    0.0%          48% / 100%
0x0048  IN      2504          47        47    89.4%    10.6%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          47        47    89.4%    10.6%     0.0%    0.0%         100% / 100%
0x001C  IN        12          44        44     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001C  IN      2507          44        44     9.1%     0.0%    90.9%    0.0%         100% / 100%
0x0019  IN        12          34        34   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500          34        34   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12          34        34    50.0%    50.0%     0.0%    0.0%          14% / 100%
0x0044  IN        12          34        34     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12          34        34     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CC  IN        12          34        34     0.0%   100.0%     0.0%    0.0%            2% / 50%
0x010A  IN        12          34        34     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -          34         -                                     no script
0x012D  IN         -          34         -                                     no script
0x0138  IN         -          34         -                                     no script
0x004D  IN        12          29        29     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503          29        29    82.8%    10.3%     6.9%    0.0%         100% / 100%
0x004D  IN      2504          29        29     0.0%    96.6%     3.4%    0.0%           79% / 79%
0x004D  IN      2507          29        29    82.8%    10.3%     6.9%    0.0%         100% / 100%
0x004D  IN      2546          29        29    82.8%    10.3%     6.9%    0.0%         100% / 100%
0x004D  IN      2549          29        29    82.8%    10.3%     6.9%    0.0%         100% / 100%
0x004D  IN      2550          29        29    82.8%    10.3%     6.9%    0.0%         100% / 100%
0x0055  OUT        -          29         -                                     no script
0x0014  IN        12          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          26        26     0.0%    96.2%     3.8%    0.0%             1% / 1%
0x0055  IN      2521          26        26     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          26        26    88.5%    11.5%     0.0%    0.0%         100% / 100%
0x0005  IN        12          24        24   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F4  IN        12          22        22     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x00A5  IN         -          21         -                                     no script
0x00E6  IN         -          20         -                                     no script
0x0038  OUT     2511          19        19     0.0%    94.7%     5.3%    0.0%           20% / 20%
0x0038  OUT     2550          19        19    89.5%    10.5%     0.0%    0.0%         100% / 100%
0x0017  IN        12          18        18     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          18        18     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          18        18     0.0%   100.0%     0.0%    0.0%           43% / 43%
0x0017  IN      2528          18        18     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550          18        18     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x003D  IN        12          18        18     0.0%     0.0%   100.0%    0.0%           96% / 96%
0x003D  IN      2512          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          18        18     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0080  OUT        -          18         -                                     no script
0x0001  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -          17         -                                     no script
0x000F  OUT        -          17         -                                     no script
0x0010  OUT        -          17         -                                     no script
0x0013  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0054  IN        12          17        17     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x006F  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12          17        17     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12          17        17     0.0%    52.9%    47.1%    0.0%           11% / 35%
0x007D  IN      2486          17        17     0.0%    88.2%    11.8%    0.0%          43% / 100%
0x007D  IN      2502          17        17    11.8%    88.2%     0.0%    0.0%          42% / 100%
0x007D  IN      2503          17        17    11.8%    88.2%     0.0%    0.0%          99% / 100%
0x007D  IN      2546          17        17    11.8%    88.2%     0.0%    0.0%          99% / 100%
0x007D  IN      2549          17        17    11.8%    88.2%     0.0%    0.0%          99% / 100%
0x007D  IN      2550          17        17    11.8%    88.2%     0.0%    0.0%          99% / 100%
0x0089  IN      2527          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -          17         -                                     no script
0x009E  IN         -          17         -                                     no script
0x00A4  IN         -          17         -                                     no script
0x00A7  IN        12          17        17     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           41% / 41%
0x00AD  IN         -          17         -                                     no script
0x00B0  OUT        -          17         -                                     no script
0x00B2  IN        12          17        17     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00B3  IN        12          17        17     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502          17        17     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -          17         -                                     no script
0x00B7  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12          17        17     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -          17         -                                     no script
0x00CA  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           10% / 20%
0x00CB  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x00D1  IN         -          17         -                                     no script
0x00DF  IN         -          17         -                                     no script
0x00EB  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -          17         -                                     no script
0x00F3  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -          17         -                                     no script
0x011B  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12          17        17     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -          17         -                                     no script
0x0131  IN         -          17         -                                     no script
0x013A  IN         -          17         -                                     no script
0x013C  IN         -          17         -                                     no script
0x001D  IN        12          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0011  OUT        -          10         -                                     no script
0x0036  OUT       12          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005F  IN        12          10        10     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0068  IN        12          10        10     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006E  IN      2486          10        10   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0109  IN        12           9         9     0.0%    33.3%    66.7%    0.0%           91% / 91%
0x0090  OUT     2504           6         6    16.7%    83.3%     0.0%    0.0%          80% / 100%
0x00EA  IN        12           5         5     0.0%   100.0%     0.0%    0.0%            2% / 11%
0x00EA  IN      2504           5         5    20.0%     0.0%    80.0%    0.0%         100% / 100%
0x00EA  IN      2507           5         5     0.0%   100.0%     0.0%    0.0%            2% / 11%
0x0010  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           4         -                                     no script
0x0019  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  OUT        -           3         -                                     no script
0x011F  IN         -           3         -                                     no script
0x003A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x0063  IN        12           2         2     0.0%     0.0%   100.0%    0.0%            2% / 66%
0x0063  IN      2507           2         2     0.0%   100.0%     0.0%    0.0%             0% / 2%
0x0063  IN      2518           2         2     0.0%   100.0%     0.0%    0.0%             0% / 2%
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x002E  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0039  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0042  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=314
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -56604 at offset 39/41
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 11520
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 1
       33    4  Int32    Segment 0/StateSync/Unknown = 63222
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = -28302

### 0x0023 IN src 12  over=1.366 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100224/Stats/Unknown = 0
      171    4  Int32    Item: 50100224/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100224/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100224/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100224/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100224/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100224/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100224/ItemEnchant/CanRepackage = False

### 0x0035 OUT src 12  over=329 threw=0 negative-length=47
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0035.py
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  ! Read<Single>: wanted 4 byte(s) at offset 34, only 0 of 34 remain
  last reads before failure (of 18):
       15    2  Int16    StateSync/SpeedCoordS/X = 0
       17    2  Int16    StateSync/SpeedCoordS/Y = 0
       19    2  Int16    StateSync/SpeedCoordS/Z = 4352
       21    1  Byte     StateSync/Unknown = 0
       22    2  Int16    StateSync/Rotation2 CoordS / 10 = 20480
       24    2  Int16    StateSync/CoordS / 1000 = 1
       26    4  Single   StateSync/UnknownCoordF/X = NaN
       30    4  Single   StateSync/UnknownCoordF/Y = 5,3936896E+30

### 0x00B0 IN src 12  over=152 threw=0 negative-length=121
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -47102 at offset 6/20
  ! ReadBytes: negative length -6654 at offset 6/20
  ! ReadBytes: negative length -43006 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593047296
        4    2  Int16    Motto/size = -23551

### 0x0047 IN src 12  over=139 threw=0 negative-length=27
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 54744 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 54744 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 54744 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 27372

### 0x0061 IN src 12  over=71 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5405, only 2 of 5407 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5297, only 2 of 5299 remain
  last reads before failure (of 0):

### 0x001C IN src 12  over=44 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 767
       23    1  Byte     StateSync/Unknown = 0
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 13568
       26    2  Int16    StateSync/CoordS / 1000 = 1
       28    4  Single   StateSync/UnknownCoordF/X = 1,291769E-39

### 0x001C IN src 2507  over=40 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 2251
       13    2  Int16    coord x = 0
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = 1219631079271432194
       30    2  Int16    speed x = 14

### 0x0045 IN src 12  over=34 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 134217728
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 3072
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 6656

### 0x00F6 IN src 12  over=34 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00F6.py
  ! Read<Int32>: wanted 4 byte(s) at offset 515, only 0 of 515 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 739, only 3 of 742 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 515, only 0 of 515 remain
  last reads before failure (of 98):
      471    4  Int32    Entry 29/QuestId? = 0
      475    8  Int64    Entry 29/Timestamp = 545319267021619200
      483    4  Int32    Entry 30/Index+1000 = -1358954496
      487    4  Int32    Entry 30/QuestId? = -2130706432
      491    8  Int64    Entry 30/Timestamp = 4026531840
      499    4  Int32    Entry 31/Index+1000 = 5963953
      503    4  Int32    Entry 31/QuestId? = 301989888
      507    8  Int64    Entry 31/Timestamp = 72057594043978687

### 0x0017 IN src 12  over=18 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 3256, only 1 of 3257 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 3248, only 4 of 3252 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 3256, only 1 of 3257 remain
  last reads before failure (of 419):
     3192    8  Int64    PlayerInfo/Player+1B0 = 386768910802228685
     3200    8  Int64    PlayerInfo/Player+1B0 = 281474976776193
     3208    8  Int64    PlayerInfo/Player+1B0 = 0
     3216    8  Int64    PlayerInfo/Player+1B0 = 0
     3224    8  Int64    PlayerInfo/Player+1B0 = 0
     3232    8  Int64    PlayerInfo/Player+1B0 = 4295622656
     3240    8  Int64    PlayerInfo/Player+1B0 = 112499538264064
     3248    8  Int64    PlayerInfo/Player+1B0 = 140737488289792

### 0x003D IN src 12  over=18 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = -3824028865937911292
        8    4  Int32    ServerTick = 731836929
       12    4  Int32    ObjectId = -1698037750
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0
