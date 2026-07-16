# Harness — MATRIX -> 2518

scripts from build : (matrix, see src column)
packets from build : 2518
packets considered : 9.206
packets executed   : 12.870  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                552   4.3%
OkExact               4.199   32.6%
UnderRead             5.776   44.9%
OverRead              2.343   18.2%

of packets a script actually ran on (12.318):
  clean (consumed exactly) : 34.1%
  over-read (WRONG)        : 19.0%
  under-read (ambiguous)   : 46.9%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12       4.481     1.500     2.9%     0.6%    96.5%    0.0%          92% / 100%
0x0058  IN        12       1.804     1.500     0.0%   100.0%     0.0%    0.0%            7% / 13%
0x0058  IN      2521       1.804     1.500    39.7%    60.3%     0.0%    0.0%          97% / 100%
0x0058  IN      2527       1.804     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12         605       605     1.5%     0.0%    98.5%    0.0%         100% / 100%
0x0023  IN      2486         605       605     1.0%    99.0%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         605       605     1.0%    99.0%     0.0%    0.0%           11% / 11%
0x007E  IN         -         412         -                                     no script
0x0024  IN        12         376       376   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         376       376   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         376       376   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        12         210       210    51.4%    48.6%     0.0%    0.0%         100% / 100%
0x0021  IN        12         195       195     0.5%    98.5%     1.0%    0.0%            0% / 20%
0x0021  IN      2511         195       195     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         195       195     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         195       195     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         195       195     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         195       195     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         195       195     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x000B  OUT       12         104       104   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          87        87     0.0%    96.6%     3.4%    0.0%           10% / 35%
0x005E  IN      2506          87        87   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12          69        69     0.0%    97.1%     2.9%    0.0%            1% / 10%
0x0055  IN      2521          69        69     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          69        69   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12          51        51     0.0%     0.0%   100.0%    0.0%             7% / 8%
0x0056  IN        12          49        49     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0052  IN        12          42        42     0.0%    95.2%     4.8%    0.0%            8% / 85%
0x0052  IN      2516          42        42    38.1%    59.5%     2.4%    0.0%          11% / 100%
0x003D  IN        12          29        29     3.4%     0.0%    96.6%    0.0%           84% / 84%
0x003D  IN      2512          29        29    96.6%     3.4%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          29        29    96.6%     3.4%     0.0%    0.0%         100% / 100%
0x004E  IN        12          21        21    38.1%     0.0%    61.9%    0.0%          18% / 100%
0x0063  IN        12          21        21     0.0%     9.5%    90.5%    0.0%           16% / 43%
0x0063  IN      2507          21        21    76.2%    23.8%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          21        21    76.2%    23.8%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          21         -                                     no script
0x002B  IN        12          20        20     0.0%    80.0%    20.0%    0.0%           93% / 93%
0x002B  IN      2530          20        20    95.0%     0.0%     5.0%    0.0%         100% / 100%
0x002B  IN      2531          20        20    95.0%     0.0%     5.0%    0.0%         100% / 100%
0x008A  IN      2511          20        20     5.0%    95.0%     0.0%    0.0%             0% / 4%
0x008A  IN      2524          20        20    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x002E  IN        12          19        19     0.0%   100.0%     0.0%    0.0%            2% / 26%
0x002E  IN      2521          19        19    78.9%    10.5%    10.5%    0.0%         100% / 100%
0x002E  IN      2528          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  IN        12          17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12          17        17     5.9%    94.1%     0.0%    0.0%           53% / 53%
0x0039  IN        12          17        17     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x001D  OUT       12          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0093  IN         -          15         -                                     no script
0x004F  OUT        -          13         -                                     no script
0x006C  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00F6  IN        12          12        12     0.0%    83.3%    16.7%    0.0%           0% / 100%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12          11        11     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0061  IN        12          10        10     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x006A  IN        12          10        10    50.0%    50.0%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          10        10    70.0%    30.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          10        10    30.0%    70.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          10        10    40.0%    60.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          10        10    40.0%    60.0%     0.0%    0.0%          20% / 100%
0x00B6  IN        12          10        10     0.0%    70.0%    30.0%    0.0%           24% / 80%
0x0045  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2496           9         9     0.0%    66.7%    33.3%    0.0%           51% / 90%
0x0069  IN      2497           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2502           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2503           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x006B  IN        12           9         9     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  OUT       12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12           8         8     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x0048  IN        12           8         8     0.0%    75.0%    25.0%    0.0%          48% / 100%
0x0048  IN      2504           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           8         8    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x004B  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507           8         8    25.0%    75.0%     0.0%    0.0%           6% / 100%
0x005B  IN        12           8         8     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0128  IN        12           8         8    25.0%    75.0%     0.0%    0.0%          14% / 100%
0x001D  IN        12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           7         7    28.6%    14.3%    57.1%    0.0%          90% / 100%
0x011C  IN         -           7         -                                     no script
0x0019  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           6         6    50.0%    16.7%    33.3%    0.0%         100% / 100%
0x0021  OUT       12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x0044  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x006F  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00CC  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x010A  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x012D  IN         -           6         -                                     no script
0x0034  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0123  IN         -           5         -                                     no script
0x0005  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A5  IN         -           4         -                                     no script
0x0001  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           3         -                                     no script
0x000F  OUT        -           3         -                                     no script
0x0010  OUT        -           3         -                                     no script
0x0013  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           3         3     0.0%    66.7%    33.3%    0.0%          56% / 100%
0x0017  IN      2528           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0029  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0035  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  OUT        -           3         -                                     no script
0x003C  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           3         3     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           3         3     0.0%    33.3%    66.7%    0.0%         100% / 100%
0x0055  OUT        -           3         -                                     no script
0x0073  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           3         3     0.0%    33.3%    66.7%    0.0%           56% / 56%
0x007D  IN      2486           3         3     0.0%    33.3%    66.7%    0.0%         100% / 100%
0x007D  IN      2502           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           3         -                                     no script
0x009E  IN         -           3         -                                     no script
0x00A7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          41% / 100%
0x00AD  IN         -           3         -                                     no script
0x00B0  OUT        -           3         -                                     no script
0x00B2  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           3         -                                     no script
0x00B7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           3         -                                     no script
0x00CA  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00D1  IN         -           3         -                                     no script
0x00DF  IN         -           3         -                                     no script
0x00E6  IN         -           3         -                                     no script
0x00EB  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           3         -                                     no script
0x00F3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           3         -                                     no script
0x011B  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0125  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           3         -                                     no script
0x0131  IN         -           3         -                                     no script
0x0137  IN         -           3         -                                     no script
0x0138  IN         -           3         -                                     no script
0x0011  OUT        -           2         -                                     no script
0x0031  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x004C  IN        12           2         2     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A4  IN         -           2         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  OUT        -           1         -                                     no script
0x001E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x002D  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x004D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           1         1     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x004D  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0057  OUT        -           1         -                                     no script
0x0060  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0066  OUT        -           1         -                                     no script
0x006C  OUT        -           1         -                                     no script
0x0103  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.448 threw=0 negative-length=574
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -18910 at offset 35/51
  ! ReadBytes: negative length -17720 at offset 39/41
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 19):
       21    1  Byte     Segment 0/StateSync/Animation3 = 90
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 7
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2055
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 1792
       33    2  Int16    Segment 0/StateSync/AnimationString?/size = -9455

### 0x0023 IN src 12  over=596 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0023.py
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 197, only 0 of 197 remain
  last reads before failure (of 59):
      167    4  Int32    Item: 50100000/Stats/Unknown = 0
      171    4  Int32    Item: 50100000/ItemEnchant/Enchants = 0
      175    4  Int32    Item: 50100000/ItemEnchant/EnchantExp = 1
      179    1  Byte     Item: 50100000/ItemEnchant/EnchantBasedChargeExp = 0
      180    8  Int64    Item: 50100000/ItemEnchant/Unknown = 0
      188    4  Int32    Item: 50100000/ItemEnchant/Unknown = 0
      192    4  Int32    Item: 50100000/ItemEnchant/Unknown = 0
      196    1  Boolean  Item: 50100000/ItemEnchant/CanRepackage = False

### 0x0047 IN src 12  over=51 threw=0 negative-length=10
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -45846 at offset 3/40
  ! ReadBytes: negative length -45846 at offset 3/40
  ! ReadBytes: negative length -45846 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -22923

### 0x0056 IN src 12  over=49 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 28415

### 0x003D IN src 12  over=28 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  last reads before failure (of 3):
        0    8  Int64    SkillUseUid = 5
        8    4  Int32    ServerTick = 7291136
       12    4  Int32    ObjectId = 7291136

### 0x0063 IN src 12  over=19 threw=0 negative-length=10
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 29388 byte(s) at offset 27, only 878 of 905 remain
  ! ReadBytes: wanted 334 byte(s) at offset 27, only 139 of 166 remain
  ! ReadBytes: wanted 426 byte(s) at offset 27, only 139 of 166 remain
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 7377177802048536601
        9    8  Int64    Entry/CharacterId = 3990863692230374455
       17    8  Int64    Entry/AccountId = 3558178379024065079
       25    2  Int16    Entry/Name/size = 14694

### 0x004E IN src 12  over=13 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004E.py
  ! ReadBytes: wanted 1200 byte(s) at offset 7, only 8 of 15 remain
  ! ReadBytes: wanted 6018 byte(s) at offset 7, only 174 of 181 remain
  ! ReadBytes: wanted 6000 byte(s) at offset 3, only 14 of 17 remain
  last reads before failure (of 3):
        0    1  Byte     Function = 2
        1    4  Int32    count = 2
        5    2  Int16    FunctionCubeName/size = 600

### 0x0061 IN src 12  over=10 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5359, only 2 of 5361 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 3847, only 2 of 3849 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=9 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 134217728
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 2304
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 5632

### 0x005B IN src 12  over=8 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x005B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 14189550

### 0x003F IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003F.py
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  last reads before failure (of 2):
        0    8  Int64    SkillCastId = 64089988804282
        8    4  Int32    OwnerObjectId = 17868405

### 0x006F IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x006F.py
  ! Read<Int16>: wanted 2 byte(s) at offset 6814, only 0 of 6814 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 6686, only 2 of 6688 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 6811, only 3 of 6814 remain
  last reads before failure (of 2019):
     6798    2  Int16    Type 7/unknown = 0
     6800    2  Int16    Type 7/unknown = 0
     6802    2  Int16    Type 7/unknown = 0
     6804    2  Int16    Type 7/unknown = 0
     6806    2  Int16    Type 7/unknown = 0
     6808    2  Int16    Type 7/unknown = 0
     6810    2  Int16    Type 7/unknown = 0
     6812    2  Int16    Type 7/unknown = 0
