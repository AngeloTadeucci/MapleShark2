# Harness — MATRIX -> 2550

scripts from build : (matrix, see src column)
packets from build : 2550
packets considered : 15.856
packets executed   : 22.687  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                527   2.3%
OkExact               6.039   26.6%
UnderRead            12.250   54.0%
OverRead              3.871   17.1%

of packets a script actually ran on (22.160):
  clean (consumed exactly) : 27.3%
  over-read (WRONG)        : 17.5%
  under-read (ambiguous)   : 55.3%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12       5.718     1.500     0.5%     0.2%    99.3%    0.0%          95% / 100%
0x0058  IN        12       3.372     1.500     0.0%   100.0%     0.0%    0.0%            5% / 12%
0x0058  IN      2521       3.372     1.500     7.4%    92.6%     0.0%    0.0%           94% / 97%
0x0058  IN      2527       3.372     1.500    66.1%    33.9%     0.0%    0.0%         100% / 100%
0x0023  IN        12       1.374     1.374     0.9%     0.0%    99.1%    0.0%         100% / 100%
0x0023  IN      2486       1.374     1.374     0.6%    99.4%     0.0%    0.0%           17% / 17%
0x0023  IN      2502       1.374     1.374     0.6%    99.4%     0.0%    0.0%           11% / 11%
0x0011  IN        12         727       727    50.8%    49.2%     0.0%    0.0%         100% / 100%
0x002E  IN        12         594       594     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521         594       594    10.6%    86.7%     2.7%    0.0%          19% / 100%
0x002E  IN      2528         594       594   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12         483       483     6.4%     0.0%    93.6%    0.0%          84% / 100%
0x003D  IN      2512         483       483    85.1%     9.7%     5.2%    0.0%         100% / 100%
0x003D  IN      2520         483       483    64.4%    34.4%     1.2%    0.0%         100% / 100%
0x0021  IN        12         396       396     0.3%    98.7%     1.0%    0.0%            0% / 20%
0x0021  IN      2511         396       396     0.0%    99.5%     0.5%    0.0%            0% / 20%
0x0021  IN      2525         396       396     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         396       396     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         396       396     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         396       396     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         396       396     0.5%    99.5%     0.0%    0.0%            0% / 20%
0x000B  OUT       12         362       362   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12         312       312    98.7%     0.0%     1.3%    0.0%         100% / 100%
0x0020  OUT     2507         312       312    45.8%    54.2%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512         312       312    98.7%     0.0%     1.3%    0.0%         100% / 100%
0x007E  IN         -         306         -                                     no script
0x005E  IN        12         229       229     0.0%    98.3%     1.7%    0.0%           10% / 16%
0x005E  IN      2506         229       229   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN        12         131       131     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521         131       131     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528         131       131    98.5%     0.8%     0.8%    0.0%         100% / 100%
0x0047  IN        12         101       101     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0024  IN        12          99        99   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502          99        99   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507          99        99   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN        12          89        89     0.0%     0.0%   100.0%    0.0%           93% / 93%
0x002B  IN      2530          89        89    95.5%     0.0%     4.5%    0.0%         100% / 100%
0x002B  IN      2531          89        89    95.5%     0.0%     4.5%    0.0%         100% / 100%
0x0006  IN        12          86        86   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          86        86   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          86        86   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  IN        12          81        81   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  IN        12          81        81     4.9%    95.1%     0.0%    0.0%           53% / 53%
0x003C  IN        12          79        79     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506          79        79     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507          79        79   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512          79        79   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520          79        79   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  IN        12          77        77     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x0075  IN        12          70        70     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0075  IN      2529          70        70   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  OUT       12          68        68   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B0  IN        12          60        60     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0056  IN        12          58        58     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0052  IN        12          50        50     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          50        50    66.0%    34.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12          34        34     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x00F6  IN        12          32        32     0.0%    75.0%    25.0%    0.0%           0% / 100%
0x00F6  IN      2520          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          28         -                                     no script
0x0026  OUT       12          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN        12          26        26     0.0%     0.0%   100.0%    0.0%           16% / 52%
0x0063  IN      2507          26        26    69.2%    30.8%     0.0%    0.0%         100% / 100%
0x0063  IN      2518          26        26    69.2%    30.8%     0.0%    0.0%         100% / 100%
0x0069  IN        12          24        24     0.0%   100.0%     0.0%    0.0%           20% / 33%
0x0069  IN      2486          24        24     0.0%    83.3%    16.7%    0.0%           33% / 53%
0x0069  IN      2496          24        24     0.0%    83.3%    16.7%    0.0%           33% / 53%
0x0069  IN      2497          24        24     0.0%    83.3%    16.7%    0.0%           33% / 53%
0x0069  IN      2502          24        24     8.3%    75.0%    16.7%    0.0%           33% / 53%
0x0069  IN      2503          24        24     4.2%    95.8%     0.0%    0.0%           20% / 33%
0x0069  IN      2504          24        24     4.2%    95.8%     0.0%    0.0%           20% / 33%
0x0069  IN      2521          24        24    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x0069  IN      2546          24        24     0.0%   100.0%     0.0%    0.0%           20% / 33%
0x0069  IN      2549          24        24    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x0069  IN      2550          24        24    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x0093  IN         -          23         -                                     no script
0x0061  IN        12          20        20     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0123  IN         -          20         -                                     no script
0x008A  IN      2511          17        17     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x008A  IN      2524          17        17    76.5%    23.5%     0.0%    0.0%         100% / 100%
0x002F  IN        12          16        16     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006C  IN        12          16        16     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x006A  IN        12          14        14    35.7%    64.3%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          14        14    71.4%    28.6%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          14        14    28.6%    71.4%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          14        14    42.9%    57.1%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          14        14    42.9%    57.1%     0.0%    0.0%          20% / 100%
0x00B6  IN        12          14        14     0.0%    71.4%    28.6%    0.0%           14% / 36%
0x0045  IN        12          12        12     0.0%    33.3%    66.7%    0.0%           98% / 98%
0x006B  IN        12          12        12     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507          12        12    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          12        12     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524          12        12    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525          12        12     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546          12        12     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549          12        12     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0128  IN        12          12        12    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x013B  IN         -          12         -                                     no script
0x0048  IN        12          11        11     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011C  IN         -          10         -                                     no script
0x004F  OUT        -           9         -                                     no script
0x0019  IN        12           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           8         8    50.0%    50.0%     0.0%    0.0%          11% / 100%
0x0044  IN        12           8         8     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           8         8     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CC  IN        12           8         8     0.0%   100.0%     0.0%    0.0%            2% / 50%
0x010A  IN        12           8         8     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x012D  IN         -           8         -                                     no script
0x0138  IN         -           8         -                                     no script
0x0034  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12           6         6     0.0%    66.7%    33.3%    0.0%           2% / 100%
0x004C  IN      2512           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A5  IN         -           6         -                                     no script
0x00F4  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            1% / 24%
0x0005  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           5         5     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           5         -                                     no script
0x00EB  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0001  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           4         -                                     no script
0x000F  OUT        -           4         -                                     no script
0x0010  OUT        -           4         -                                     no script
0x0013  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           4         4     0.0%   100.0%     0.0%    0.0%           42% / 42%
0x0017  IN      2528           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x001C  OUT        -           4         -                                     no script
0x001F  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0035  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0035  OUT       12           4         4     0.0%     0.0%   100.0%    0.0%           82% / 94%
0x0036  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           4         4     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           4         -                                     no script
0x006F  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           4         4     0.0%    25.0%    75.0%    0.0%           19% / 56%
0x007D  IN      2486           4         4     0.0%    50.0%    50.0%    0.0%          40% / 100%
0x007D  IN      2502           4         4    50.0%    50.0%     0.0%    0.0%          39% / 100%
0x007D  IN      2503           4         4    50.0%    50.0%     0.0%    0.0%          83% / 100%
0x007D  IN      2546           4         4    50.0%    50.0%     0.0%    0.0%          83% / 100%
0x007D  IN      2549           4         4    50.0%    50.0%     0.0%    0.0%          83% / 100%
0x007D  IN      2550           4         4    50.0%    50.0%     0.0%    0.0%          83% / 100%
0x0089  IN      2527           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           4         -                                     no script
0x00A4  IN         -           4         -                                     no script
0x00A7  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           41% / 41%
0x00AD  IN         -           4         -                                     no script
0x00B0  OUT        -           4         -                                     no script
0x00B2  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00B3  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           4         -                                     no script
0x00B7  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           4         -                                     no script
0x00CA  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           10% / 20%
0x00CB  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -           4         -                                     no script
0x00DF  IN         -           4         -                                     no script
0x00E6  IN         -           4         -                                     no script
0x00EA  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            1% / 12%
0x00EA  IN      2504           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EA  IN      2507           4         4     0.0%   100.0%     0.0%    0.0%            1% / 12%
0x00EE  IN         -           4         -                                     no script
0x00F3  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           4         -                                     no script
0x011B  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           4         -                                     no script
0x0131  IN         -           4         -                                     no script
0x013A  IN         -           4         -                                     no script
0x013C  IN         -           4         -                                     no script
0x0021  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502           3         3     0.0%   100.0%     0.0%    0.0%            5% / 73%
0x003F  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0041  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           97% / 97%
0x004E  IN        12           3         3     0.0%    66.7%    33.3%    0.0%             6% / 6%
0x002E  OUT       12           2         2     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0036  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004A  OUT       12           2         2     0.0%    50.0%    50.0%    0.0%           17% / 20%
0x004F  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004F  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           2         -                                     no script
0x0068  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            3% / 20%
0x0068  IN      2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006E  IN      2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0084  IN        12           2         2     0.0%    50.0%    50.0%    0.0%            0% / 33%
0x0090  IN         -           2         -                                     no script
0x0092  IN         -           2         -                                     no script
0x0094  IN         -           2         -                                     no script
0x00C1  IN         -           2         -                                     no script
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0090  OUT     2504           1         1     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x00CF  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00D6  IN         -           1         -                                     no script
0x011F  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.490 threw=0 negative-length=343
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -2 at offset 35/41
  ! Read<Int32>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 19):
       21    1  Byte     Segment 0/StateSync/Animation3 = 90
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 131
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 2051
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    2  Int16    Segment 0/StateSync/AnimationString?/size = -1

### 0x0023 IN src 12  over=1.361 threw=0
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

### 0x003D IN src 12  over=452 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 16, only 3 of 19 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 1 of 42 remain
  last reads before failure (of 3):
        0    8  Int64    SkillUseUid = 5
        8    4  Int32    ServerTick = 2670080
       12    4  Int32    ObjectId = 2670080

### 0x0047 IN src 12  over=101 threw=0 negative-length=74
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -41354 at offset 3/40
  ! ReadBytes: negative length -41354 at offset 3/40
  ! ReadBytes: negative length -41354 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -20677

### 0x002B IN src 12  over=89 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 3 of 45 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 245, only 3 of 248 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 224, only 0 of 224 remain
  last reads before failure (of 11):
       12    1  Boolean  flag = True
       13    8  Int64    Uid = 2671622678039155243
       21    4  Single   positionCoordF/X = -7,990579E-26
       25    4  Single   positionCoordF/Y = 6,343164E-39
       29    4  Single   positionCoordF/Z = -1,01708026E-23
       33    4  Int32    ownerObjectId = 98466
       37    4  Int32    Unknown = 1
       41    1  Byte     Unknown = 21

### 0x00B0 IN src 12  over=60 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: wanted 8706 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 44034 byte(s) at offset 6, only 14 of 20 remain
  ! ReadBytes: wanted 44034 byte(s) at offset 6, only 14 of 20 remain
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593046528
        4    2  Int16    Motto/size = 4353

### 0x0056 IN src 12  over=58 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0056.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    ObjectId = 10313

### 0x0063 IN src 12  over=26 threw=0 negative-length=5
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0063.py
  ! ReadBytes: wanted 25698 byte(s) at offset 27, only 446 of 473 remain
  ! ReadBytes: wanted 334 byte(s) at offset 27, only 139 of 166 remain
  ! ReadBytes: wanted 426 byte(s) at offset 27, only 139 of 166 remain
  last reads before failure (of 5):
        0    1  Byte     function = 8
        1    8  Int64    Entry/EntryUid = 3630182912076283917
        9    8  Int64    Entry/CharacterId = 7005411004355207780
       17    8  Int64    Entry/AccountId = 4062584651090505776
       25    2  Int16    Entry/Name/size = 12849

### 0x003D IN src 2512  over=25 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2512\Inbound\0x003D.py
  ! Read<Int32>: wanted 4 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 40, only 1 of 41 remain
  last reads before failure (of 14):
       20    1  Byte     AttackPoint = 0
       21    2  Int16    ImpactPositionCoordS/X = -6890
       23    2  Int16    ImpactPositionCoordS/Y = 2333
       25    2  Int16    ImpactPositionCoordS/Z = 1499
       27    4  Single   ImpactDirectionCoordF/X = 0,89515156
       31    4  Single   ImpactDirectionCoordF/Y = -0,44576192
       35    4  Single   ImpactDirectionCoordF/Z = 0
       39    1  Byte     Unknown = 1

### 0x0061 IN src 12  over=20 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5403, only 0 of 5403 remain
  ! Read<Single>: wanted 4 byte(s) at offset 5201, only 0 of 5201 remain
  last reads before failure (of 0):

### 0x002F IN src 12  over=16 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 25210683
        4    1  Byte     Function = 1

### 0x002E IN src 2521  over=16 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2521\Inbound\0x002E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 42, only 0 of 42 remain
  last reads before failure (of 12):
       10    4  Int32    0 base = 0
       14    4  Int32    0 total = 100
       18    4  Int32    1 bonus = 11764618
       22    4  Int32    1 base = 0
       26    4  Int32    1 total = 100
       30    4  Int32    2 bonus = 11764618
       34    4  Int32    2 base = 0
       38    4  Int32    2 total = 100
