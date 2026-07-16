# Harness — MATRIX -> 2532

scripts from build : (matrix, see src column)
packets from build : 2532
packets considered : 13.533
packets executed   : 21.354  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                274   1.3%
OkExact               7.609   35.6%
UnderRead            11.348   53.1%
OverRead              2.123   9.9%

of packets a script actually ran on (21.080):
  clean (consumed exactly) : 36.1%
  over-read (WRONG)        : 10.1%
  under-read (ambiguous)   : 53.8%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0024  IN        12       3.886     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       3.886     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       3.886     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  OUT       12       2.498     1.500     0.0%   100.0%     0.0%    0.0%             7% / 7%
0x0058  IN        12       1.823     1.500     0.0%   100.0%     0.0%    0.0%            6% / 12%
0x0058  IN      2521       1.823     1.500     0.5%    99.5%     0.0%    0.0%           88% / 90%
0x0058  IN      2527       1.823     1.500     0.5%    99.5%     0.0%    0.0%           89% / 94%
0x0011  IN        12         719       719    50.5%    49.5%     0.0%    0.0%         100% / 100%
0x0012  OUT       12         602       602     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0023  IN        12         394       394     2.3%     0.0%    97.7%    0.0%         100% / 100%
0x0023  IN      2486         394       394     1.5%    98.5%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         394       394     1.5%    98.5%     0.0%    0.0%           11% / 11%
0x000B  OUT       12         359       359   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12         355       355     0.0%   100.0%     0.0%    0.0%           26% / 42%
0x002E  IN      2521         355       355     3.9%    96.1%     0.0%    0.0%           19% / 32%
0x002E  IN      2528         355       355   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CB  IN        12         351       351     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x003D  IN        12         296       296     0.0%     0.0%   100.0%    0.0%           96% / 96%
0x003D  IN      2512         296       296   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         296       296     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0021  IN        12         279       279     2.2%    96.4%     1.4%    0.0%            0% / 20%
0x0021  IN      2511         279       279     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         279       279     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         279       279     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         279       279     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         279       279     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         279       279     1.1%    98.9%     0.0%    0.0%            0% / 20%
0x001C  IN        12         244       244     0.0%     0.4%    99.6%    0.0%         100% / 100%
0x001C  IN      2507         244       244    75.4%     0.0%    24.6%    0.0%         100% / 100%
0x0047  IN        12         189       189     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x00B0  IN        12         180       180     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x007B  IN        12         174       174    50.0%    50.0%     0.0%    0.0%           1% / 100%
0x004D  IN        12         159       159     0.0%   100.0%     0.0%    0.0%           19% / 21%
0x004D  IN      2503         159       159   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504         159       159     0.0%   100.0%     0.0%    0.0%           81% / 81%
0x004D  IN      2507         159       159   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546         159       159   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549         159       159   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550         159       159   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          80        80     0.0%    96.2%     3.8%    0.0%           11% / 20%
0x005E  IN      2506          80        80   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12          73        73   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          73        73   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          73        73   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -          59         -                                     no script
0x0037  IN        12          55        55     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x004F  OUT        -          52         -                                     no script
0x0061  IN        12          33        33     0.0%     0.0%   100.0%    0.0%          99% / 100%
0x001D  IN        12          32        32   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008A  IN      2511          27        27     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          27        27    81.5%     7.4%    11.1%    0.0%         100% / 100%
0x0052  IN        12          26        26     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0052  IN      2516          26        26    65.4%    34.6%     0.0%    0.0%         100% / 100%
0x0093  IN         -          26         -                                     no script
0x00A8  IN         -          21         -                                     no script
0x00F6  IN        12          20        20     0.0%    85.0%    15.0%    0.0%            0% / 99%
0x00F6  IN      2520          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12          19        19     0.0%    78.9%    21.1%    0.0%          15% / 100%
0x0011  OUT        -          16         -                                     no script
0x0079  OUT       12          14        14    28.6%    71.4%     0.0%    0.0%          60% / 100%
0x0048  IN        12          13        13     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          13        13   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CE  IN        12          13        13     0.0%    46.2%    53.8%    0.0%          56% / 100%
0x006A  IN        12          12        12    25.0%    75.0%     0.0%    0.0%          22% / 100%
0x006A  IN      2486          12        12    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          12        12    25.0%    75.0%     0.0%    0.0%          10% / 100%
0x006A  IN      2502          12        12    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          12        12    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006C  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0055  IN        12          10        10     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          10        10     0.0%   100.0%     0.0%    0.0%           64% / 99%
0x0055  IN      2528          10        10    20.0%     0.0%    80.0%    0.0%          98% / 100%
0x0045  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           9         9     0.0%    66.7%    33.3%    0.0%           20% / 59%
0x0069  IN      2496           9         9     0.0%    66.7%    33.3%    0.0%           35% / 70%
0x0069  IN      2497           9         9     0.0%    66.7%    33.3%    0.0%           20% / 59%
0x0069  IN      2502           9         9     0.0%    66.7%    33.3%    0.0%           20% / 59%
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
0x00B6  IN        12           9         9     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x00F4  IN        12           9         9     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x0128  IN        12           9         9    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0005  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500           6         6     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           6         6     0.0%    33.3%    66.7%    0.0%         100% / 100%
0x0017  IN      2528           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2550           6         6     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0019  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           6         6    50.0%    33.3%    16.7%    0.0%         100% / 100%
0x0033  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0036  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0044  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x010A  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           6         -                                     no script
0x0123  IN         -           6         -                                     no script
0x012D  IN         -           6         -                                     no script
0x0138  IN         -           6         -                                     no script
0x00A5  IN         -           5         -                                     no script
0x0014  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12           4         4    50.0%     0.0%    50.0%    0.0%          98% / 100%
0x0020  OUT     2507           4         4    50.0%    50.0%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512           4         4    50.0%     0.0%    50.0%    0.0%          98% / 100%
0x0055  OUT        -           4         -                                     no script
0x005A  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0078  OUT        -           4         -                                     no script
0x00E6  IN         -           4         -                                     no script
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
0x0015  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0034  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0038  OUT     2511           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0054  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x005B  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006F  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x007D  IN      2486           3         3     0.0%   100.0%     0.0%    0.0%           59% / 64%
0x007D  IN      2502           3         3     0.0%   100.0%     0.0%    0.0%           58% / 63%
0x007D  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           3         3     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           3         -                                     no script
0x009E  IN         -           3         -                                     no script
0x00A7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
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
0x00CA  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00D1  IN         -           3         -                                     no script
0x00DF  IN         -           3         -                                     no script
0x00EB  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           3         -                                     no script
0x00F3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           3         -                                     no script
0x011B  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0125  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           3         -                                     no script
0x0131  IN         -           3         -                                     no script
0x0137  IN         -           3         -                                     no script
0x013A  IN         -           3         -                                     no script
0x0018  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x003C  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           2         2     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           2         -                                     no script
0x009D  IN         -           2         -                                     no script
0x0010  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0030  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  OUT        -           1         -                                     no script
0x0042  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x006C  OUT        -           1         -                                     no script
0x0079  IN        12           1         1     0.0%     0.0%   100.0%    0.0%             3% / 3%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00A4  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%           11% / 11%
0x00D6  IN         -           1         -                                     no script
0x0103  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=602 threw=0 negative-length=142
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -1536
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Single   Segment 0/StateSync/UnknownCoordF/X = NaN
       37    4  Single   Segment 0/StateSync/UnknownCoordF/Y = 1,4062669E+11

### 0x0023 IN src 12  over=385 threw=0
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

### 0x003D IN src 12  over=296 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 4236898789388745988
        8    4  Int32    ServerTick = 156702464
       12    4  Int32    ObjectId = -1698037759
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x001C IN src 12  over=243 threw=0 negative-length=10
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Single>: wanted 4 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       16    1  Byte     StateSync/Animation3 = 90
       17    2  Int16    StateSync/SpeedCoordS/X = 11520
       19    2  Int16    StateSync/SpeedCoordS/Y = -9984
       21    2  Int16    StateSync/SpeedCoordS/Z = 4607
       23    1  Byte     StateSync/Unknown = 0
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = -1536
       26    2  Int16    StateSync/CoordS / 1000 = 0
       28    4  Single   StateSync/UnknownCoordF/X = NaN

### 0x0047 IN src 12  over=189 threw=0 negative-length=143
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -26652 at offset 3/40
  ! ReadBytes: negative length -26652 at offset 3/40
  ! ReadBytes: negative length -26652 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -13326

### 0x00B0 IN src 12  over=180 threw=0 negative-length=60
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -54270 at offset 6/20
  ! ReadBytes: negative length -54270 at offset 6/20
  ! ReadBytes: negative length -54270 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037056
        4    2  Int16    Motto/size = -27135

### 0x001C IN src 2507  over=60 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 151
       13    2  Int16    coord x = 0
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -578994022043877359
       30    2  Int16    speed x = 0

### 0x0061 IN src 12  over=33 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Single>: wanted 4 byte(s) at offset 1091, only 2 of 1093 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=9 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 16777216
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 0
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0

### 0x0055 IN src 2528  over=8 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0055.py
  ! Read<Int32>: wanted 4 byte(s) at offset 137, only 3 of 140 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 137, only 3 of 140 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 137, only 3 of 140 remain
  last reads before failure (of 34):
      103    8  Int64    buff 0/additionalEffect2/additionalEffect2 = 0
      111    4  Int32    buff 1/TargetObjectId = 0
      115    4  Int32    buff 1/BuffObjectId = 50
      119    4  Int32    buff 1/OwnerObjectId = 0
      123    4  Int32    buff 1/additionalEffect/StartServerTick = 65536
      127    4  Int32    buff 1/additionalEffect/EndServerTick = -1734279168
      131    4  Int32    buff 1/additionalEffect/SkillId = 66284
      135    2  Int16    buff 1/additionalEffect/SkillLevel = 0

### 0x00CE IN src 12  over=7 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00CE.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1, only 0 of 1 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 248, only 2 of 250 remain
  ! Read<Single>: wanted 4 byte(s) at offset 219, only 1 of 220 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 6

### 0x0017 IN src 12  over=6 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 1957, only 6 of 1963 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1806, only 7 of 1813 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1806, only 7 of 1813 remain
  last reads before failure (of 258):
     1893    8  Int64    PlayerInfo/Player+1B0 = 211935616536998400
     1901    8  Int64    PlayerInfo/Player+1B0 = 72058696186371410
     1909    8  Int64    PlayerInfo/Player+1B0 = 16777216
     1917    8  Int64    PlayerInfo/Player+1B0 = 0
     1925    8  Int64    PlayerInfo/Player+1B0 = 0
     1933    8  Int64    PlayerInfo/Player+1B0 = 167773451845632
     1941    8  Int64    PlayerInfo/Player+1B0 = 0
     1949    8  Int64    PlayerInfo/Player+1B0 = -72057594037927936
