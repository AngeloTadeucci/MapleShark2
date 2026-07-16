# Harness — MATRIX -> 2465

scripts from build : (matrix, see src column)
packets from build : 2465
packets considered : 4.694
packets executed   : 10.022  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                130   1.3%
OkExact               6.732   67.2%
UnderRead             2.992   29.9%
OverRead                167   1.7%
Threw                     1   0.0%

of packets a script actually ran on (9.892):
  clean (consumed exactly) : 68.1%
  over-read (WRONG)        : 1.7%
  under-read (ambiguous)   : 30.2%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12       1.293     1.293     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521       1.293     1.293   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  IN      2527       1.293     1.293   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  OUT       12       1.208     1.208   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN        12         514       514   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         514       514   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         514       514   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        12         437       437    50.3%    49.7%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         218       218   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN        12         137       137   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN      2511         137       137     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         137       137     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         137       137     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         137       137     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         137       137     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         137       137     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0023  IN        12         125       125   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN      2486         125       125     1.6%    98.4%     0.0%    0.0%           14% / 14%
0x0023  IN      2502         125       125     1.6%    98.4%     0.0%    0.0%             9% / 9%
0x00B0  IN        12          90        90     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x004D  IN        12          57        57     0.0%   100.0%     0.0%    0.0%           21% / 21%
0x004D  IN      2503          57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504          57        57     0.0%   100.0%     0.0%    0.0%           79% / 79%
0x004D  IN      2507          57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546          57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549          57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550          57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN        12          55        55   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          55        55   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          55        55   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12          38        38     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x0037  IN        12          36        36     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x005E  IN        12          29        29     0.0%    96.6%     3.4%    0.0%            0% / 26%
0x005E  IN      2506          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12          26        26     7.7%    88.5%     3.8%    0.0%            1% / 90%
0x006C  IN        12          26        26     0.0%   100.0%     0.0%    0.0%            8% / 50%
0x003A  OUT        -          23         -                                     no script
0x0048  IN        12          20        20     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0093  IN         -          15         -                                     no script
0x00AD  IN         -          15         -                                     no script
0x0011  OUT        -          14         -                                     no script
0x008A  IN      2511          13        13     0.0%   100.0%     0.0%    0.0%            1% / 20%
0x008A  IN      2524          13        13    76.9%     0.0%    15.4%    7.7%         100% / 100%
0x00F6  IN        12          12        12     0.0%    83.3%    16.7%    0.0%           0% / 100%
0x00F6  IN      2520          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12          11        11     0.0%   100.0%     0.0%    0.0%            2% / 42%
0x002E  IN      2521          11        11    63.6%    36.4%     0.0%    0.0%         100% / 100%
0x002E  IN      2528          11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          11        11     0.0%   100.0%     0.0%    0.0%            0% / 11%
0x0052  IN      2516          11        11    72.7%    27.3%     0.0%    0.0%         100% / 100%
0x0061  IN        12          11        11     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x006B  OUT        -          11         -                                     no script
0x0050  OUT        -          10         -                                     no script
0x007E  IN         -           8         -                                     no script
0x0056  OUT       12           7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -           7         -                                     no script
0x0069  IN        12           5         5     0.0%   100.0%     0.0%    0.0%            4% / 20%
0x0069  IN      2486           5         5    20.0%    80.0%     0.0%    0.0%          96% / 100%
0x0069  IN      2496           5         5    20.0%    80.0%     0.0%    0.0%          20% / 100%
0x0069  IN      2497           5         5    20.0%    80.0%     0.0%    0.0%           4% / 100%
0x0069  IN      2502           5         5    60.0%    40.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2503           5         5     0.0%   100.0%     0.0%    0.0%            4% / 20%
0x0069  IN      2504           5         5     0.0%   100.0%     0.0%    0.0%            4% / 20%
0x0069  IN      2521           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2546           5         5     0.0%   100.0%     0.0%    0.0%            4% / 20%
0x0069  IN      2549           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0069  IN      2550           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12           4         4    25.0%    75.0%     0.0%    0.0%          22% / 100%
0x006A  IN      2486           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           4         4    25.0%    75.0%     0.0%    0.0%          10% / 100%
0x006A  IN      2502           4         4    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503           4         4    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x0081  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12           4         4     0.0%    75.0%    25.0%    0.0%            2% / 50%
0x00F4  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x012D  IN         -           4         -                                     no script
0x0005  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           30% / 30%
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0068  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0068  IN      2486           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%            3% / 24%
0x00E6  IN         -           3         -                                     no script
0x0123  IN         -           3         -                                     no script
0x0128  IN        12           3         3    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001E  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0037  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  OUT     2502           2         2     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x0044  IN        12           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x006E  IN      2486           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007B  IN        12           2         2    50.0%    50.0%     0.0%    0.0%           0% / 100%
0x008F  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A5  IN         -           2         -                                     no script
0x00CB  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            1% / 10%
0x00EB  IN        12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F5  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           10% / 78%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x0001  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           1         -                                     no script
0x000F  OUT        -           1         -                                     no script
0x0010  OUT        -           1         -                                     no script
0x0013  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN      2507           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           60% / 60%
0x0017  IN      2500           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x0017  IN      2528           1         1     0.0%     0.0%   100.0%    0.0%           60% / 60%
0x0017  IN      2550           1         1     0.0%     0.0%   100.0%    0.0%           60% / 60%
0x001F  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507           1         1     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0020  OUT     2512           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002D  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506           1         1     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0067  OUT        -           1         -                                     no script
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0071  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0073  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007A  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x007D  IN      2486           1         1     0.0%   100.0%     0.0%    0.0%           54% / 54%
0x007D  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%           53% / 53%
0x007D  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%           77% / 77%
0x007D  IN      2546           1         1     0.0%   100.0%     0.0%    0.0%           77% / 77%
0x007D  IN      2549           1         1     0.0%   100.0%     0.0%    0.0%           77% / 77%
0x007D  IN      2550           1         1     0.0%   100.0%     0.0%    0.0%           77% / 77%
0x0089  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009E  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00B1  OUT        -           1         -                                     no script
0x00B2  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B6  OUT       12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x00B7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           1         -                                     no script
0x00CA  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00D1  IN         -           1         -                                     no script
0x00DF  IN         -           1         -                                     no script
0x00EE  IN         -           1         -                                     no script
0x00F3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0130  IN         -           1         -                                     no script

## Sample failures

### 0x00B0 IN src 12  over=90 threw=0 negative-length=90
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -22014 at offset 6/20
  ! ReadBytes: negative length -63486 at offset 6/20
  ! ReadBytes: negative length -43518 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037568
        4    2  Int16    Motto/size = -11007

### 0x0047 IN src 12  over=38 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: wanted 16508 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 16508 byte(s) at offset 3, only 37 of 40 remain
  ! ReadBytes: wanted 16508 byte(s) at offset 3, only 37 of 40 remain
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = 8254

### 0x0061 IN src 12  over=11 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 4927, only 2 of 4929 remain
  ! Read<Single>: wanted 4 byte(s) at offset 4971, only 0 of 4971 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 18, only 1 of 19 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 301989888
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 3072
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 12800

### 0x008A IN src 2524  over=2 threw=1 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2524\Inbound\0x008A.py
  ! name 'decode_guild_rank' is not defined
  ! ReadBytes: negative length -30956 at offset 3/5
  ! Read<Int64>: wanted 8 byte(s) at offset 15, only 4 of 19 remain
  last reads before failure (of 3393):
    24545    4  Int32    Guild Members/GuildMember/Unknown = 26003001
    24549    4  Int32    Guild Members/GuildMember/Unknown = 1000
    24553    4  Int32    Guild Members/GuildMember/Unknown = 26004001
    24557    4  Int32    Guild Members/GuildMember/Unknown = 1000
    24561    4  Int32    Guild Members/GuildMember/Unknown = 26005001
    24565    4  Int32    Guild Members/GuildMember/Unknown = 1000
    24569    1  Boolean  Guild Members/GuildMember/CanCheckIn? = True
    24570    1  Byte     GuildRanks/GuildRanksCount = 6

### 0x002F IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 3088446
        4    1  Byte     Function = 1

### 0x00EB IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00EB.py
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    CameraId = 1
        4    1  Boolean  Enabled = False

### 0x00F6 IN src 12  over=2 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00F6.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1575, only 1 of 1576 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 1843, only 2 of 1845 remain
  last reads before failure (of 297):
     1531    8  Int64    Entry 95/Timestamp = 0
     1539    4  Int32    Entry 96/Index+1000 = -1856177168
     1543    4  Int32    Entry 96/QuestId? = 7
     1547    8  Int64    Entry 96/Timestamp = 4084513899543
     1555    4  Int32    Entry 97/Index+1000 = 1333
     1559    4  Int32    Entry 97/QuestId? = 1509642595
     1563    8  Int64    Entry 97/Timestamp = 6817493415341588480
     1571    4  Int32    Entry 98/Index+1000 = 0

### 0x0017 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 13012 byte(s) at offset 3410, only 2301 of 5711 remain
  last reads before failure (of 975):
     3377    1  Boolean  InBattle = True
     3378    1  Byte     gameObject_vtbl+572 virtual call/Unknown = 0
     3379    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 0
     3383    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 4467570830351532032
     3391    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = 4467899618755096352
     3399    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
     3400    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = -3838446310944735185
     3408    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = 6506

### 0x0035 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0

### 0x0054 IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0054.py
  ! Read<Int32>: wanted 4 byte(s) at offset 9, only 1 of 10 remain
  last reads before failure (of 2):
        0    1  Byte     function = 14
        1    8  Int64    CharacterId = 4294967296

### 0x005E IN src 12  over=1 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x005E.py
  ! Read<Int32>: wanted 4 byte(s) at offset 0, only 1 of 1 remain
  last reads before failure (of 0):
