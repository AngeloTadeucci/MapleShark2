# Harness — MATRIX -> 2514

scripts from build : (matrix, see src column)
packets from build : 2514
packets considered : 2.706
packets executed   : 5.366  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                 59   1.1%
OkExact               1.478   27.5%
UnderRead             2.123   39.6%
OverRead              1.706   31.8%

of packets a script actually ran on (5.307):
  clean (consumed exactly) : 27.9%
  over-read (WRONG)        : 32.1%
  under-read (ambiguous)   : 40.0%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0012  OUT       12         952       952     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x001C  IN        12         453       453     1.5%     0.0%    98.5%    0.0%         100% / 100%
0x001C  IN      2507         453       453    92.3%     0.0%     7.7%    0.0%         100% / 100%
0x0058  IN        12         450       450     0.0%   100.0%     0.0%    0.0%           12% / 12%
0x0058  IN      2521         450       450     0.0%   100.0%     0.0%    0.0%           88% / 90%
0x0058  IN      2527         450       450     0.0%   100.0%     0.0%    0.0%           88% / 94%
0x0024  IN        12         275       275   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502         275       275   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507         275       275   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EA  IN        12         126       126     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00EA  IN      2504         126       126     0.0%     0.0%   100.0%    0.0%           16% / 16%
0x00EA  IN      2507         126       126     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B0  IN        12          60        60     0.0%     0.0%   100.0%    0.0%           30% / 30%
0x0011  IN        12          59        59    52.5%    47.5%     0.0%    0.0%         100% / 100%
0x0021  IN        12          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2511          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2525          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2529          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2546          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2549          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0021  IN      2550          35        35     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0023  IN        12          31        31     9.7%     0.0%    90.3%    0.0%         100% / 100%
0x0023  IN      2486          31        31     6.5%    93.5%     0.0%    0.0%           17% / 17%
0x0023  IN      2502          31        31     6.5%    93.5%     0.0%    0.0%           11% / 11%
0x000B  OUT       12          29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002E  IN        12          26        26     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521          26        26    11.5%    88.5%     0.0%    0.0%          19% / 100%
0x002E  IN      2528          26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12          23        23     0.0%     0.0%   100.0%    0.0%           96% / 96%
0x003D  IN      2512          23        23   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520          23        23     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x007E  IN         -          15         -                                     no script
0x0006  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12           8         8     0.0%    87.5%    12.5%    0.0%           35% / 35%
0x005E  IN      2506           8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN         -           7         -                                     no script
0x001D  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -           6         -                                     no script
0x0052  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           17% / 20%
0x0052  IN      2516           5         5    40.0%    60.0%     0.0%    0.0%          20% / 100%
0x008A  IN      2511           5         5     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524           5         5    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x0093  IN         -           5         -                                     no script
0x0048  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN        12           4         4    25.0%    75.0%     0.0%    0.0%          22% / 100%
0x006A  IN      2486           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           4         4    25.0%    75.0%     0.0%    0.0%          10% / 100%
0x006A  IN      2502           4         4    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006A  IN      2503           4         4    50.0%    50.0%     0.0%    0.0%          20% / 100%
0x006C  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0011  OUT        -           3         -                                     no script
0x0045  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0061  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x0069  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           3         3     0.0%    66.7%    33.3%    0.0%           20% / 34%
0x0069  IN      2496           3         3     0.0%    66.7%    33.3%    0.0%           34% / 90%
0x0069  IN      2497           3         3     0.0%    66.7%    33.3%    0.0%           20% / 34%
0x0069  IN      2502           3         3     0.0%    66.7%    33.3%    0.0%           20% / 34%
0x0069  IN      2503           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x006B  IN        12           3         3     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           3         3    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           3         3     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           3         3     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x00F4  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           24% / 24%
0x0128  IN        12           3         3    33.3%    66.7%     0.0%    0.0%          14% / 100%
0x0017  IN        12           2         2     0.0%     0.0%   100.0%    0.0%          80% / 100%
0x0017  IN      2500           2         2     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           2         2     0.0%    50.0%    50.0%    0.0%           8% / 100%
0x0017  IN      2528           2         2     0.0%     0.0%   100.0%    0.0%          10% / 100%
0x0017  IN      2550           2         2     0.0%     0.0%   100.0%    0.0%          80% / 100%
0x0019  IN        12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           2         2    50.0%     0.0%    50.0%    0.0%         100% / 100%
0x006D  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CC  IN        12           2         2     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x010A  IN        12           2         2     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x011C  IN         -           2         -                                     no script
0x0001  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0005  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           1         -                                     no script
0x000F  OUT        -           1         -                                     no script
0x0010  OUT        -           1         -                                     no script
0x0013  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           99% / 99%
0x0015  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0038  OUT     2511           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x004D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           1         1     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x004D  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           1         -                                     no script
0x0055  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0055  IN      2528           1         1     0.0%   100.0%     0.0%    0.0%           51% / 51%
0x005A  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x005A  IN      2490           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x007D  IN      2486           1         1     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x007D  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x007D  IN      2503           1         1     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           1         1     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           1         1     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           1         1     0.0%   100.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           1         -                                     no script
0x0097  OUT        -           1         -                                     no script
0x009E  IN         -           1         -                                     no script
0x00A5  IN         -           1         -                                     no script
0x00A7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           1         -                                     no script
0x00B0  OUT        -           1         -                                     no script
0x00B2  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           1         1     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           1         -                                     no script
0x00B7  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C1  IN         -           1         -                                     no script
0x00C4  IN         -           1         -                                     no script
0x00CA  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           10% / 10%
0x00CB  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00D1  IN         -           1         -                                     no script
0x00DF  IN         -           1         -                                     no script
0x00E6  IN         -           1         -                                     no script
0x00EB  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00EE  IN         -           1         -                                     no script
0x00F3  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x0110  IN         -           1         -                                     no script
0x011B  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0125  IN        12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           1         -                                     no script
0x0131  IN         -           1         -                                     no script
0x0138  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=952 threw=0 negative-length=81
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -43024 at offset 39/41
  ! ReadBytes: negative length -42804 at offset 39/41
  ! ReadBytes: negative length -40588 at offset 39/41
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 4607
       28    1  Byte     Segment 0/StateSync/Unknown = 0
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -14592
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = -21512

### 0x001C IN src 12  over=446 threw=0 negative-length=28
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
       24    2  Int16    StateSync/Rotation2 CoordS / 10 = 12032
       26    2  Int16    StateSync/CoordS / 1000 = 1
       28    4  Single   StateSync/UnknownCoordF/X = 1,80426E-40

### 0x00EA IN src 2504  over=126 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2504\Inbound\0x00EA.py
  ! ReadBytes: wanted 17118 byte(s) at offset 8, only 22 of 30 remain
  ! ReadBytes: wanted 17118 byte(s) at offset 8, only 42 of 50 remain
  ! ReadBytes: wanted 17118 byte(s) at offset 8, only 42 of 50 remain
  last reads before failure (of 6):
        0    2  Int16    mode = 7
        2    1  Byte     coords/x = 220
        3    1  Byte     coords/y = 202
        4    1  Byte     coords/z = 65
        5    1  Byte     zero = 0
        6    2  Int16    portal name/size = 8559

### 0x00B0 IN src 12  over=60 threw=0 negative-length=60
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B0.py
  ! ReadBytes: negative length -8702 at offset 6/20
  ! ReadBytes: negative length -54782 at offset 6/20
  ! ReadBytes: negative length -8702 at offset 6/20
  last reads before failure (of 2):
        0    4  Int32    ObjectId = 1593037312
        4    2  Int16    Motto/size = -4351

### 0x001C IN src 2507  over=35 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 301
       13    2  Int16    coord x = 0
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -651896040978382831
       30    2  Int16    speed x = 1

### 0x0023 IN src 12  over=28 threw=0
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

### 0x003D IN src 12  over=23 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = 4740399248725067780
        8    4  Int32    ServerTick = 1595888640
       12    4  Int32    ObjectId = -1698037759
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0045 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 2 of 14 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 0
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 0
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 0

### 0x0061 IN src 12  over=3 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 827, only 1 of 828 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0017 IN src 12  over=2 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: negative length -33224 at offset 5319/6634
  ! Read<Int64>: wanted 8 byte(s) at offset 1724, only 4 of 1728 remain
  last reads before failure (of 1955):
     5294    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/UUID = 
     5294    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/size = 0
     5296    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/ItemName = 
     5296    1  Byte     gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 0
     5297    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 738197504
     5301    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/AccountId = 3170920199310295497
     5309    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterId = 963980447455396297
     5317    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterName/size = -16612

### 0x0017 IN src 2528  over=2 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! ReadBytes: negative length -47070 at offset 645/6634
  ! Read<Int64>: wanted 8 byte(s) at offset 1724, only 4 of 1728 remain
  last reads before failure (of 124):
      612    1  Boolean  InBattle = True
      613    1  Byte     gameObject_vtbl+572 virtual call/Unknown = 0
      614    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemId = 5
      618    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/ItemUid = 288401504795099392
      626    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/Unknown = -6588484775571357696
      634    1  Boolean  gameObject_vtbl+572 virtual call/CubeItemInfo/IsUgc = True
      635    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Uid = 281474976711936
      643    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/size = -23535

### 0x0017 IN src 2550  over=2 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2550\Inbound\0x0017.py
  ! ReadBytes: negative length -33224 at offset 5319/6634
  ! Read<Int64>: wanted 8 byte(s) at offset 1724, only 4 of 1728 remain
  last reads before failure (of 1955):
     5294    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UUID/UUID = 
     5294    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/size = 0
     5296    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/ItemName/ItemName = 
     5296    1  Byte     gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 0
     5297    4  Int32    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 738197504
     5301    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/AccountId = 3170920199310295497
     5309    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterId = 963980447455396297
     5317    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CharacterName/size = -16612
