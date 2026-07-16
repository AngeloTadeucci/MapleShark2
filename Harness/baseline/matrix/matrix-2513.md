# Harness — MATRIX -> 2513

scripts from build : (matrix, see src column)
packets from build : 2513
packets considered : 110.493
packets executed   : 28.719  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript              1.968   6.9%
OkExact               9.966   34.7%
UnderRead             8.857   30.8%
OverRead              7.928   27.6%

of packets a script actually ran on (26.751):
  clean (consumed exactly) : 37.3%
  over-read (WRONG)        : 29.6%
  under-read (ambiguous)   : 33.1%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x001C  IN        12      65.951     1.500     1.7%     0.0%    98.3%    0.0%         100% / 100%
0x001C  IN      2507      65.951     1.500    93.9%     0.9%     5.1%    0.0%         100% / 100%
0x007A  IN        12      21.707     1.500     0.0%     0.0%   100.0%    0.0%           78% / 78%
0x0012  OUT       12       7.980     1.500     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0041  OUT       12       3.535     1.500     0.0%   100.0%     0.0%    0.0%           41% / 41%
0x0024  IN        12       2.079     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       2.079     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       2.079     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN        12       1.480     1.480     0.0%     0.0%   100.0%    0.0%             8% / 8%
0x007E  IN         -       1.355         -                                     no script
0x002E  IN        12         950       950     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521         950       950     2.7%    66.6%    30.6%    0.0%          19% / 100%
0x002E  IN      2528         950       950    69.4%    30.6%     0.0%    0.0%         100% / 100%
0x0011  IN        12         941       941    50.5%    49.5%     0.0%    0.0%         100% / 100%
0x0023  IN        12         593       593     1.5%     0.0%    98.5%    0.0%         100% / 100%
0x0023  IN      2486         593       593     1.0%    99.0%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         593       593     1.0%    99.0%     0.0%    0.0%           11% / 11%
0x003D  IN        12         516       516     0.0%    36.0%    64.0%    0.0%           90% / 96%
0x003D  IN      2512         516       516    64.0%    36.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         516       516    57.0%    43.0%     0.0%    0.0%         100% / 100%
0x000B  OUT       12         469       469   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x012B  IN         -         278         -                                     no script
0x0053  IN        12         245       245     0.0%    90.6%     9.4%    0.0%            4% / 11%
0x0021  IN        12         243       243     0.8%    97.5%     1.6%    0.0%            0% / 20%
0x0021  IN      2511         243       243     1.2%    98.8%     0.0%    0.0%            0% / 20%
0x0021  IN      2525         243       243     1.2%    98.8%     0.0%    0.0%            0% / 20%
0x0021  IN      2529         243       243     1.2%    98.8%     0.0%    0.0%            0% / 20%
0x0021  IN      2546         243       243     1.2%    98.8%     0.0%    0.0%            0% / 20%
0x0021  IN      2549         243       243     1.2%    98.8%     0.0%    0.0%            0% / 20%
0x0021  IN      2550         243       243     1.2%    98.8%     0.0%    0.0%            0% / 20%
0x005E  IN        12         225       225     0.0%    98.7%     1.3%    0.0%           11% / 26%
0x005E  IN      2506         225       225   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN        12         216       216     0.0%    50.0%    50.0%    0.0%           2% / 100%
0x004C  IN      2512         216       216   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN        12         195       195     0.0%   100.0%     0.0%    0.0%           44% / 44%
0x003C  IN      2506         195       195     0.0%   100.0%     0.0%    0.0%           70% / 70%
0x003C  IN      2507         195       195   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2512         195       195   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN      2520         195       195   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  OUT        -         160         -                                     no script
0x002F  IN        12         123       123     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0006  IN        12         102       102   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486         102       102   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486         102       102   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003F  IN        12          81        81     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004E  IN        12          69        69     4.3%    39.1%    56.5%    0.0%           56% / 93%
0x0079  IN        12          42        42     0.0%     0.0%   100.0%    0.0%           13% / 29%
0x008A  IN      2511          42        42     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x008A  IN      2524          42        42    83.3%     0.0%    16.7%    0.0%         100% / 100%
0x0033  IN        12          40        40     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0061  IN        12          39        39     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0020  OUT       12          36        36    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x0020  OUT     2507          36        36    50.0%    50.0%     0.0%    0.0%          89% / 100%
0x0020  OUT     2512          36        36    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12          33        33     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0017  IN      2500          33        33     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503          33        33     0.0%    81.8%    18.2%    0.0%          10% / 100%
0x0017  IN      2528          33        33     0.0%     0.0%   100.0%    0.0%          30% / 100%
0x0017  IN      2550          33        33     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0093  IN         -          33         -                                     no script
0x0052  IN        12          27        27     0.0%   100.0%     0.0%    0.0%            0% / 17%
0x0052  IN      2516          27        27    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x00F6  IN        12          27        27     0.0%    92.6%     7.4%    0.0%             0% / 4%
0x00F6  IN      2520          27        27   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN        12          22        22   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  IN        12          21        21     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x005D  IN        12          21        21     0.0%     0.0%   100.0%    0.0%           73% / 73%
0x0068  IN        12          21        21     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0068  IN      2486          21        21   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN        12          21        21     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00A3  IN         -          21         -                                     no script
0x00A6  IN        12          21        21     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00A8  IN         -          21         -                                     no script
0x0036  IN        12          19        19     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0034  OUT       12          16        16   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12          14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          13         -                                     no script
0x0048  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           41% / 41%
0x006C  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00EB  IN        12          12        12     0.0%    75.0%    25.0%    0.0%          69% / 100%
0x0123  IN         -          10         -                                     no script
0x0005  IN        12           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  IN        12           9         9     0.0%     0.0%   100.0%    0.0%           98% / 98%
0x0069  IN        12           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2496           9         9     0.0%    66.7%    33.3%    0.0%           42% / 90%
0x0069  IN      2497           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2502           9         9     0.0%    66.7%    33.3%    0.0%           20% / 53%
0x0069  IN      2503           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2546           9         9     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x0069  IN      2550           9         9    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x006A  IN        12           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2486           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2500           9         9    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2502           9         9    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2503           9         9    33.3%    66.7%     0.0%    0.0%          20% / 100%
0x006B  IN        12           9         9     0.0%    66.7%    33.3%    0.0%          46% / 100%
0x006B  IN      2507           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2511           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2524           9         9    66.7%    33.3%     0.0%    0.0%         100% / 100%
0x006B  IN      2525           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2546           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2549           9         9     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x006B  IN      2550           9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  IN        12           9         9     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x011C  IN         -           8         -                                     no script
0x0019  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           6         6    50.0%    33.3%    16.7%    0.0%         100% / 100%
0x006D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00CB  IN        12           6         6     0.0%   100.0%     0.0%    0.0%             2% / 4%
0x00CC  IN        12           6         6     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x00E6  IN         -           6         -                                     no script
0x010A  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x0128  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 14%
0x012C  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            4% / 25%
0x0044  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x005F  IN        12           5         5     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0001  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           3         -                                     no script
0x000F  OUT        -           3         -                                     no script
0x0010  OUT        -           3         -                                     no script
0x0010  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001F  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0035  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0037  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           16% / 16%
0x0038  OUT     2511           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0038  OUT     2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0055  OUT        -           3         -                                     no script
0x006F  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0073  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           56% / 56%
0x007D  IN      2486           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x007D  IN      2502           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           3         -                                     no script
0x0097  OUT        -           3         -                                     no script
0x009E  IN         -           3         -                                     no script
0x00A5  IN         -           3         -                                     no script
0x00A7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00A9  IN        12           3         3     0.0%    33.3%    66.7%    0.0%         100% / 100%
0x00AD  IN         -           3         -                                     no script
0x00B0  OUT        -           3         -                                     no script
0x00B2  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             2% / 2%
0x00B3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B3  IN      2502           3         3     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B5  OUT        -           3         -                                     no script
0x00B7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00B9  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00BD  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00C4  IN         -           3         -                                     no script
0x00CA  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00D1  IN         -           3         -                                     no script
0x00DF  IN         -           3         -                                     no script
0x00EE  IN         -           3         -                                     no script
0x00F3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           3         -                                     no script
0x011B  IN        12           3         3     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0125  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0126  IN         -           3         -                                     no script
0x0131  IN         -           3         -                                     no script
0x0138  IN         -           3         -                                     no script
0x0011  OUT        -           2         -                                     no script
0x004B  OUT       12           2         2     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00F9  IN         -           2         -                                     no script
0x003A  OUT        -           1         -                                     no script
0x00A4  IN         -           1         -                                     no script

## Sample failures

### 0x0012 OUT src 12  over=1.500 threw=0 negative-length=215
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! Read<Int32>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 39, only 2 of 41 remain
  ! Read<Single>: wanted 4 byte(s) at offset 41, only 0 of 41 remain
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 193
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = 3073
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    4  Int32    Segment 0/ClientTicks = 515222872

### 0x007A IN src 12  over=1.500 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x007A.py
  ! Read<Int64>: wanted 8 byte(s) at offset 37, only 3 of 40 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 25, only 7 of 32 remain
  last reads before failure (of 6):
        0    8  Int64    CharacterId = 4762558809277564008
        8    1  Boolean  Bool = True
        9    8  Int64    Unknown = 900734098930203590
       17    8  Int64    CharacterId = 6539074180501901909
       25    8  Int64    CurrentTime = 928870721025748224
       33    4  Int32    Buffer 1/BufferSize = 1023410240

### 0x0047 IN src 12  over=1.480 threw=0 negative-length=1.060
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -65380 at offset 3/40
  ! ReadBytes: negative length -65380 at offset 3/40
  ! ReadBytes: negative length -65380 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -32690

### 0x001C IN src 12  over=1.474 threw=0 negative-length=45
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 17):
       18    2  Int16    StateSync/PositionCoordS/Z = 45
       20    2  Int16    StateSync/Rotation = -39
       22    1  Byte     StateSync/Animation3 = 2
       23    2  Int16    StateSync/SpeedCoordS/X = 1799
       25    2  Int16    StateSync/SpeedCoordS/Y = 10
       27    2  Int16    StateSync/SpeedCoordS/Z = 12544
       29    1  Byte     StateSync/Unknown = 246
       30    2  Int16    StateSync/Rotation2 CoordS / 10 = 5

### 0x0023 IN src 12  over=584 threw=0
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

### 0x003D IN src 12  over=330 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = -1909042453038385148
        8    4  Int32    ServerTick = -1503569152
       12    4  Int32    ObjectId = 29699
       16    4  Int32    SkillId = 0
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x002E IN src 2521  over=291 threw=0
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
       54    8  Int64    hp bonus long = 16151
       62    8  Int64    hp base long = 438086664299
       70    8  Int64    hp total long = 429496729700

### 0x002F IN src 12  over=123 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002F.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    objectId = 15040624
        4    1  Byte     Function = 1

### 0x004C IN src 12  over=108 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004C.py
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 1
        1    4  Int32    ObjectId = 15045357

### 0x003F IN src 12  over=81 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003F.py
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 12, only 0 of 12 remain
  last reads before failure (of 2):
        0    8  Int64    SkillCastId = 63770042540682
        8    4  Int32    OwnerObjectId = 15041865

### 0x001C IN src 2507  over=77 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 59, only 0 of 59 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 1316
       13    2  Int16    coord x = 440
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -127789634309474302
       30    2  Int16    speed x = 5

### 0x0079 IN src 12  over=42 threw=0 negative-length=12
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0079.py
  ! ReadBytes: negative length -18432 at offset 2/15
  ! ReadBytes: wanted 30976 byte(s) at offset 2, only 13 of 15 remain
  ! ReadBytes: wanted 23296 byte(s) at offset 2, only 13 of 15 remain
  last reads before failure (of 1):
        0    2  Int16    EntityId/size = -18432
