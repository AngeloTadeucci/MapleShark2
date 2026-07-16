# Phase 0 harness — CHAINED -> 2546

scripts from build : (chained, see src column)
packets from build : 2546
packets considered : 1.523.466
packets executed   : 100.926  (--sample 1500 per opcode)

## Totals (weighted by executed packets)

outcome             packets   share
NoScript             61.167   60.6%
OkExact              25.848   25.6%
UnderRead            10.720   10.6%
OverRead              3.163   3.1%
Threw                     1   0.0%
CompileError             27   0.0%

of packets a script actually ran on (39.732):
  clean (consumed exactly) : 65.1%
  over-read (WRONG)        : 8.0%
  under-read (ambiguous)   : 27.0%

## Per opcode

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN      2527     663.508     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN      2507     168.598     1.500    93.9%     1.1%     5.0%    0.0%         100% / 100%
0x002E  IN      2528     106.785     1.500    99.9%     0.1%     0.0%    0.0%         100% / 100%
0x0012  OUT        -      89.256         -                                     no script
0x003D  IN      2520      69.342     1.500    39.5%    60.5%     0.0%    0.0%           4% / 100%
0x0024  IN      2507      65.583     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -      62.039         -                                     no script
0x0011  IN         -      52.950         -                                     no script
0x0047  IN         -      26.151         -                                     no script
0x003C  IN      2520      16.532     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN      2506      15.808     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN      2529      14.923     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN         -      12.156         -                                     no script
0x0021  IN      2546      11.617     1.500     1.8%    98.1%     0.0%    0.1%           17% / 20%
0x0055  IN      2528      10.835     1.500    98.8%     0.9%     0.3%    0.0%         100% / 100%
0x0020  OUT     2512      10.666     1.500    99.6%     0.1%     0.3%    0.0%         100% / 100%
0x004C  IN      2512       9.757     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN      2502       8.139     1.500     3.0%    97.0%     0.0%    0.0%           11% / 11%
0x00CB  IN         -       7.554         -                                     no script
0x0056  IN         -       6.966         -                                     no script
0x000B  OUT        -       6.825         -                                     no script
0x00B0  IN         -       6.030         -                                     no script
0x0006  IN      2486       5.542     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007A  IN         -       4.674         -                                     no script
0x0048  IN      2507       2.798     1.500    94.8%     5.2%     0.0%    0.0%         100% / 100%
0x0052  IN      2516       2.686     1.500    28.7%    63.6%     7.7%    0.0%          17% / 100%
0x0041  OUT        -       2.561         -                                     no script
0x0063  IN      2518       2.360     1.500    43.5%    56.5%     0.0%    0.0%           4% / 100%
0x004B  IN      2507       1.929     1.500    17.9%    82.1%     0.0%    0.0%           6% / 100%
0x00C7  IN         -       1.904         -                                     no script
0x0066  IN         -       1.788         -                                     no script
0x0037  IN         -       1.672         -                                     no script
0x002B  IN      2531       1.655     1.500    48.0%     0.0%    52.0%    0.0%         100% / 100%
0x0093  IN         -       1.642         -                                     no script
0x002C  IN         -       1.634         -                                     no script
0x00A8  IN         -       1.627         -                                     no script
0x002D  IN         -       1.548         -                                     no script
0x004F  IN      2507       1.447     1.447     9.9%     0.0%    90.1%    0.0%           16% / 16%
0x0069  IN      2546       1.427     1.427     0.0%   100.0%     0.0%    0.0%            4% / 20%
0x0006  OUT     2486       1.250     1.250   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN         -       1.247         -                                     no script
0x004D  IN      2546       1.154     1.154    82.9%    17.0%     0.1%    0.0%         100% / 100%
0x0053  IN         -       1.094         -                                     no script
0x006A  IN      2503       1.018     1.018    35.1%    64.9%     0.0%    0.0%          20% / 100%
0x006C  IN         -       1.004         -                                     no script
0x0061  IN         -         964         -                                     no script
0x0039  IN         -         961         -                                     no script
0x0045  IN         -         891         -                                     no script
0x0080  OUT        -         852         -                                     no script
0x003F  IN         -         819         -                                     no script
0x0128  IN         -         805         -                                     no script
0x006B  IN      2546         778       778     0.0%   100.0%     0.0%    0.0%            8% / 20%
0x013B  IN         -         774         -                                     no script
0x00B6  IN         -         748         -                                     no script
0x0014  IN         -         680         -                                     no script
0x0005  IN         -         664         -                                     no script
0x0041  IN         -         603         -                                     no script
0x0017  IN      2528         588       588     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0138  IN         -         544         -                                     no script
0x001A  IN         -         493         -                                     no script
0x0044  IN         -         490         -                                     no script
0x00CC  IN         -         477         -                                     no script
0x0019  IN      2500         475       475   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011C  IN         -         471         -                                     no script
0x006D  IN         -         461         -                                     no script
0x010A  IN         -         460         -                                     no script
0x012D  IN         -         449         -                                     no script
0x001D  IN         -         447         -                                     no script
0x00F4  IN         -         426         -                                     no script
0x0033  IN         -         418         -                                     no script
0x0073  IN      2531         417       417   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EB  IN         -         373         -                                     no script
0x0036  IN         -         369         -                                     no script
0x00E6  IN         -         356         -                                     no script
0x006F  IN         -         348         -                                     no script
0x0051  IN      2546         338       338    23.1%     1.5%    75.4%    0.0%         100% / 100%
0x00CA  IN         -         337         -                                     no script
0x0034  OUT        -         324         -                                     no script
0x00F3  IN         -         319         -                                     no script
0x00D1  IN         -         315         -                                     no script
0x0016  IN      2546         314       314   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546         314       314    94.3%     5.7%     0.0%    0.0%         100% / 100%
0x011B  IN         -         314         -                                     no script
0x001F  IN         -         314         -                                     no script
0x0035  IN         -         314         -                                     no script
0x0022  OUT        -         313         -                                     no script
0x0103  IN         -         307         -                                     no script
0x00B1  IN         -         304         -                                     no script
0x0013  IN         -         271         -                                     no script
0x013A  IN         -         270         -                                     no script
0x00F1  IN         -         264         -                                     no script
0x005A  IN      2527         252       252   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C4  IN         -         249         -                                     no script
0x00C3  IN         -         248         -                                     no script
0x000F  OUT        -         246         -                                     no script
0x0038  OUT     2511         245       245     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x0010  OUT        -         244         -                                     no script
0x0055  OUT        -         242         -                                     no script
0x0054  IN         -         242         -                                     no script
0x00A5  IN         -         240         -                                     no script
0x000C  OUT        -         238         -                                     no script
0x0001  IN         -         233         -                                     no script
0x0001  OUT        -         233         -                                     no script
0x008E  OUT        -         233         -                                     no script
0x0004  OUT        -         232         -                                     no script
0x000D  IN         -         232         -                                     no script
0x00B3  IN      2502         232       232     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x00B0  OUT        -         231         -                                     no script
0x00DF  IN         -         231         -                                     no script
0x00B2  IN         -         231         -                                     no script
0x013C  IN         -         230         -                                     no script
0x0004  IN         -         230         -                                     no script
0x0125  IN         -         230         -                                     no script
0x00B5  OUT        -         230         -                                     no script
0x00BD  IN         -         230         -                                     no script
0x00A7  IN         -         230         -                                     no script
0x0015  IN      2507         230       230   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AD  IN         -         230         -                                     no script
0x0110  IN         -         230         -                                     no script
0x00A9  IN         -         230         -                                     no script
0x009E  IN         -         230         -                                     no script
0x0089  IN      2527         230       230   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EE  IN         -         230         -                                     no script
0x00B7  IN         -         230         -                                     no script
0x00B9  IN         -         230         -                                     no script
0x0126  IN         -         230         -                                     no script
0x000E  OUT        -         229         -                                     no script
0x0039  OUT        -         219         -                                     no script
0x0131  IN         -         217         -                                     no script
0x005C  IN         -         199         -                                     no script
0x0010  IN         -         199         -                                     no script
0x0079  IN         -         184         -                                     no script
0x0018  IN         -         173         -                                     no script
0x005F  IN         -         169         -                                     no script
0x003E  IN         -         168         -                                     no script
0x0026  IN         -         165         -                                     no script
0x0026  OUT        -         159         -                                     no script
0x0025  IN         -         159         -                                     no script
0x0094  IN         -         156         -                                     no script
0x005B  IN         -         151         -                                     no script
0x0049  IN      2529         150       150    29.3%    70.7%     0.0%    0.0%           1% / 100%
0x0060  IN         -         149         -                                     no script
0x0096  IN         -         144         -                                     no script
0x00CD  IN         -         141         -                                     no script
0x001E  IN         -         126         -                                     no script
0x010C  IN      2502         100       100    55.0%    45.0%     0.0%    0.0%         100% / 100%
0x00F2  IN         -          88         -                                     no script
0x0029  OUT        -          84         -                                     no script
0x00F6  IN      2520          82        82   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  OUT        -          79         -                                     no script
0x005D  IN         -          77         -                                     no script
0x0042  IN         -          68         -                                     no script
0x010E  IN         -          58         -                                     no script
0x008A  IN      2524          56        56    71.4%    12.5%    16.1%    0.0%         100% / 100%
0x0021  OUT        -          52         -                                     no script
0x0109  IN         -          48         -                                     no script
0x0090  IN         -          48         -                                     no script
0x0011  OUT        -          45         -                                     no script
0x0070  IN         -          45         -                                     no script
0x0068  IN      2486          43        43    90.7%     9.3%     0.0%    0.0%         100% / 100%
0x006E  IN      2486          42        42    73.8%     0.0%    26.2%    0.0%         100% / 100%
0x0038  IN         -          42         -                                     no script
0x0123  IN         -          41         -                                     no script
0x002F  OUT        -          31         -                                     no script
0x0016  OUT        -          26         -                                     no script
0x0022  IN         -          26         -                                     no script
0x0100  IN         -          26         -                                     no script
0x001D  OUT        -          23         -                                     no script
0x00FF  IN         -          23         -                                     no script
0x0031  OUT        -          22         -                                     no script
0x001C  OUT        -          21         -                                     no script
0x0065  IN         -          19         -                                     no script
0x00A2  OUT        -          19         -                                     COMPILE-ERR
0x000C  IN      2525          19        19    42.1%     0.0%    57.9%    0.0%         100% / 100%
0x0040  IN         -          19         -                                     no script
0x0080  IN         -          18         -                                     no script
0x001B  IN         -          18         -                                     no script
0x006C  OUT        -          17         -                                     no script
0x00C1  IN         -          17         -                                     no script
0x0137  IN         -          15         -                                     no script
0x0025  OUT     2502          14        14    64.3%    35.7%     0.0%    0.0%         100% / 100%
0x0018  OUT        -          14         -                                     no script
0x00FB  IN         -          14         -                                     no script
0x0071  IN         -          14         -                                     no script
0x0097  IN         -          14         -                                     no script
0x00A6  IN         -          13         -                                     no script
0x0034  IN         -          13         -                                     no script
0x00A4  IN         -          13         -                                     no script
0x00F0  IN         -          13         -                                     no script
0x0050  IN         -          13         -                                     no script
0x0084  IN         -          11         -                                     no script
0x0037  OUT     2502          11        11    18.2%    81.8%     0.0%    0.0%          20% / 100%
0x00E9  IN         -          10         -                                     no script
0x002B  OUT        -          10         -                                     no script
0x0066  OUT        -           9         -                                     no script
0x0048  OUT        -           9         -                                     no script
0x0074  OUT        -           9         -                                     no script
0x00EA  IN         -           8         -                                     COMPILE-ERR
0x007B  IN         -           8         -                                     no script
0x00A4  OUT        -           6         -                                     no script
0x005A  OUT        -           5         -                                     no script
0x0059  IN         -           4         -                                     no script
0x0057  OUT        -           4         -                                     no script
0x0035  OUT        -           4         -                                     no script
0x0061  OUT        -           4         -                                     no script
0x0097  OUT        -           3         -                                     no script
0x0040  OUT        -           3         -                                     no script
0x0009  IN         -           3         -                                     no script
0x00B8  IN         -           3         -                                     no script
0x010F  IN         -           3         -                                     no script
0x00E8  IN         -           3         -                                     no script
0x0036  OUT        -           3         -                                     no script
0x001F  OUT        -           3         -                                     no script
0x001E  OUT        -           3         -                                     no script
0x0078  IN      2506           3         3     0.0%     0.0%   100.0%    0.0%           39% / 49%
0x00D6  IN         -           2         -                                     no script
0x00CF  IN         -           2         -                                     no script
0x000B  IN      2507           2         2     0.0%   100.0%     0.0%    0.0%           76% / 76%
0x003A  OUT        -           2         -                                     no script
0x009D  IN         -           2         -                                     no script
0x009F  IN         -           2         -                                     no script
0x00DC  IN         -           2         -                                     no script
0x0099  OUT        -           2         -                                     no script
0x0072  OUT        -           2         -                                     no script
0x0013  OUT        -           2         -                                     no script
0x002E  OUT        -           2         -                                     no script
0x0032  OUT        -           1         -                                     no script
0x00A2  IN         -           1         -                                     no script
0x00A3  IN         -           1         -                                     no script
0x0082  OUT        -           1         -                                     no script
0x011F  IN         -           1         -                                     no script
0x0089  OUT        -           1         -                                     no script
0x002D  OUT        -           1         -                                     no script
0x0009  OUT     2525           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  IN         -           1         -                                     no script
0x0014  OUT        -           1         -                                     no script
0x0027  OUT        -           1         -                                     no script
0x002C  OUT        -           1         -                                     no script
0x0017  OUT        -           1         -                                     no script
0x004A  OUT        -           1         -                                     no script
0x000D  OUT        -           1         -                                     no script
0x0083  IN         -           1         -                                     no script
0x0073  OUT        -           1         -                                     no script
0x0092  IN         -           1         -                                     no script
0x00BB  IN         -           1         -                                     no script
0x004D  OUT        -           1         -                                     no script
0x0003  OUT        -           1         -                                     no script
0x00C6  IN         -           1         -                                     no script
0x000A  IN         -           1         -                                     no script
0x00AF  IN         -           1         -                                     no script
0x003B  IN         -           1         -                                     no script

## Sample failures

### 0x004F IN  over=1.304 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x004F.py
  ! ReadBytes: wanted 24931 byte(s) at offset 7, only 38 of 45 remain
  ! ReadBytes: wanted 25187 byte(s) at offset 7, only 38 of 45 remain
  ! ReadBytes: wanted 12646 byte(s) at offset 7, only 38 of 45 remain
  last reads before failure (of 3):
        0    1  Byte     byte = 1
        1    4  Int32    count = 1714880544
        5    2  Int16    entity id/size = 24931

### 0x002B IN  over=780 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2531\Inbound\0x002B.py
  ! Read<Int32>: wanted 4 byte(s) at offset 224, only 0 of 224 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 224, only 0 of 224 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 224, only 0 of 224 remain
  last reads before failure (of 67):
      194    4  Int32    Item: 90000009/Stats/Unknown = 0
      198    4  Int32    Item: 90000009/ItemEnchant/Enchants = 0
      202    4  Int32    Item: 90000009/ItemEnchant/EnchantExp = 1
      206    1  Byte     Item: 90000009/ItemEnchant/EnchantBasedChargeExp = 0
      207    8  Int64    Item: 90000009/ItemEnchant/Unknown = 0
      215    4  Int32    Item: 90000009/ItemEnchant/Unknown = 0
      219    4  Int32    Item: 90000009/ItemEnchant/Unknown = 0
      223    1  Boolean  Item: 90000009/ItemEnchant/CanRepackage = False

### 0x0017 IN  over=588 threw=0 negative-length=20
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0017.py
  ! Read<Int64>: wanted 8 byte(s) at offset 2240, only 0 of 2240 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1896, only 1 of 1897 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 1854, only 6 of 1860 remain
  last reads before failure (of 298):
     2176    8  Int64    PlayerInfo/Player+1B0 = 73903104924565281
     2184    8  Int64    PlayerInfo/Player+1B0 = 1099511628032
     2192    8  Int64    PlayerInfo/Player+1B0 = 0
     2200    8  Int64    PlayerInfo/Player+1B0 = 0
     2208    8  Int64    PlayerInfo/Player+1B0 = 0
     2216    8  Int64    PlayerInfo/Player+1B0 = 0
     2224    8  Int64    PlayerInfo/Player+1B0 = 0
     2232    8  Int64    PlayerInfo/Player+1B0 = 549755813632

### 0x0051 IN  over=255 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2546\Inbound\0x0051.py
  ! Read<Int32>: wanted 4 byte(s) at offset 259, only 0 of 259 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 259, only 0 of 259 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 259, only 0 of 259 remain
  last reads before failure (of 87):
      229    4  Int32    Item 0/Item: 50600006/Stats/Unknown = 0
      233    4  Int32    Item 0/Item: 50600006/ItemEnchant/Enchants = 0
      237    4  Int32    Item 0/Item: 50600006/ItemEnchant/EnchantExp = 1
      241    1  Byte     Item 0/Item: 50600006/ItemEnchant/EnchantBasedChargeExp = 0
      242    8  Int64    Item 0/Item: 50600006/ItemEnchant/Unknown = 0
      250    4  Int32    Item 0/Item: 50600006/ItemEnchant/Unknown = 0
      254    4  Int32    Item 0/Item: 50600006/ItemEnchant/Unknown = 0
      258    1  Boolean  Item 0/Item: 50600006/ItemEnchant/CanRepackage = False

### 0x0052 IN  over=116 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2516\Inbound\0x0052.py
  ! Read<Int32>: wanted 4 byte(s) at offset 13, only 0 of 13 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 13, only 0 of 13 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 13, only 0 of 13 remain
  last reads before failure (of 4):
        0    1  Byte     quest mode = 3
        1    4  Int32    quest id = 30000443
        5    4  Int32    condition index = 1
        9    4  Int32    value = 78

### 0x001C IN  over=75 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2507\Inbound\0x001C.py
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 32, only 0 of 32 remain
  last reads before failure (of 13):
       11    2  Int16    emote unk = 151
       13    2  Int16    coord x = 2250
       15    2  Int16    coord y = 23049
       17    2  Int16    coord z = 11520
       19    2  Int16    rotation = -9984
       21    1  Byte     animation3 = 255
       22    8  Int64    2x float = -362258289892210159
       30    2  Int16    speed x = 0

### 0x000C IN  over=11 threw=0 negative-length=2
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2525\Inbound\0x000C.py
  ! Read<Int32>: wanted 4 byte(s) at offset 4378, only 2 of 4380 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 10240, only 2 of 10242 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 9383, only 1 of 9384 remain
  last reads before failure (of 1322):
     4354    4  Int32    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/IntegerValue = 7012454
     4358    2  Int16    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/StatType = 52
     4360    4  Int32    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/IntegerValue = 0
     4364    2  Int16    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/StatType = 0
     4366    4  Int32    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/IntegerValue = 0
     4370    2  Int16    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/StatType = 0
     4372    4  Int32    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/IntegerValue = 0
     4376    2  Int16    Item 3/Item: 256/LimitBreak/LimitBreakStatOption/StatType = 0

### 0x006E IN  over=11 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2486\Inbound\0x006E.py
  ! Read<Int64>: wanted 8 byte(s) at offset 39, only 0 of 39 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 39, only 0 of 39 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 39, only 0 of 39 remain
  last reads before failure (of 10):
        3    4  Int32    obj id = 4282784
        7    8  Int64    char id = 2600450466718032250
       15    4  Single   position/x = 13
       19    4  Single   position/y = 3136
       23    4  Single   position/z = 600
       27    4  Single   rotation/x = 0
       31    4  Single   rotation/y = 0
       35    4  Single   rotation/z = 224

### 0x008A IN  over=9 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2524\Inbound\0x008A.py
  ! Read<Int32>: wanted 4 byte(s) at offset 2717, only 2 of 2719 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 2717, only 2 of 2719 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 2717, only 2 of 2719 remain
  last reads before failure (of 925):
     2701    2  Int16    GuildBank/UnknownEntry/Rarity = 120
     2703    4  Int32    GuildBank/UnknownEntry/Amount = 1537
     2707    1  Boolean  GuildBank/UnknownEntry/Unknown = False
     2708    1  Boolean  GuildBank/UnknownEntry/Unknown = True
     2709    1  Boolean  GuildBank/UnknownEntry/Unknown = False
     2710    1  Boolean  GuildBank/UnknownEntry/Unknown = False
     2711    4  Int32    GuildBank/UnknownEntry/ItemId = 256
     2715    2  Int16    GuildBank/UnknownEntry/Rarity = 0

### 0x0055 IN  over=5 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2528\Inbound\0x0055.py
  ! Read<Int32>: wanted 4 byte(s) at offset 137, only 0 of 137 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 158, only 2 of 160 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 201, only 3 of 204 remain
  last reads before failure (of 34):
      103    8  Int64    buff 0/additionalEffect2/additionalEffect2 = 218103808
      111    4  Int32    buff 1/TargetObjectId = 0
      115    4  Int32    buff 1/BuffObjectId = 512
      119    4  Int32    buff 1/OwnerObjectId = 1672081664
      123    4  Int32    buff 1/additionalEffect/StartServerTick = -83885822
      127    4  Int32    buff 1/additionalEffect/EndServerTick = 16933801
      131    4  Int32    buff 1/additionalEffect/SkillId = 0
      135    2  Int16    buff 1/additionalEffect/SkillLevel = 0

### 0x0020 OUT  over=5 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2512\Outbound\0x0020.py
  ! ReadBytes: wanted 14 byte(s) at offset 80, only 2 of 82 remain
  ! ReadBytes: wanted 6 byte(s) at offset 80, only 2 of 82 remain
  ! ReadBytes: wanted 6 byte(s) at offset 80, only 2 of 82 remain
  last reads before failure (of 22):
       52    4  Single   RotationCoordF/Z = 134,99998
       56    4  Single   UnknownFloat = 0
       60    4  Int32    ClientTick = 2084990
       64    1  Boolean  Unknown = False
       65    8  Int64    Unknown = 0
       73    1  Boolean  flag = True
       74    4  Int32    Unknown = 290805626
       78    2  Int16    Unknown/size = 7

### 0x0078 IN  over=3 threw=0 negative-length=3
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\2506\Inbound\0x0078.py
  ! ReadBytes: negative length -62538 at offset 1252/3238
  ! ReadBytes: negative length -62538 at offset 1252/2548
  ! ReadBytes: negative length -62538 at offset 1252/3238
  last reads before failure (of 56):
     1054    4  Single   Buffer 1/Stats4/Stat = 4,867349E-39
     1058    4  Single   Buffer 1/Stats4/Stat = 4,867349E-39
     1062    4  Single   Buffer 1/Stats4/Stat = 5,142862E-39
     1066    4  Single   Buffer 1/Stats4/Stat = 5,05103E-39
     1070    4  Single   Buffer 1/Stats4/Stat = 4,500011E-39
     1074    4  Single   Buffer 1/Stats4/Stat = 4,86735E-39
     1078  172  Field    Buffer 1/unk = 2E0070006E0067000000000000000000..
     1250    2  Int16    Buffer 1/ProfileUrl/size = -31269
