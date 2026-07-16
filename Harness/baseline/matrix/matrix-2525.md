# Harness — MATRIX -> 2525

scripts from build : (matrix, see src column)
packets from build : 2525
packets considered : 17.854
packets executed   : 15.763  (reservoir;n=1500;seed=1)

## Totals (weighted by executed packets)

NOTE: matrix totals aggregate every candidate source, including known-bad ones.
They describe the evidence run, not achievable coverage. Use the CSV per edge.

outcome             packets   share
NoScript                256   1.6%
OkExact               8.543   54.2%
UnderRead             5.574   35.4%
OverRead              1.390   8.8%

of packets a script actually ran on (15.507):
  clean (consumed exactly) : 55.1%
  over-read (WRONG)        : 9.0%
  under-read (ambiguous)   : 35.9%

## Per opcode x source

opcode  dir      src        seen       ran    clean    under     over   threw    consumed p50/p90
0x0058  IN        12      10.399     1.500     0.0%   100.0%     0.0%    0.0%           13% / 13%
0x0058  IN      2521      10.399     1.500    93.9%     6.1%     0.0%    0.0%         100% / 100%
0x0058  IN      2527      10.399     1.500    93.9%     6.1%     0.0%    0.0%         100% / 100%
0x0024  IN        12       4.582     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2502       4.582     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN      2507       4.582     1.500   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        12         533       533     2.3%     0.0%    97.7%    0.0%         100% / 100%
0x0023  IN      2486         533       533     1.5%    98.5%     0.0%    0.0%           17% / 17%
0x0023  IN      2502         533       533     1.5%    98.5%     0.0%    0.0%           11% / 11%
0x0012  OUT       12         410       410     0.0%     0.0%   100.0%    0.0%          95% / 100%
0x0011  IN        12         243       243    63.4%    36.6%     0.0%    0.0%         100% / 100%
0x0021  IN        12         217       217     0.5%    98.2%     1.4%    0.0%           17% / 20%
0x0021  IN      2511         217       217     0.9%    99.1%     0.0%    0.0%           17% / 20%
0x0021  IN      2525         217       217     0.5%    99.1%     0.5%    0.0%           17% / 20%
0x0021  IN      2529         217       217     0.5%    99.1%     0.5%    0.0%           17% / 20%
0x0021  IN      2546         217       217     0.5%    99.1%     0.5%    0.0%           17% / 20%
0x0021  IN      2549         217       217     0.5%    99.1%     0.5%    0.0%           17% / 20%
0x0021  IN      2550         217       217     0.5%    99.1%     0.5%    0.0%           17% / 20%
0x002E  IN        12         207       207     0.0%   100.0%     0.0%    0.0%           26% / 26%
0x002E  IN      2521         207       207     5.3%    94.7%     0.0%    0.0%           19% / 19%
0x002E  IN      2528         207       207   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN        12         196       196     0.0%     0.0%   100.0%    0.0%           96% / 96%
0x003D  IN      2512         196       196   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN      2520         196       196     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x0047  IN        12         125       125     0.0%     0.0%   100.0%    0.0%            8% / 23%
0x000B  OUT       12         120       120   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007E  IN         -          98         -                                     no script
0x0055  IN        12          80        80     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0055  IN      2521          80        80     0.0%   100.0%     0.0%    0.0%           99% / 99%
0x0055  IN      2528          80        80    87.5%     3.8%     8.8%    0.0%         100% / 100%
0x0048  IN        12          43        43     0.0%   100.0%     0.0%    0.0%           48% / 48%
0x0048  IN      2504          43        43   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0048  IN      2507          43        43   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005E  IN        12          36        36     0.0%    88.9%    11.1%    0.0%            0% / 26%
0x005E  IN      2506          36        36   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN        12          26        26     0.0%   100.0%     0.0%    0.0%            0% / 20%
0x0052  IN      2516          26        26    61.5%    38.5%     0.0%    0.0%         100% / 100%
0x00A8  IN         -          25         -                                     no script
0x0006  IN        12          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  IN      2486          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT     2486          19        19   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN        12          15        15     0.0%    80.0%    20.0%    0.0%           9% / 100%
0x006B  IN      2507          15        15    53.3%    46.7%     0.0%    0.0%         100% / 100%
0x006B  IN      2511          15        15    13.3%    86.7%     0.0%    0.0%           8% / 100%
0x006B  IN      2524          15        15    46.7%    53.3%     0.0%    0.0%           2% / 100%
0x006B  IN      2525          15        15     6.7%    93.3%     0.0%    0.0%            2% / 20%
0x006B  IN      2546          15        15     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2549          15        15     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x006B  IN      2550          15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CC  IN        12          13        13     0.0%    76.9%    23.1%    0.0%           10% / 50%
0x005E  OUT        -          12         -                                     no script
0x006C  IN        12          12        12     0.0%   100.0%     0.0%    0.0%           20% / 50%
0x0045  IN        12          11        11     0.0%     9.1%    90.9%    0.0%           98% / 98%
0x0061  IN        12          11        11     0.0%     0.0%   100.0%    0.0%           0% / 100%
0x0069  IN        12          11        11     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2486          11        11     9.1%    63.6%    27.3%    0.0%           20% / 47%
0x0069  IN      2496          11        11     9.1%    63.6%    27.3%    0.0%           47% / 54%
0x0069  IN      2497          11        11     9.1%    63.6%    27.3%    0.0%           20% / 47%
0x0069  IN      2502          11        11     9.1%    63.6%    27.3%    0.0%           20% / 47%
0x0069  IN      2503          11        11     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2504          11        11     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2521          11        11    72.7%     0.0%    27.3%    0.0%         100% / 100%
0x0069  IN      2546          11        11     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0069  IN      2549          11        11    72.7%     0.0%    27.3%    0.0%         100% / 100%
0x0069  IN      2550          11        11    72.7%     0.0%    27.3%    0.0%         100% / 100%
0x006A  IN        12          11        11    45.5%    54.5%     0.0%    0.0%          83% / 100%
0x006A  IN      2486          11        11    72.7%    27.3%     0.0%    0.0%         100% / 100%
0x006A  IN      2500          11        11    27.3%    72.7%     0.0%    0.0%          20% / 100%
0x006A  IN      2502          11        11    45.5%    54.5%     0.0%    0.0%          20% / 100%
0x006A  IN      2503          11        11    45.5%    54.5%     0.0%    0.0%          20% / 100%
0x0093  IN         -          11         -                                     no script
0x004B  IN        12          10        10     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x004B  IN      2507          10        10     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x008A  IN      2511          10        10     0.0%   100.0%     0.0%    0.0%             0% / 1%
0x008A  IN      2524          10        10    70.0%    10.0%    20.0%    0.0%         100% / 100%
0x0055  OUT        -           9         -                                     no script
0x00B6  IN        12           9         9     0.0%    66.7%    33.3%    0.0%           24% / 80%
0x0038  OUT     2511           8         8     0.0%    87.5%    12.5%    0.0%           20% / 97%
0x0038  OUT     2550           8         8    62.5%    37.5%     0.0%    0.0%         100% / 100%
0x011C  IN         -           8         -                                     no script
0x0044  IN        12           7         7     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0128  IN        12           7         7    14.3%    85.7%     0.0%    0.0%          14% / 100%
0x0019  IN        12           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  IN      2500           6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001A  IN        12           6         6    50.0%    50.0%     0.0%    0.0%          36% / 100%
0x0063  IN        12           6         6     0.0%    66.7%    33.3%    0.0%           27% / 66%
0x0063  IN      2507           6         6     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x0063  IN      2518           6         6     0.0%   100.0%     0.0%    0.0%             3% / 3%
0x006D  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            8% / 14%
0x00EB  IN        12           6         6     0.0%    16.7%    83.3%    0.0%         100% / 100%
0x010A  IN        12           6         6     0.0%   100.0%     0.0%    0.0%            6% / 20%
0x012D  IN         -           6         -                                     no script
0x0138  IN         -           6         -                                     no script
0x0001  IN        12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  OUT       12           5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN        12           5         5     0.0%   100.0%     0.0%    0.0%           56% / 56%
0x004F  OUT        -           5         -                                     no script
0x006F  IN        12           5         5     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0004  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT        -           4         -                                     no script
0x000F  OUT        -           4         -                                     no script
0x0010  OUT        -           4         -                                     no script
0x0013  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0014  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0015  IN      2507           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN        12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2546           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2549           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN      2550           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0017  IN        12           4         4     0.0%     0.0%   100.0%    0.0%          29% / 100%
0x0017  IN      2500           4         4     0.0%   100.0%     0.0%    0.0%             0% / 0%
0x0017  IN      2503           4         4     0.0%   100.0%     0.0%    0.0%           13% / 34%
0x0017  IN      2528           4         4     0.0%     0.0%   100.0%    0.0%          46% / 100%
0x0017  IN      2550           4         4     0.0%     0.0%   100.0%    0.0%          29% / 100%
0x001F  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           62% / 62%
0x0033  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           33% / 33%
0x0034  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0036  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           80% / 80%
0x0039  OUT       12           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           90% / 90%
0x0071  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x0073  IN        12           4         4     0.0%     0.0%   100.0%    0.0%           80% / 80%
0x0073  IN      2531           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN        12           4         4     0.0%    25.0%    75.0%    0.0%           56% / 56%
0x007D  IN      2486           4         4     0.0%    25.0%    75.0%    0.0%         100% / 100%
0x007D  IN      2502           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2503           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2546           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2549           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x007D  IN      2550           4         4    75.0%    25.0%     0.0%    0.0%         100% / 100%
0x0089  IN      2527           4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008E  OUT        -           4         -                                     no script
0x00A5  IN         -           4         -                                     no script
0x00A7  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             6% / 6%
0x00B0  OUT        -           4         -                                     no script
0x00B3  IN        12           4         4     0.0%   100.0%     0.0%    0.0%             0% / 3%
0x00B3  IN      2502           4         4     0.0%    75.0%    25.0%    0.0%             0% / 3%
0x00B9  IN        12           4         4     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00C4  IN         -           4         -                                     no script
0x00CA  IN        12           4         4     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x00CB  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            4% / 32%
0x00D1  IN         -           4         -                                     no script
0x011B  IN        12           4         4     0.0%   100.0%     0.0%    0.0%            2% / 20%
0x0126  IN         -           4         -                                     no script
0x0005  IN        12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  IN        12           3         3    66.7%     0.0%    33.3%    0.0%         100% / 100%
0x000C  IN      2507           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  IN      2525           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             5% / 5%
0x005A  IN      2490           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN      2527           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0079  OUT       12           3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0097  IN         -           3         -                                     no script
0x009E  IN         -           3         -                                     no script
0x00A9  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00AD  IN         -           3         -                                     no script
0x00B2  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             4% / 4%
0x00B5  OUT        -           3         -                                     no script
0x00B7  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           29% / 29%
0x00BD  IN        12           3         3     0.0%     0.0%   100.0%    0.0%           20% / 20%
0x00DF  IN         -           3         -                                     no script
0x00E6  IN         -           3         -                                     no script
0x00EE  IN         -           3         -                                     no script
0x00F3  IN        12           3         3     0.0%   100.0%     0.0%    0.0%           50% / 50%
0x00F4  IN        12           3         3     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x0110  IN         -           3         -                                     no script
0x0125  IN        12           3         3     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x0131  IN         -           3         -                                     no script
0x0137  IN         -           3         -                                     no script
0x013A  IN         -           3         -                                     no script
0x0022  OUT       12           2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0066  OUT        -           2         -                                     no script
0x0080  OUT        -           2         -                                     no script
0x0003  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT     2525           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  OUT        -           1         -                                     no script
0x0014  OUT        -           1         -                                     no script
0x001D  IN        12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0029  OUT       12           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x004D  IN        12           1         1     0.0%   100.0%     0.0%    0.0%             1% / 1%
0x004D  IN      2503           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2504           1         1     0.0%   100.0%     0.0%    0.0%             9% / 9%
0x004D  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2546           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2549           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN      2550           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           35% / 35%
0x004F  IN        12           1         1     0.0%   100.0%     0.0%    0.0%           20% / 20%
0x004F  IN      2507           1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0082  OUT       12           1         1     0.0%     0.0%   100.0%    0.0%         100% / 100%
0x00B8  IN        12           1         1     0.0%     0.0%   100.0%    0.0%           12% / 12%
0x0119  IN         -           1         -                                     no script

## Sample failures

### 0x0023 IN src 12  over=521 threw=0
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

### 0x0012 OUT src 12  over=410 threw=0 negative-length=139
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0012.py
  ! ReadBytes: negative length -63284 at offset 39/41
  ! ReadBytes: negative length -62786 at offset 39/41
  ! ReadBytes: negative length -59242 at offset 39/41
  last reads before failure (of 20):
       22    2  Int16    Segment 0/StateSync/SpeedCoordS/X = 11520
       24    2  Int16    Segment 0/StateSync/SpeedCoordS/Y = -10240
       26    2  Int16    Segment 0/StateSync/SpeedCoordS/Z = 767
       28    1  Byte     Segment 0/StateSync/Unknown = 69
       29    2  Int16    Segment 0/StateSync/Rotation2 CoordS / 10 = -1531
       31    2  Int16    Segment 0/StateSync/CoordS / 1000 = 0
       33    4  Int32    Segment 0/StateSync/Unknown = 2147483647
       37    2  Int16    Segment 0/StateSync/UnknownStr/size = -31642

### 0x003D IN src 12  over=196 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x003D.py
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 25, only 1 of 26 remain
  last reads before failure (of 7):
        0    8  Int64    SkillUseUid = -6433929726087784700
        8    4  Int32    ServerTick = -180720896
       12    4  Int32    ObjectId = -1698037758
       16    4  Int32    SkillId = 59
       20    2  Int16    SkillLevel = 0
       22    1  Byte     MotionPoint = 0
       23    2  Int16    PositionCoordS/X = 0

### 0x0047 IN src 12  over=125 threw=0 negative-length=75
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0047.py
  ! ReadBytes: negative length -37848 at offset 3/40
  ! ReadBytes: negative length -37848 at offset 3/40
  ! ReadBytes: negative length -37848 at offset 3/40
  last reads before failure (of 2):
        0    1  Byte     function = 0
        1    2  Int16    message/size = -18924

### 0x0061 IN src 12  over=11 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0061.py
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 1 of 1 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 757, only 1 of 758 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 0, only 5 of 5 remain
  last reads before failure (of 0):

### 0x0045 IN src 12  over=10 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0045.py
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 40, only 1 of 41 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 18, only 1 of 19 remain
  last reads before failure (of 12):
       16    2  Int16    Unknown/JobRank/JobRank = 512
       18    4  Int32    Unknown/JobRank/Points = 167772160
       22    2  Int16    Unknown/JobRank/JobRank = 0
       24    4  Int32    Unknown/JobRank/Points = 768
       28    2  Int16    Unknown/JobRank/JobRank = 768
       30    4  Int32    Unknown/JobRank/Points = 67108864
       34    2  Int16    Unknown/JobRank/JobRank = 0
       36    4  Int32    Unknown/JobRank/Points = 12800

### 0x0055 IN src 2528  over=7 threw=0
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

### 0x006F IN src 12  over=5 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x006F.py
  ! Read<Int32>: wanted 4 byte(s) at offset 6811, only 3 of 6814 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 6811, only 3 of 6814 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 6811, only 3 of 6814 remain
  last reads before failure (of 1728):
     6779    4  Int32    function = 0
     6783    4  Int32    function = 0
     6787    4  Int32    function = 0
     6791    4  Int32    function = 268435456
     6795    4  Int32    function = 0
     6799    4  Int32    function = 0
     6803    4  Int32    function = 0
     6807    4  Int32    function = 0

### 0x00EB IN src 12  over=5 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00EB.py
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    CameraId = 1
        4    1  Boolean  Enabled = False

### 0x0015 IN src 12  over=4 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0015.py
  ! Read<Int32>: wanted 4 byte(s) at offset 1466, only 3 of 1469 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 1502, only 3 of 1505 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 444, only 3 of 447 remain
  last reads before failure (of 325):
     1434    4  Int32    Unlocked Taxis/MapId = 889204224
     1438    4  Int32    Unlocked Taxis/MapId = 788541696
     1442    4  Int32    Unlocked Taxis/MapId = 1627417856
     1446    4  Int32    Unlocked Taxis/MapId = 1577060864
     1450    4  Int32    Unlocked Taxis/MapId = 1946183680
     1454    4  Int32    Unlocked Taxis/MapId = 1879077888
     1458    4  Int32    Unlocked Taxis/MapId = 1056994048
     1462    4  Int32    Unlocked Taxis/MapId = 788544000

### 0x0017 IN src 12  over=4 threw=0 negative-length=1
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0017.py
  ! ReadBytes: wanted 51200 byte(s) at offset 965, only 2360 of 3325 remain
  ! ReadBytes: negative length -2093804771 at offset 3258/3661
  ! Read<Int64>: wanted 8 byte(s) at offset 1350, only 6 of 1356 remain
  last reads before failure (of 134):
      940    8  Int64    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/CreationTime = 13267153977444
      948    2  Int16    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UGC Url/size = 0
      950    0  Field    gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/UGC Url/UGC Url = 
      950    1  Byte     gameObject_vtbl+572 virtual call/CubeItemInfo/CUgcItemLook/Unknown = 0
      951    4  Int32    gameObject_vtbl+572 virtual call/Unknown = 25600
      955    4  Int32    SkinColor/Color1 = 25600
      959    4  Int32    SkinColor/Color2 = 25600
      963    2  Int16    Profile Url/size = 25600

### 0x0035 IN src 12  over=4 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0035.py
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  ! Read<Byte>: wanted 1 byte(s) at offset 4, only 0 of 4 remain
  last reads before failure (of 1):
        0    4  Int32    UserObjectId = 0
