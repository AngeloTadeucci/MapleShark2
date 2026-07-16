# Phase 0 harness — HOME baseline

scripts from build : 12
packets from build : 12
packets considered : 6.046.907
packets executed   : 51.129  (--sample 300 per opcode)

## Totals (weighted by executed packets)

outcome             packets   share
NoScript              7.509   14.7%
OkExact              41.689   81.5%
UnderRead             1.328   2.6%
OverRead                569   1.1%
Threw                    34   0.1%

of packets a script actually ran on (43.620):
  clean (consumed exactly) : 95.6%
  over-read (WRONG)        : 1.3%
  under-read (ambiguous)   : 3.0%

## Per opcode

opcode  dir          seen       ran    clean    under     over   threw    consumed p50/p90
0x0059  IN      1.372.121       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0024  IN        834.364       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  IN        751.740       300    99.7%     0.0%     0.3%    0.0%         100% / 100%
0x0012  OUT       606.435       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  IN        559.439       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0077  IN        279.982       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003E  IN        228.679       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0080  IN        189.747       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  IN        169.069       300    71.0%    29.0%     0.0%    0.0%         100% / 100%
0x0048  IN         99.879       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  OUT        85.690       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003D  IN         82.632       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0020  OUT        71.106       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004F  IN         65.569       300    19.0%     0.0%    81.0%    0.0%          73% / 100%
0x005F  IN         59.145       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0056  IN         58.964       300    99.7%     0.3%     0.0%    0.0%         100% / 100%
0x0042  OUT        48.401       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  IN         47.423       300    99.7%     0.3%     0.0%    0.0%         100% / 100%
0x0057  IN         43.803       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  IN         43.460       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004D  IN         38.981       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0006  OUT        18.772         -                                     no script
0x0006  IN         18.494       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  OUT        11.528       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0040  IN         10.991       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0021  OUT        10.972       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0042  IN         10.867       300     0.0%   100.0%     0.0%    0.0%           72% / 72%
0x0053  IN         10.681       300    83.3%    16.7%     0.0%    0.0%         100% / 100%
0x0022  OUT        10.606       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  IN          9.741       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0081  OUT         8.752       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0049  IN          7.434       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0068  IN          6.478       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0095  IN          5.347         -                                     no script
0x00AA  IN          4.810       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0065  IN          4.383       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006B  IN          3.822       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006C  IN          3.722       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0038  IN          3.510       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0030  IN          3.383       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006E  IN          3.336         -                                     no script
0x0014  IN          3.125       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x012A  IN          3.082       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0046  IN          3.057       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0034  OUT         2.989       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  IN          2.940       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0063  IN          2.799       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0050  IN          2.773       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011B  IN          2.747       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011E  IN          2.738       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0035  OUT         2.722       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002B  IN          2.718       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0050  OUT         2.717         -                                     no script
0x001D  IN          2.704       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  IN          2.616       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  IN          2.606       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0011  OUT         2.561         -                                     no script
0x002D  IN          2.296       300    52.7%    47.3%     0.0%    0.0%         100% / 100%
0x001A  IN          2.176       300    97.3%     2.7%     0.0%    0.0%         100% / 100%
0x0005  IN          2.090       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B8  IN          2.081       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005C  OUT         2.023         -                                     no script
0x0045  IN          1.864       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  IN          1.664       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CE  IN          1.529       300    50.7%    49.3%     0.0%    0.0%         100% / 100%
0x0041  OUT         1.528       300     9.7%    63.0%    27.3%    0.0%           25% / 90%
0x0029  OUT         1.505       300    96.3%     3.7%     0.0%    0.0%         100% / 100%
0x00B2  IN          1.478       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  IN          1.426       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00E3  IN          1.423         -                                     no script
0x0019  IN          1.414       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006F  IN          1.407       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001C  OUT         1.367         -                                     no script
0x010C  IN          1.362         -                                     no script
0x0034  IN          1.332       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00ED  IN          1.323       300    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x00CC  IN          1.305       300    97.0%     0.0%     3.0%    0.0%         100% / 100%
0x008F  OUT         1.287       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003A  OUT         1.275         -                                     no script
0x0039  OUT         1.232       300    99.3%     0.7%     0.0%    0.0%         100% / 100%
0x0017  IN          1.230       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0037  IN          1.220       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x011D  IN          1.213       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F5  IN          1.208       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000F  OUT         1.201         -                                     no script
0x0010  OUT         1.200         -                                     no script
0x00D3  IN          1.192       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  IN          1.185       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0036  IN          1.185       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007F  IN          1.184       300    99.7%     0.3%     0.0%    0.0%         100% / 100%
0x001F  IN          1.184       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007B  IN          1.118       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00E8  IN          1.027       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F3  IN          1.021       300    58.7%     0.0%    41.3%    0.0%         100% / 100%
0x0031  OUT         1.019       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0105  IN            985       300    94.3%     0.0%     5.7%    0.0%         100% / 100%
0x0056  OUT           937       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001D  OUT           919       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0055  IN            902       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0071  IN            883       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F6  IN            872       300    82.3%    17.7%     0.0%    0.0%         100% / 100%
0x00F8  IN            868       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0054  IN            848       300    97.7%     2.3%     0.0%    0.0%         100% / 100%
0x000C  OUT           814       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0013  IN            812       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0052  IN            798       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C7  IN            763       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0001  IN            746       300    97.0%     3.0%     0.0%    0.0%         100% / 100%
0x0001  OUT           746       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005B  IN            744       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C6  IN            726       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0127  IN            724         -                                     no script
0x00B7  OUT           724       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  OUT           720       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  IN            720       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B2  OUT           720       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A7  IN            719       300    96.7%     3.3%     0.0%    0.0%         100% / 100%
0x0128  IN            718       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0004  IN            711       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B5  IN            709       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A9  IN            700       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0015  IN            699       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  OUT           699         -                                     no script
0x00BB  OUT           699         -                                     no script
0x00AF  IN            698         -                                     no script
0x00BF  IN            695       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0112  IN            695         -                                     no script
0x00B4  IN            690       300    86.7%     2.0%    11.3%    0.0%         100% / 100%
0x0132  IN            686         -                                     no script
0x00B9  IN            685       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00BB  IN            685       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008B  IN            682       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AB  IN            681       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A0  IN            681       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00E1  IN            681       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F0  IN            681       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006D  OUT           680       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0096  IN            665         -                                     no script
0x00A6  IN            663       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x008C  IN            642       300    98.7%     1.3%     0.0%    0.0%         100% / 100%
0x002E  OUT           595       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005C  IN            507       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0010  IN            489       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0060  IN            486       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0125  IN            479       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C5  IN            447       300   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B4  OUT           434         -                                     no script
0x0062  IN            281       281   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00F4  IN            238       238   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0043  IN            220       220   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000C  IN            208       208   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0016  OUT           206         -                                     no script
0x003B  OUT           192       192    84.4%     7.3%     8.3%    0.0%         100% / 100%
0x0098  IN            183       183    99.5%     0.5%     0.0%    0.0%         100% / 100%
0x0092  IN            155         -                                     no script
0x004A  IN            154       154   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0025  IN            143       143   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005B  OUT           140       140    98.6%     1.4%     0.0%    0.0%         100% / 100%
0x00A6  OUT           138         -                                     no script
0x0072  IN            137       137   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0026  IN            128       128   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x006A  IN            119       119   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A5  OUT           113         -                                     no script
0x0037  OUT           101       101    99.0%     1.0%     0.0%    0.0%         100% / 100%
0x00CD  IN             93        93   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0022  IN             93        93   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0102  IN             89        89    67.4%    32.6%     0.0%    0.0%         100% / 100%
0x0099  IN             88        88   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  IN             81        81   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C3  IN             81        81   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005F  OUT            80        80   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004B  OUT            78        78   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0086  IN             78        78   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0039  IN             78        78   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007D  IN             76        76    65.8%    34.2%     0.0%    0.0%         100% / 100%
0x0028  OUT            75        75     0.0%   100.0%     0.0%    0.0%            8% / 11%
0x001E  IN             72        72   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0101  IN             68        68     0.0%   100.0%     0.0%    0.0%           45% / 45%
0x001A  OUT            68         -                                     no script
0x00AE  IN             68         -                                     no script
0x0049  OUT            67        67   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A3  OUT            66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x010E  IN             66        66   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007A  OUT            66        66    98.5%     1.5%     0.0%    0.0%         100% / 100%
0x0066  OUT            66         -                                     no script
0x0025  OUT            64        64   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00FD  IN             64         -                                     no script
0x0048  OUT            59         -                                     no script
0x0082  IN             57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  IN             57         -                                     no script
0x005E  IN             57        57   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  OUT            56        56    92.9%     7.1%     0.0%    0.0%         100% / 100%
0x0035  IN             55        55   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0041  IN             55        55   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0023  OUT            55        55    80.0%     0.0%    20.0%    0.0%         100% / 100%
0x0081  IN             54         -                                     no script
0x001F  OUT            53         -                                     no script
0x0018  OUT            53        53    84.9%    15.1%     0.0%    0.0%         100% / 100%
0x002B  OUT            52        52   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x005A  IN             51        51   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0067  IN             50        50   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0012  IN             49        49   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  OUT            49        49   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002F  OUT            48        48    27.1%    72.9%     0.0%    0.0%          17% / 100%
0x00BA  IN             46        46   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C9  IN             46        46    89.1%    10.9%     0.0%    0.0%         100% / 100%
0x009A  OUT            45        45   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004C  OUT            44        44    97.7%     2.3%     0.0%    0.0%         100% / 100%
0x00B9  OUT            43         -                                     no script
0x00F2  IN             41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EA  IN             41        41   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00EB  IN             37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x001B  IN             37        37    13.5%     0.0%     0.0%   86.5%          27% / 100%
0x0017  OUT            37         -                                     no script
0x002D  OUT            37        37   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0110  IN             37         -                                     no script
0x0078  IN             36        36   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0009  IN             35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0121  IN             35        35   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0019  OUT            33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0032  IN             33        33   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0074  OUT            30        30   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0111  IN             29         -                                     no script
0x003D  OUT            29         -                                     no script
0x009A  IN             29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00AF  OUT            29        29   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000B  IN             28        28   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0067  OUT            27         -                                     no script
0x0013  OUT            26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0032  OUT            26         -                                     no script
0x0060  OUT            26        26   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0030  OUT            25        25   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x010F  IN             25         -                                     no script
0x00A4  OUT            22        22    59.1%    31.8%     0.0%    9.1%         100% / 100%
0x0079  OUT            21        21    57.1%    42.9%     0.0%    0.0%         100% / 100%
0x003B  IN             20        20   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0075  OUT            19        19    84.2%    15.8%     0.0%    0.0%         100% / 100%
0x010B  IN             18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0018  IN             18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007C  OUT            18        18   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000E  IN             17        17   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A3  IN             17         -                                     no script
0x00F9  IN             16         -                                     no script
0x002A  IN             16        16     6.2%     0.0%    93.8%    0.0%         100% / 100%
0x0100  IN             15        15   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0058  OUT            14         -                                     no script
0x0027  OUT            14        14   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0003  OUT            14        14     0.0%     0.0%   100.0%    0.0%            5% / 53%
0x0014  OUT            12         -                                     no script
0x0005  OUT            12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0007  IN             12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0008  IN             12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0007  OUT            12         -                                     no script
0x0008  OUT            12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0051  IN             12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CF  IN             12        12   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00B6  OUT            11        11   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0083  OUT            10         -                                     no script
0x009B  IN              9         9   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000A  IN              8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x009F  IN              8         8   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x002C  OUT             7         7   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00D8  IN              6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x000D  OUT             6         -                                     no script
0x0070  IN              6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00D0  IN              6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00A8  OUT             6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0114  IN              6         6   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0047  IN              5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00D1  IN              5         -                                     no script
0x000F  IN              5         5   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x004E  OUT             5         -                                     no script
0x00DE  IN              5         -                                     no script
0x009E  OUT             5         -                                     no script
0x009C  OUT             5         -                                     no script
0x0104  IN              5         5     0.0%   100.0%     0.0%    0.0%           67% / 67%
0x009D  OUT             5         -                                     no script
0x008B  OUT             5         -                                     no script
0x0036  OUT             4         4   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0044  OUT             4         -                                     no script
0x0122  IN              3         -                                     no script
0x0082  OUT             3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0045  OUT             3         -                                     no script
0x007E  IN              3         -                                     no script
0x0076  OUT             3         3   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00CA  IN              3         3     0.0%     0.0%   100.0%    0.0%           88% / 88%
0x00C1  IN              3         -                                     no script
0x0052  OUT             2         2   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x00C8  IN              2         -                                     no script
0x010D  IN              2         -                                     no script
0x0072  OUT             2         -                                     no script
0x0085  IN              1         -                                     no script
0x0094  IN              1         -                                     no script
0x0046  OUT             1         -                                     no script
0x001E  OUT             1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x007A  IN              1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x003C  IN              1         1     0.0%   100.0%     0.0%    0.0%           86% / 86%
0x004F  OUT             1         -                                     no script
0x00DF  IN              1         -                                     no script
0x0084  OUT             1         -                                     no script
0x00D9  IN              1         -                                     no script
0x006A  OUT             1         -                                     no script
0x00AD  IN              1         -                                     no script
0x008A  IN              1         -                                     no script
0x0031  IN              1         1   100.0%     0.0%     0.0%    0.0%         100% / 100%
0x0073  OUT             1         -                                     no script

## Sample failures

### 0x004F IN  over=243 threw=0 negative-length=2
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x004F.py
  ! Read<Single>: wanted 4 byte(s) at offset 18, only 2 of 20 remain
  ! Read<Single>: wanted 4 byte(s) at offset 18, only 2 of 20 remain
  ! Read<Single>: wanted 4 byte(s) at offset 18, only 2 of 20 remain
  last reads before failure (of 9):
        1    4  Int32    count = 3
        5    4  Int32    SomeTriggerId = 101
        9    1  Boolean  IsVisible = False
       10    1  Boolean  TriggerMesh/UnknownBool = True
       11    1  Byte     TriggerMesh/UnknownByte = 0
       12    4  Int32    TriggerMesh/UnknownInt = 1728053248
       16    2  Int16    TriggerMesh/UnknownStr/size = 0
       18    0  Field    TriggerMesh/UnknownStr/UnknownStr = 

### 0x00F3 IN  over=124 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00F3.py
  ! Read<Int16>: wanted 2 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 5, only 0 of 5 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 5, only 0 of 5 remain
  last reads before failure (of 2):
        0    4  Int32    Unknown = 1
        4    1  Byte     Unknown = 0

### 0x0041 OUT  over=82 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0041.py
  ! Read<Int64>: wanted 8 byte(s) at offset 61, only 7 of 68 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 61, only 7 of 68 remain
  ! Read<Int64>: wanted 8 byte(s) at offset 61, only 7 of 68 remain
  last reads before failure (of 17):
       36    2  Int16    CUgcItemLook/ItemName/size = 0
       38    0  Field    CUgcItemLook/ItemName/ItemName = 
       38    1  Byte     CUgcItemLook/Unknown = 0
       39    4  Int32    CUgcItemLook/Unknown = 0
       43    8  Int64    CUgcItemLook/AccountId = 0
       51    8  Int64    CUgcItemLook/CharacterId = 0
       59    2  Int16    CUgcItemLook/CharacterName/size = 0
       61    0  Field    CUgcItemLook/CharacterName/CharacterName = 

### 0x00B4 IN  over=34 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00B4.py
  ! ReadBytes: wanted 51426 byte(s) at offset 39, only 1012 of 1051 remain
  ! ReadBytes: wanted 51426 byte(s) at offset 39, only 1012 of 1051 remain
  ! ReadBytes: wanted 51426 byte(s) at offset 39, only 1012 of 1051 remain
  last reads before failure (of 5):
        0    1  Byte     Function = 0
        1    4  Int32    count = 15
        5    2  Int16    Entry 0/event/size = 15
        7   30  Field    Entry 0/event/event = 4700750069006C006400560073004700..
       37    2  Int16    Entry 1/event/size = 25713

### 0x001B IN  over=0 threw=32
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x001B.py
  ! expected str, got Int32
  ! expected str, got Int32
  ! expected str, got Int32
  last reads before failure (of 12):
        7    4  Int32    Time? (s) = 431
       11    4  Int32    Score? = -1
       15    4  Int32    MaxScore? = -1
       19    1  Byte     Unknown = 2
       20    1  Byte     Unknown = 0
       21    1  Byte     Unknown = 0
       22    1  Byte     Unknown = 0
       23    4  Int32    Reward/RewardCount = 3

### 0x0105 IN  over=17 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x0105.py
  ! Read<Single>: wanted 4 byte(s) at offset 353, only 1 of 354 remain
  ! Read<Single>: wanted 4 byte(s) at offset 343, only 1 of 344 remain
  ! Read<Single>: wanted 4 byte(s) at offset 363, only 1 of 364 remain
  last reads before failure (of 105):
      327    4  Single   Item: 0/Stats/Empowerment Stats 2/SpecialOption 18/FloatValue = 2,5431157E+30
      331    2  Int16    Item: 0/Stats/Empowerment Stats 2/StatType = 18176
      333    4  Single   Item: 0/Stats/Empowerment Stats 2/SpecialOption 19/FloatValue = 0
      337    4  Single   Item: 0/Stats/Empowerment Stats 2/SpecialOption 19/FloatValue = 0
      341    2  Int16    Item: 0/Stats/Empowerment Stats 2/StatType = 0
      343    4  Single   Item: 0/Stats/Empowerment Stats 2/SpecialOption 20/FloatValue = 0
      347    4  Single   Item: 0/Stats/Empowerment Stats 2/SpecialOption 20/FloatValue = 0
      351    2  Int16    Item: 0/Stats/Empowerment Stats 2/StatType = 0

### 0x003B OUT  over=16 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x003B.py
  ! Read<Int16>: wanted 2 byte(s) at offset 1, only 0 of 1 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 1, only 0 of 1 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 1, only 0 of 1 remain
  last reads before failure (of 1):
        0    1  Byte     Function = 7

### 0x002A IN  over=15 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x002A.py
  ! Read<Int64>: wanted 8 byte(s) at offset 290, only 6 of 296 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 243, only 1 of 244 remain
  ! Read<Int32>: wanted 4 byte(s) at offset 243, only 1 of 244 remain
  last reads before failure (of 85):
      269    4  Int32    Item: 10200000/Transfer/Remaining Trades = 0
      273    4  Int32    Item: 10200000/Transfer/Remaining Repackage Count = 0
      277    1  Byte     Item: 10200000/Transfer/Unknown = 0
      278    1  Boolean  Item: 10200000/Transfer/Unknown = False
      279    1  Byte     Item: 10200000/Transfer/IsBound = 0
      280    1  Byte     Item: 10200000/GemSockets/MaxSockets = 0
      281    1  Byte     Item: 10200000/GemSockets/TotalSockets = 0
      282    8  Int64    Item: 10200000/PairedCharacterId = 0

### 0x0003 OUT  over=14 threw=0 negative-length=8
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0003.py
  ! ReadBytes: wanted 45776 byte(s) at offset 3, only 59 of 62 remain
  ! ReadBytes: wanted 45776 byte(s) at offset 3, only 59 of 62 remain
  ! ReadBytes: wanted 45776 byte(s) at offset 3, only 59 of 62 remain
  last reads before failure (of 2):
        0    1  Byte     mode = 2
        1    2  Int16    username/size = 22888

### 0x0023 OUT  over=11 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Outbound\0x0023.py
  ! Read<Single>: wanted 4 byte(s) at offset 27, only 0 of 27 remain
  ! Read<Single>: wanted 4 byte(s) at offset 83, only 0 of 83 remain
  ! Read<Single>: wanted 4 byte(s) at offset 83, only 0 of 83 remain
  last reads before failure (of 10):
        2    1  Byte     UseVoucher = 1
        3    4  Int32    BeautyItemShopId = 10300040
        7    4  Int32    ItemExtraData/EquipColor/Color1 = -8457224
       11    4  Int32    ItemExtraData/EquipColor/Color2 = -10905179
       15    4  Int32    ItemExtraData/EquipColor/Color3 = -16168604
       19    4  Int32    ItemExtraData/EquipColor/ColorIndex = 14
       23    4  Int32    ItemExtraData/EquipColor/Unknown = 3
       27    0  Field    ItemExtraData/102 = 

### 0x00CC IN  over=9 threw=0
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00CC.py
  ! Read<Int16>: wanted 2 byte(s) at offset 2, only 0 of 2 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 2, only 0 of 2 remain
  ! Read<Int16>: wanted 2 byte(s) at offset 2, only 0 of 2 remain
  last reads before failure (of 2):
        0    1  Byte     Function = 1
        1    1  Byte     type = 3

### 0x00CA IN  over=3 threw=0 negative-length=3
script: D:\Projetos\MapleStory2\MapleShark2 - Ochi\Scripts\0\12\Inbound\0x00CA.py
  ! ReadBytes: negative length -34572 at offset 274/312
  ! ReadBytes: negative length -34572 at offset 274/312
  ! ReadBytes: negative length -34572 at offset 274/312
  last reads before failure (of 85):
      251    1  Byte     Item: 0/GemSockets/MaxSockets = 0
      252    1  Byte     Item: 0/GemSockets/TotalSockets = 0
      253    8  Int64    Item: 0/PairedCharacterId = 1099511633920
      261    2  Int16    Item: 0/PairedName/size = 0
      263    0  Field    Item: 0/PairedName/PairedName = 
      263    1  Boolean  Item: 0/Unknown = False
      264    8  Int64    Item: 0/BoundToCharId = 2526801969738153984
      272    2  Int16    Item: 0/BoundToName/size = -17286
