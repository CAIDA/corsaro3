#!/usr/bin/python

import string,sys

inf = sys.argv[1]
outf = sys.argv[2]

intervalts = None
intervalnum = None
state = None

with open(outf, 'w') as out:
    with open(inf, 'r') as f:

        for line in f:
            line = line.strip()

            if line.startswith("# CORSARO_INTERVAL_START"):
                s = line.split(' ')
                intervalts = s[3]
                intervalnum = s[2]
                state = "intstart"
            elif line.startswith("# CORSARO_INTERVAL_END"):
                state = None
            elif state == "intstart":
                state = "intbody"
            elif state == "intbody" and line.startswith("START PACKET"):
                state = "packetbody"
            elif state == "intbody":
                assert(',' in line)
                line += ",%s,%s" % (intervalnum, intervalts)
                out.write(line + "\n")
            elif state == "packetbody":
                if line.startswith("END PACKET"):
                    state = "intbody"


