#!/usr/bin/python

# Very simple src checker.
# Trim trailing whitespace and consecutive newlines.
# -solar 2007

import os
import sys

def crapspace(fname):
	chars = True
	fp = open(fname, "r")
	line = fp.readline()
	while line:
		line = line.rstrip()
		if line:
			chars = True
			print line
		else:
			if chars:
				print ""
			chars = False

		line = fp.readline()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		sys.stderr.write( "Usage: rstrip <file>\n")
		sys.exit(1)

	crapspace(sys.argv[1])
