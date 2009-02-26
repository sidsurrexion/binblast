#!/usr/bin/python


import matchoutput
import os.path
import sys

f = open( sys.argv[1] )

(matches, idxfiles) = matchoutput.bincompare_matches(f)

f.close()

cov = []

for match in matches.values():
	# We only want to handle fileA matches
	if not match.a:
		continue
	
	# We've not yet initialed the coverage of fileA
	if not cov:
		[instructions, bytes] = matchoutput.disassemble_entry(match.entry,returnbytes=True)

		for i in range(match.entry.len):
			cov.append(0)

	# Block out what we've seen in this match
	for i in range(match.offset,match.offset + match.len):
		try:
			cov[i] = 1
		except IndexError:
			continue

# Loop preconditions
inCovered = False
for i in range(len(instructions)):
	# We're entering a covered section
	if cov[i] and (not inCovered):
		inCovered = True
	# We've left a covered section, print it out
	elif (not cov[i]) and inCovered:
		sys.stdout.write('\n')
		inCovered = False

	if not inCovered:
		x = bytes[i]
		x = x.split()
		x = ''.join(x)
		sys.stdout.write('%s' % x)

