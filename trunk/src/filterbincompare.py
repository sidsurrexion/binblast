#!/usr/bin/python
# Program:	filterbincompare.py
# Programmer:	Scott Miller
# Description:	A program to filter the output of bincompare into
#		 a number of more useful (usually smaller) files.
#		 The dominant use is for in-line filtering of results 
#	         determined by Karlin-Altschul analysis to be below the 
#		 noise threshold.  Unlike the tools in matchoutput.py,
#                filterbincompare is designed to work with large
#		 filestreams.

# binBLAST suite of binary analysis tools
# Copyright (C) 2006 Scott Miller
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

# This is required for using stdin
import sys   # Needed for stdin access

# The scoring constants
x1 = 6
x2 = 5
x3 = 4
x4 = -4

# The analysis parameters
lambdaS = 0.250000
Ks = 0.249865

import math
x = - math.log(math.log(1/0.99)) / lambdaS

def set_args():
	from optparse import OptionParser
	parser = OptionParser()
	parser.add_option("-d","--no-dirout",
		dest="dirout",
		action="store_false",
		default=True,
		help="Do not correct dirout relative offsets to absolute offsets")
	parser.add_option("-n","--nosort",
		dest="sort",
		action="store_false",
		default=True,
		help="Don't sort results (reduces memory usage)")
	parser.add_option("-t","--threshold",
		dest="minscore",
		default="1",
		help="Threshold minimum score, if score is above Karlin-Altschul threshold")
	parser.add_option("-l","--minlen",
		dest="minlen",
		default="1",
		help="Minimum match length")
	parser.add_option("-a","--filea",
		dest="coverage",
		action="store_true",
		default=False,
		help="Reduce results into matches covering only fileA")

	(options,args) = parser.parse_args()
	return(options,args)


def print_sorted(sortdict, output_stream):
	"""Using a sortdict, keyed on something sortable and valued
	with a list of items associated with that key, sort the keys
	in decreasing order and then print each item associated with
	that key to output_stream, on-per-line."""

	# Get the keys sorted in descending order
	keylist = sortdict.keys()
	keylist.sort()
	keylist.reverse()

	# Print the values in-order, one item per line
	for k in keylist:
		for item in sortdict[k]:
			output_stream.write('%s\n' % str(item) )

	# All done

def print_coverage(cov, offset, output_stream):
	"""This will output matches to output_stream to reflect only
	the coverage of fileA by all matches.  Thus, in this form,
	fileB and score are unused and are set to 0 and -1 respectively."""

	# Loop preconditions
	lastCoveredIndex = 0
	inCovered = False
	for i in range(len(cov)):
		# We're entering a covered section
		if cov[i] and (not inCovered):
			lastCoveredIndex = i
			inCovered = True
			
		# We've left a covered section, print it out
		elif (not cov[i]) and inCovered:
			output_stream.write('%d,0,-1,%d\n' % ( \
				lastCoveredIndex + offset,
				i - lastCoveredIndex) )
			inCovered = False
	# We had a coverage section that went all the way to the end
	if inCovered:
		i = len(cov)
		output_stream.write('%d,0,-1,%d\n' % ( \
			lastCoveredIndex + offset,
			i - lastCoveredIndex) )

	
def filter_stream(bincompare_stream,output_stream,options):
	"""Filter the stream of incoming results from 
	bincompare_stream and write the results to output_stream
	using the provided options."""
	# TODO: There is definitely some duplicated code between this
	#  fucntion and matchoutput.bincompare_matches.  There's
	#  probably a better way to write a common bincompare output
	#  interface

	# Bincompare streams can contain multiple result streams.
	# We've not yet seen anything.  Not we're only interested
	# in the offsets (for correct dirout files) and the lengths
	# (for coverage reductions)
	offA = 0
	lenA = 0
	offB = 0
	lenB = 0

	# Initialize the matches dictionary, which may or may not
	#  be used
	matches = {}
	cov = []

	# Convert the options into something useful
	minscore = long(options.minscore)
	minlen = long(options.minlen)
	
	# Start looking for the first file
	lookingFor = 'fileA'

	# Consider the input line-by-line
	line = bincompare_stream.readline()
	while line:
		# Remove whitespace
		line = line.strip()
		
		# Lines starting with `File ' are the cue that we've
		#  encountered a comparison output
		if line.startswith('File ') and \
		   lookingFor not in ['fileA', 'fileB']:
		   	# Are we storing anything?
		   	if matches:
				print_sorted(matches, output_stream)
				matches = {}
			if cov:
				print_coverage(cov, offA, output_stream)
				cov = {}
				
		   	lookingFor = 'fileA'
			
		# Assume shellscript-type comments and blank lines
		#  may be present in the file.  Simply pass them along
		if line.startswith('#') or line == '':
			output_stream.write('%s\n' % line)
		# We're looking for the idx files?
		elif lookingFor in ['fileA', 'fileB'] :
			# The rest of this will be in the form
			# File FILENAME, offset OFFSET, len LEN
			try:
				(filename, a)   = line[5:].split(', offset ',2)
				(offset,   dlen) =        a.split(', len'    ,2)
				offset = long(offset)
				dlen    = long(dlen)
			except ValueError:
				line = bincompare_stream.readline()
				continue
				
			# Echo this to the output
			output_stream.write('File %s, offset %d, len %d\n' % ( \
				filename,
				offset,
				dlen) )
				
			# If we're compensating for dirout, we need to
			#  keep the offsets.  Otherwise, discard
			if not options.dirout:
				offset = 0

			# Store this in our variables as necessary,
			#  prepare for the next step
			if lookingFor == 'fileA':
				offA = offset
				lenA = dlen
				lookingFor = 'fileB'
			else:
				offB = offset
				lenB = dlen
				lookingFor = 'match'
				# Before we get carried away, make sure
				#  to note that this filtering has done
				#  something
				optstr = ''
				if options.dirout:
					optstr = '%s dirout' % optstr
				if options.minlen:
					optstr = '%s minlen=%d' % (optstr, minlen) 
				if options.minscore:
					optstr = '%s minscore=%d' % (optstr, minscore)
				if options.coverage:
					optstr = '%s coverage' % optstr
					# Initialize the coverage array
					cov = []
					for i in range(lenA):
						cov.append(False)
					
				if options.sort:
					optstr = '%s sort' % optstr

				output_stream.write('# filterbincompare: %s \n' % optstr)
		elif lookingFor == 'match':
			fields = line.split(',')

			# 4+ fields == match
			if len(fields) >= 4:
			 try:
				a =     long(fields[0])
				b =     long(fields[1])
				score = long(fields[2])
				dlen =  long(fields[3])

				if score < minscore or \
				   dlen < minlen:
				   raise ZeroDivisionError
				   
				# Filtering
				gain = 20.0 * math.log10(1.0 * score / (x2 * dlen))
				noise =  ((math.log(dlen) + math.log(Ks)) / lambdaS
					) + x
				noisegain = 20.0 * math.log10(1.0 * noise / (x2 * dlen))

				# Anything useful remain?
				if gain < noisegain:
					raise ZeroDivisionError
				
				line = '%d,%d,%d,%d' % (
					a + offA,
					b + offB,
					score,
					dlen )
	
				# Include in coverage
				if options.coverage:
				 for i in range(a,a+dlen):
					cov[i] = True
				# Add to sort
				elif options.sort:
				 try:
					matches[score].append( line )
				 except KeyError:
					matches[score] = [ line ]
				else:
					output_stream.write('%s\n' % line)	
			 except ZeroDivisionError:
				pass 
		
		# Get the next line of the input stream
		line = bincompare_stream.readline()

	# Are we storing anything?
	if matches:
		print_sorted(matches, output_stream)
		matches = {}
	if cov:
		print_coverage(cov, offA, output_stream)

if __name__ == "__main__":
	import sys

	# Figure out what to do
	(options, args) = set_args()

	# Do it
	filter_stream(sys.stdin, sys.stdout, options)
	
