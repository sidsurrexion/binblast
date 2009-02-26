#!/usr/bin/python
# Program:    binblast_html.py
# Programmer: Scott Miller
# Function:   A simple html/CGI interface to the major binblast programs --
#              mklib, bincompare, and matchoutput. 

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

# Important reminders (read the warranty above for the real text):
#  Running the queries with bincompare requires an external invocation of
#   the bincompare binary.  This can be computationally expensive and also
#   server as a security hazard.
#  It is not yet intended that this be part of a publically accessible
#   Internet web page but rather run on a local server and accessed 
#   locally (like Autopsy or similar.)

# We're going to need this to parse through the CGI
import cgi

# The next line enables the python CGI debugger, comment out to allow
#  quieter failures
import cgitb; cgitb.enable()

# The directory in which to cache results as well as
#  a unique prefix to identify
tmp_dir = "/tmp/"

# When uploading files, where should this go?
upload_distname = 'uploads'
work_dir = '/var/www/workdir/'

# Basic output formatting
#################################################
def print_header(title):
	print """<html>

<head><title>binBLAST - %s</title></head>
<body>
<table width="100%%">
	<tr bgcolor="000000"><td bgcolor="000000">
	<h2><font color='FFFFFF'>binBLAST - %s</font></h2>
	
	<font color='#ffffff' link='#ffffff' vlink='#ffffff'>
	<a href="?action=add_file">Add a file</a> -
	<a href="?action=run_query">Run a query</a> -
	<a href="?action=show_results">View results</a>	
	</font>

	</td>
	</tr>
	
	<tr><td>
""" % (title, title)

def print_footer():
	print """
	</td></tr><tr bgcolor="000000" align="right">
	<td bgcolor="000000"><font color='ffffff'>
<small><em>binBLAST Copyright (C) 2006 Scott Miller</em></small></font>
	</td></tr>
							
	</table>
</body></html>
"""

# Functions to help ensure clean data comes in
##################################################
def scrubname(name):
	"""Returns a scrubbed version of name:
	NO absolute paths
	NO parent directory references ('../')"""
	# No parent/current directory references
	name = name.replace('../','')
	name = name.replace('./','')
	
	# No directories at all...
	# (thus it will necessarily be a relative
	# file name)
	name = name.replace('/','_')

	return(name)
	
# Specific interface functions
##################################################
def home(form):
	print_header('Main')
	print '<ul>'
	print '<li><a href="?action=add_file">Add a file</a>'
	print '<li><a href="?action=run_query">Run a query</a>'
	print '<li><a href="?action=show_results">View results</a>'	
	print '</ul>'

def add_file(form):
	# TODO: Catch exceptions

	# Has a file been presented or should we
	#  query for a file?
	import os.path
	import mklib
	
	if form.has_key('file'):
		filename = form['file'].filename
		filename = scrubname(filename)

		print_header('Adding %s' % filename)

		print '<pre>'
		print 'Received filename %s' % filename
		print 'Adding to %s...' % upload_distname
		# Firstly, be suspcious of incoming filenames

		# Save into the work directory
		absfilename = os.path.join(work_dir, filename)
		file = open(absfilename,'wb')
		file.write(form['file'].file.read())
		file.close()

		# Disassemble and chronicle...
		options = mklib.MklibOpts()
		options.bin = True
		options.database = False
		options.verbose = True

		mklib.process_archive(absfilename, \
			os.path.join(work_dir,upload_distname), \
			options)
	

		# All done
		print "Complete</pre>"
		
	else:
		print_header('Add file')
		
		print "Current supported filetypes: %s " % ','.join(mklib.archives)
		print "<form method=post enctype='multipart/form-data'>"
		print "File to upload: <input type=file name='file'><br>"
		print "<input type=hidden name='action' value='add_file'>"
		print "<input type=submit value='Upload'>"
		print '</form>'

def run_query(form):
	# TODO: Support for more than just the upload_distname files
	# TODO: Distribution ISO is ignored right now
	# TODO: Allow range selection by index, distribution, or archive.
	# Concept: This basically links each entry to a pair of numbers,
	#  the idxfile it's in and its line number.

	import os
	import matchoutput
	
	if form.has_key('idx_files'):
		outfile = scrubname( form['output'].value )
		if not outfile.endswith('.out'):
			outfile = "%s.out" % outfile
	
		print_header('Running query - %s' % outfile)
		
		# Keep track of the entries we're going to need
		entrylist = [ [], [] ]
		
		# We need to get all of the selected entries
		idxfiles = form['idx_files'].value.split(',')
		# A list of matchout.idxFiles, useful for getting full
		#  entries
		idxlist = []
		for i in range(len(idxfiles)):
			idxfile = open(os.path.join(work_dir,idxfiles[i]))
			idxlist.append(matchoutput.idxFile( \
			 os.path.join(work_dir,idxfiles[i])) )

			
			linenum = 0
			line = idxfile.readline()
			x = matchoutput.idxEntry()
			while line:
				# If this wasn't included, keep going
				if (not form.has_key('A*%d*%d' % (i, linenum))) and \
				   (not form.has_key('B*%d*%d' % (i, linenum))):
				   line = idxfile.readline()
				   linenum += 1
				   continue
				
				# Get the entry
				x = matchoutput.idxEntry()
				x.fromIDX(line)

				# Get the full entry (using idxFile)
				x = (idxlist[i])[x.start]

				# Add to each list as necessary
				if form.has_key('A*%d*%d' % (i, linenum)):
					entrylist[0].append(x)
				if form.has_key('B*%d*%d' % (i, linenum)):
					entrylist[1].append(x)
					
				# Keep going
				linenum += 1
				line = idxfile.readline()

		# We've now got a bunch of entries, some without len (just
		#  offsets).  Fill in the details and generate a series of 
		#  bincompare statements
		# TODO: Combine entries? (Keeping them separate allows for
		#  obvious parallelism)
		comparelist = []

		out = open(os.path.join(work_dir, outfile),'w')
		for a in entrylist[0]:
			for b in entrylist[1]:
				bout = os.popen('bincompare %s.dat %d %d %s.dat %d %d' % ( \
					a.idx.name[:-4],
					a.start,
					a.len,
					b.idx.name[:-4],
					b.start,
					b.len ) )
				out.write(bout.read())
				bout.close()
				out.write('\n\n\n\n')
		out.close()
		
		for x in comparelist:
			print "<li>%s" % x
		print "</ul>"
	else:
		print_header('Run query')
		print '<form>'
		print 'Output file:<input type=text name="output" value="bincompare.out"><br><ol>'
		# Okay, we need all of the IDX files
		files = os.listdir(work_dir)
		idxfiles = []
		for file in files:
		 if file.endswith('.idx'):
		  idxfiles.append(file)
		
		# Every IDX file, every entry:
		for i in range(len(idxfiles)):
			print '<li> %s' % idxfiles[i]
			print ' <ul>'
			idxfile = open(os.path.join(work_dir,idxfiles[i]))
			
			# Loop preconditions...
			x = matchoutput.idxEntry()
			line = idxfile.readline()
			linenum = 0
			curarchive = ''
			# Read all lines from this file
			while line:
				# Process
				x.fromIDX(line)

				# Need another level for a new archive?
				if x.archive == curarchive:
					pass
				elif curarchive:
					print " </ol>"
					print " <li>%s" % x.archive
					print " <ol start=%d>" % (linenum + 1)
					curarchive = x.archive
				else:
					print " <li> %s" % x.archive
					print " <ol start=%d>" % (linenum + 1)
					curarchive = x.archive

				# Print this file
				print """  <li><input type=checkbox 
	name='A*%d*%d'><input type=checkbox name = 'B*%d*%d'>%s""" % ( \
					i, linenum,
					i, linenum,
					x.file)

				# Get the next line
				linenum += 1
				line = idxfile.readline()
			if curarchive:
				print "  </ol>"
			print ' </ul>'
		
		print """</ol>
		<input type=hidden name='idx_files' value='%s'>
		<input type=hidden name='action' value='run_query'>
		<input type=submit value="Go">
		</form>""" % ','.join(idxfiles)

def display_side_by_side(form):
	import matchoutput

	
        # Get the IDX files
	fileA = matchoutput.idxFile( form['idxA'].value )
	if form['idxA'].value != form['idxB'].value:
		fileB = matchoutput.idxFile( form['idxB'].value )
	else:
		fileB = fileA

	# Get the start and lengths
	startA = long( form['startA'].value )
	lenA = long( form['lenA'].value )
	startB = long( form['startB'].value )
	lenB = long( form['lenB'].value )

	# We need the IDX entries involved
	entryA = fileA[ startA ]
	entryB = fileB[ startB ]

	# Figure out the in-file offsets
	offA = startA - entryA.start
	offB = startB - entryB.start

	# Create new matches for these
	matchA = matchoutput.bincompareMatch(entryA, \
			offA, \
			lenA, \
			long(form['score'].value) )
	matchB = matchoutput.bincompareMatch(entryB, \
			offB, \
			lenB, \
			long(form['score'].value) )

	print_header('Display query - %d vs. %d, %d' % (startA, startB, lenB) )

	# Disassemble the entries
	matches = [matchA, matchB]
	disassembly = []
	for i in matches:
		# TODO: It's going to try to mount an iso if there is a
		#  distname
		i.entry.distname = ''
		disassembly.append( matchoutput.disassemble_entry(i.entry) )
	
	# Print the table
	print '<table>'
	print '<tr><td colspan=4 align=center>'
	print 'Score: %d  Len: %d' % (matchA.score, matchA.len)
	print '<tr>'
	for i in matches:
		print '<td colspan=2>'
		print '%s<br>%s' % ( \
			i.entry.file,
			i.entry.archive )
		print '</td>'
	for offset in range(0,matches[0].len):
		# Figure out the alignment
		aligned = []
		for i in range(len(matches)):
			aligned.append( disassembly[i][offset + matches[i].offset ])

		# Print this
		print '<tr>'
		left = True
		for instruction in aligned:
			print '<td>'
			if left:
				print '%s</td><td>' % instruction[2]
				
			# Opcode/operands
			if len(instruction) == 3:
				print '<b>%s</b> %s' % ( \
					instruction[0], instruction[1] )
			# Opcode/operands/label
			elif len(instruction) == 4:
					print '<em>%s</em> <b>%s</b> %s' % ( \
					instruction[3],
					instruction[0], instruction[1] )
		
			if left:
				left = False
			else:
				print '</td><td>%s' % instruction[2]
			print '</td>'
		print '</tr>'

	print '</table>'
	
def display_matches(form):
	import matchoutput
	import os.path

	print_header('Display query - %s - Matches' % form['file'].value)

	f = open(os.path.join(work_dir, form['file'].value) )

	(matches, idxfiles) = matchoutput.bincompare_matches(f)

	f.close()

	print "<table>"
	print "<tr>"
	print "<td></td><td></td><td colspan=2>FileA</td><td colspan=2>FileB</td>"
	print "</tr><tr>"
	print "<td>Score</td><td>Len</td><td>Name</td><td>Offset</td><td>Name</td><td>Offset</td>"
	print "</tr>"

	scores = {}
	for match in matches:
		try:
			# Avoid duplications here; we're showing only matches
			#  that were a `fileA'...
			if matches[match].a:
				scores[matches[match].score].append(match)
			else:
				pass
		except KeyError:
			scores[matches[match].score] = [ match ]
	scorekeys = scores.keys()
	scorekeys.sort()
	scorekeys.reverse()

	for score in scorekeys:
		for matchkey in scores[score]:
			match = matches[matchkey]

			side_by_side_query = "?action=show_results&output=side_by_side&idxA=%s&startA=%d&lenA=%d&idxB=%s&startB=%d&lenB=%d&score=%d" % ( \
				match.entry.idx.name,
				match.offset + match.entry.start,
				match.len,
				match.targets[0].entry.idx.name,
				match.targets[0].offset + match.targets[0].entry.start,
				match.targets[0].len,
				match.score)

			print "<tr>"
			print "<td><a href='%s'>%d</a></td><td>%d</td>" % (side_by_side_query, match.score, match.len)
			print "<td>%s</td><td>%d</td><td>%s</td><td>%d</td>" % \
			   (match.entry.file, match.offset, \
			    match.targets[0].entry.file, match.targets[0].offset)
			print "</tr>"

	print "</table>"

def display_coverage(form):
	import matchoutput
	import os.path

	print_header('Display query - %s - Coverage' % form['file'].value)

	f = open(os.path.join(work_dir, form['file'].value) )

	(matches, idxfiles) = matchoutput.bincompare_matches(f)

	f.close()

	# We're going to do a series of coverage lists for each FileA

	# Find all of the FileA's present
	fileAs = []
	for match in matches:
		if matches[match].a and \
		   (not matches[match].entry in fileAs):
			fileAs.append(matches[match].entry)

	# Figure out what files are present
	files = []
	for idxfile in idxfiles.values():
		for file in idxfile.entry:
			files.append(file)
			
	# Iterate through each fileA
	for fileA in fileAs:
		print '<h2>%s - %s - %s</h2>' % (fileA.file, fileA.archive, fileA.distname)
		# Compute the similarities to other files
		sims = {} # Keyed by similarity, valued by a list of entries
		for file in files:
			# Compute the similarity
			a = matchoutput.coverage(fileA,file.filter(matches))
			b = matchoutput.coverage(file,fileA.filter(matches))
			c = a * b

			# Add this to the list
			try:
				sims[ c ].append(file)
			except KeyError:
				sims[ c ] = [ file ]
				

		print 'Match coverage: %g' % matchoutput.coverage(fileA,matches)
		# Sort this list
		sortsims = sims.keys()
		sortsims.sort()
		sortsims.reverse()

		# Print the table
		print '<table>'
		print '<tr><td>Sim</td><td>File</td><td>Archive</td><td>Distro</td></tr>'
		for s in sortsims:
			if s == 0:
				continue

			for entry in sims[s]:
				print '<tr><td>%g</td><td>%s</td><td>%s</td><td>%s</td></tr>' % \
				  (s, entry.file, entry.archive, entry.distname)

		print '</table>'
	

def display_list(form):
	import os
	
	filelist = os.listdir(work_dir)

	print_header('Display query - Available queries')

	print "<table>"

	for file in filelist:
		if not file.endswith('.out'):
			continue
		
		print '<tr><td><a href="?action=show_results&output=matches&file=%s">%s</a> <a href="?action=show_results&output=coverage&file=%s">*</a></td></tr>' % (file,file, file)

	print "</table>"	

def show_results(form):
	try:
		if form['output'].value == 'side_by_side':
			display_side_by_side(form)
		elif form['output'].value == 'matches':
			display_matches(form)
		elif form['output'].value == 'coverage':
			display_coverage(form)
		else:
			display_list(form)

	except KeyError:
		display_list(form)

# Server actions
##################################################
# This is a dictionary of things that the interface can currently perform
#  which must include a `home' action to be performed by default.  The
#  dictionary is indexed by a descriptive string and valued by a function
#  that expects a CGI form object as its only parameter.
server_actions = { 'home':home, \
		   'add_file':add_file, \
		   'run_query':run_query, \
		   'show_results':show_results }


def get_action(form):
	"""Given a CGI form object, figure out what should be done
	next.  This is mainly responsible for verifying valid requests."""
	if form.has_key('action'):
		cgi_action = form['action'].value.strip()
		if server_actions.has_key(cgi_action):
			return cgi_action
	
	# Nothing else worked, default to showing the home
	return 'home'


# Main interface
##################################################
if __name__ == "__main__":
	print 'Content-type: text/html\n\n',

	form = cgi.FieldStorage() 
	action = get_action(form)
	server_actions[action](form)

	print_footer()
