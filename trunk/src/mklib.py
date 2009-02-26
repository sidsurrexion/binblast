#!/usr/bin/python
# Program:    mklib.py
# Programmer: Scott Miller
# Function:   A utility to create the .dat and .idx files needed by
#              bincompare

# binBLAST suite of binary analysis tools
# Copyright (C) 2006 Scott Miller
# 
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

# When creating potentially huge uncompressed structures, do it here. 
mytempdir = "/home/hllywood/"

# The path to the alien binary, required to convert random
#  distribution files into .tar.gz
alienbin = "/usr/bin/alien"
# Archives supported by alien
alienarc = ["rpm","lsb","deb","pkg"]
# Other archives and their uncompression command.  Before this 
#  command, the archive will be copied into a temp directory,
#  the shell will cd into that temp directory, and then this
#  command will be executed
otherarc = { 'zip':'unzip', 'tgz':'tar -xzf ',
           'tar.gz':'tar -xzf', 'gz':'gzip -d' }
# The total listing of archives
archives = alienarc + otherarc.keys()

# The global database for storing information on the instruction frequencies
instructionDB = {}

# Need this to make temporary directories
from tempfile import mkdtemp

class MklibOpts:
	file = None
	distdir = None
	distname = None
	bin = False
	verbose = False
	database = True
	
def set_args():
	from optparse import OptionParser
	parser = OptionParser()

	parser.add_option("-i","--iso",
			  dest="file",
			  help="Use an ISO file as the distribution source",
			  metavar="FILE")
	parser.add_option("-d","--dir",
			  dest="distdir",
			  help="Use a directory tree as the distribution source",
			  metavar="DIR")
	parser.add_option("-n","--name",
			  dest="distname",
			  metavar="MY_LINUX_X.X",
			  help="A unique identifier for this distribution")
	parser.add_option("-b","--bin",
			  dest="bin",
			  action="store_true",
			  default=False,
			  help="Produce binary output, name.dat and name.idx") 
	parser.add_option("-v","--verbose",
			  dest="verbose",
			  action="store_true",
			  default=False,
			  help="Produce verbose status information")
	parser.add_option("-o","--no-db",
			  dest="database",
			  action="store_false",
			  default=True,
			  help="Do not produce the default database output, name.db")
			  
	
	parser.set_defaults(distname="unknown")

	(options,args) = parser.parse_args()

	return options

def remove_temp_path(path):
	"""Strips out any temporary path prefixes, i.e. 
	/tmp/tmp12751ha/this becomes /this"""
	import os.path

	# This expects an absolute path
	path = os.path.abspath(path)
	tmppath = os.path.abspath(mytempdir)
	this = path.split('/')
	that = tmppath.split('/')

	for x in that:
		if x == this[0]:
			this.pop(0)
		else:
			break

	# Put the root thing back in
	this.insert(0,'')

	# Keep removing parts from the beginning 
	#  that have 'tmp' in them
	# Note: If this is absolute (which it was made earlier),
	# this[0] will be '' (root)
	while 'tmp' in this[1]:
		unused = this.pop(1)
	
	# Put it back together
	this = '/'.join(this)
	return(this)

def compact_instruction(instruction):
	"""Reduce instruction, an [opcode,operands] list, into a 4-byte
	binary hash/truncation.  The result has:
	byte 0: top byte of md5 hash of the first two letters of the operand
	byte 1: top byte of md5 hash of the entire operand
	byte 2-3: md5hash of the operands"""
	import md5

	# Byte 0
	hash = md5.new()
	hash.update( (instruction[0])[0:2] )
	this =        (hash.digest())[0]

	# Byte 1
	hash = md5.new()
	hash.update( (instruction[0])[:] )
	this = this + (hash.digest())[0:1]

	# Bytes 2-3
	hash = md5.new()
	hash.update( (instruction[1])[:] )
	this = this + (hash.digest())[0:2]

	return(this)

def process_file(path,archive,distname,options):
	"Process a binary file, dissasembling it and then recording stats" 

	# For convenience, have an escaped path suitable for use in 
	#  shell environments
	escapedPath = path.replace(" ", "\\ ")
	escapedPath = escapedPath.replace("$", "\\$")

	# Don't bother with links, this can make processing /lib
	#  very lengthy and duplicatous (sic)
	import os.path
	if os.path.islink(path):
		return
	
	# Disassemble the file
	import objdumputil
	binaryFile = objdumputil.Objdump()
	instructions = binaryFile.disassemble(path)
	
	# Nothing came out, return now
	if len(instructions) == 0:
		return
	
	# Prepare to write binary output
	if options.bin:
		# Open the files
		dat = open(distname + ".dat","ab")
		idx = open(distname + ".idx","a")
		# Make sure that the dat file is at the end
		dat.seek(0,2)

		# Write the index entry
		idx.write("%ld,%s,%s,%s\n" % ( 
			dat.tell() / 4,            # Start location
			remove_temp_path(path),    # File name
			remove_temp_path(archive), # Archive
			distname) )                # Distribution name
		idx.close()

	# Add any useful information to the global instructionDB
	for instruction in instructions:
		try:
			instructionDB[ instruction[0] ] += 1
		except KeyError:
			instructionDB[ instruction[0] ] = 1

		# If we're writing the binary, compact and write
		if options.bin:
			dat.write( compact_instruction(instruction) )

	if options.bin:
		dat.write('\x00\x00\x00\x00')
		dat.close()

	if options.verbose:		
		print "+ process_file %s" % escapedPath
		print ">>> %d instructions" % len(instructions)

def unpack_archive(archive):
	"""Create a temporary directory and unpack archive to that
	directory.  If this is a package format, use alien to first
	convert it into a tar'd gzip'd archive that can be easily unpacked.
	Returns the temporary directory."""
	import os

	# Create a temporary directory
	tmpdir = mkdtemp(dir=mytempdir)

	# Is this a package to be processed by alien?
	parts = archive.split('.')
	if parts[-1] in alienarc:
		# Create a .tgz version of the package
		os.system('cp %s %s' % (archive, tmpdir))
		parts =  archive.split("/")
		archiveName = parts[-1]
		
		os.system('cd %s && %s -t %s/%s 2>/dev/null 1>/dev/null' % (tmpdir,alienbin,tmpdir,archiveName)) 
		parts = archiveName.split('.')
		parts[-1] = 'tgz'
		archive = tmpdir + '/' + '.'.join(parts)

		# Ocassionally, alien munges the extension
		os.system('mv %s/*.tgz %s' % (tmpdir, archive))
	else:
		# If this wasn't something for alien, move it
		#  to the tmpdir
		os.system('cp -u %s %s/.' % (archive,tmpdir))
		
	# Figure out how to uncompress this archive
	extension = archive.split('.')[-1]
	archiveName = archive.split("/")[-1]
	uncompress = otherarc[extension]
	os.system('cd %s && %s %s' % ( \
			tmpdir, # cd %s
			uncompress,archiveName # %s %s 
		))

	return(tmpdir)

def process_archive(archive, distname,options):
	""""Use alien to unpack an archive in a temp directory, then process 
	each binary file with process_file()"""
	import os
	
	def scanFunc(unused, dirname, files):
		
		# Traverse each file in the directory
		for filename in files:
			# Figure out the absolute path name
			path = os.path.join(dirname, filename)

			# Make sure the file still exists
			try:
				t = os.stat(path)
			except os.error:
				# This should only happy if the file
				#  was deleted between when the walk
				#  started and when we looked at it.
				# Keep the code stable by moving on
				continue

			# Process this file
			process_file(path,archive,distname,options)

	try:
		# Unpack the archive
		tmpdir = unpack_archive(archive)
		
		# Print out information, if requested
		if options.verbose:
			print "= process_archive(%s,%s) in %s" % \
				(archive, distname, tmpdir)

		# Process the directory
		os.path.walk(tmpdir,scanFunc,None)
	except:
		raise
	# Clean up
	if tmpdir:
		os.system('rm -rf %s' % tmpdir)
	
def scan_distdir(dir, distname,options):
	"""Walk through a distribution directory looking for archive files (but
	not binaries) and then invoke process_archive()"""
	import os.path

	print "Scanning %s in %s" % (distname, dir)

	def scanfunc(unused, dirname, files):
		import os
		
		# Traverse each file in the directory
		for filename in files:
			# Figure out the absolute path name
			path = os.path.join(dirname, filename)

			# Make sure the file still exists
			try:
				t = os.stat(path)
			except os.error:
				# This should only happy if the file
				#  was deleted between when the walk
				#  started and when we looked at it.
				# Keep the code stable by moving on
				continue

			# Figure out if this is an extension we should
			#  consider
			parts = filename.split('.')
			extension = parts[-1]

			if extension in archives:
				process_archive(path, distname,options)
	
	os.path.walk(dir,scanfunc,None)
	
def mount_isofile(isofile):
	"""Mount an ISO on a temporary directory and return that directory"""

	# Create a temporary directory
	mountdir = mkdtemp(dir=mytempdir)
	
	# Attempt to mount the iso in loopback to this directory
	try:
		import os
		os.system('mount -oloop %s %s' % (isofile, mountdir))
		print "%s mounted on %s" % (isofile, mountdir)
	except os.error:
		import sys
		print sys.exc_info()[0]
		rmdir(mountdir)
	
	return(mountdir)

def main():
	options = set_args()

	try:
		# If there is an iso file, mount it
		if options.file:
			options.distdir = mount_isofile(options.file)
			
		# Scan the distribution directory
		scan_distdir(options.distdir, options.distname, options)

	finally:
	# If there was an iso file, unmount it and remove the directory
		if options.file:
			try:
				import os
				import time
				os.system('umount -d %s' % options.distdir)

				# Umount is non-blocking
				time.sleep(1)
				os.rmdir(options.distdir)
			except os.error:
				import sys
				print sys.exc_info()[0]

		if options.database:
			import pickle
			dbsave = open(options.distname + '.db','w')
			pickle.dump(instructionDB,dbsave)

if __name__ == "__main__":
	main()
