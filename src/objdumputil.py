#!/usr/bin/python
# Program:    objdumputil.py
# Programmer: Scott Miller
# Function:   A wrapper for processing files using objdump

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

class Objdump:
	"""A wrapper for processing files using objdump.  The
	objdump binary and its appropriate arguments must be
	set (although the default values may work) before 
	invoking objdump()"""
	
	objdumpBin = "/usr/bin/objdump"
	objdumpArgs = "-Mintel -d"
	
	def objdump(self,fileName):
		"""Returns the filestream from invoking
		objdump on fileName.  If fileName is not
		a binary format recognized by objdump, this
		will be an empty stream.
		"""

		import os

		(child_stdin, child_stdout, child_stderr) =  \
		          os.popen3(self.objdumpBin + " " + \
			  self.objdumpArgs + " " + \
		          fileName,   
			  4096) # Include a 4K bufsize to address
			        #  larger binaries
	
		return child_stdout
	
	def disassemble(self,fileName,returnbytes=False):
		"""Returns a list of (opcode, operand, [label]) tuples as
		disassembled from fileName.  If fileName is not
		a binary format recognized by objdump, an empty
		list [] is returned."""
		import re

		# Start disassembly
		instructions = []
		bytes = []
		label = ''
		disassembly = self.objdump(fileName)

		# Work with this line-by-line
		#  This is effectively a do-while loop
		line = disassembly.readline()
		while line:
			# Reduce the input into fields
			field = line.split('\t')
			
			# If there was only one field, perhaps this is a label
			if len(field) == 1:
				# Labels will be in the form 
				# offset <label>:
				parts = re.match('[0-9a-fA-F]+\W*<(.*)>:',field[0])
				try:
					label = parts.group(1)
				except AttributeError:
					pass
					
			# The opcode is in the 3rd field [0,1,2,...]
			if len(field) > 2:
				# Isolate the opcode, everything up to the
				#  first non-alphanumeric character
				# This allows for arbitrary-length instructions
				# Note: (bad), objdump's default output if
				# it wasn't able to disassemble the memory
				# space, will be entered as an empty 
				# opcode '' and the operands '(bad)'
				import re

				parts  = re.match('\W*(\w*).*', field[0])
				offset  = parts.group(1)

				parts = re.match('\W*(\w*)(.*)', field[2])
				opcode = parts.group(1)
				operands = parts.group(2).strip()

				# If there was a label, add it and then remove
				#  it
				# REMOVE NOPS!
				if opcode == 'nop':
					bytes[-1] += field[1]
					pass
				elif label == '':
					bytes.append(field[1])
					instructions.append([opcode, operands, offset])
				else:
					bytes.append(field[1])
					instructions.append([opcode, operands, offset, \
							     label])
					label = ''
				
			# Any more?
			line = disassembly.readline()
		if not returnbytes:
			return instructions
		else:
			return [instructions, bytes]

