# User-configuration
#-----------------------

# The location from which CGI files can be executed
cgi-bin = ~/public_html/cgi-bin

# The location where the binblast executable should be installed
install-bin = /usr/local/bin

# The location of the python interpreter (used for fix-python)
python-bin = /usr/bin/python
#-----------------------
# User-configuration ends

# All of the files associated with the CGI interface that need to be moved
cgi-files = binblast_html.cgi matchoutput.py mklib.py objdumputil.py

install: binblast_html bincompare-install
	echo $<
	touch install

bincompare: bincompare.c
	$(CC) -o $@ $<
	
bincompare-install: bincompare
	install -m 555 $< $(install-bin)/$<	
	touch bincompare-install

$(cgi-bin)/%: %
	install -m 555 $< $@ 
	
binblast_html: $(cgi-files:%=${cgi-bin}/%)
	echo $<
	touch binblast_html

fix-python: 
	sed -e "s/#\!.*/#\!${subst /,\/,${python-bin}}/" --in-place *.py *.cgi
