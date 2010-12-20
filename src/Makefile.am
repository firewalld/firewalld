bin_SCRIPTS = firewall-applet firewall-cmd
#firewall-config
sbin_SCRIPTS = firewalld

#scfwdir = $(pkgdatadir)
#scfw_PYTHON = *.py convert-config

scfwindir = $(pkgdatadir)
scfwin_in_files = *.py.in
scfwin_PYTHON = $(scfwin_in_files:.in=)

#gladedir = $(pkgdatadir)
#glade_PYTHON = *.glade

icondir = $(datadir)/icons/hicolor
iconFILES = icons/*/apps/*

EXTRA_DIST = $(bin_SCRIPTS) $(sbin_SCRIPTS) $(iconFILES)

CLEANFILES = *~ *\# .\#* *.py?

install-data-local:
	install -d $(DESTDIR)/$(icondir)
	cp -fpR icons/* $(DESTDIR)/$(icondir)
