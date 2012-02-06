bin_SCRIPTS = firewall-applet firewall-cmd
#firewall-config
sbin_SCRIPTS = firewalld

icondir = $(datadir)/icons/hicolor
iconFILES = icons/*/apps/*

EXTRA_DIST = $(bin_SCRIPTS) $(sbin_SCRIPTS) $(iconFILES)

CLEANFILES = *~ *\# .\#* *.py?

install-data-local:
	install -d $(DESTDIR)/$(pythondir)
	cp -fpR firewall $(DESTDIR)/$(pythondir)
	find $(DESTDIR)/$(pythondir) -name "*.in" -exec rm {} \;

	install -d $(DESTDIR)/$(icondir)
	cp -fpR icons/* $(DESTDIR)/$(icondir)
