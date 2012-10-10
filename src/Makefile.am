bin_SCRIPTS = firewall-applet firewall-cmd firewall-offline-cmd firewall-config
sbin_SCRIPTS = firewalld

gladedir = $(pkgdatadir)
glade_PYTHON = firewall-config.glade

gtkextradir = $(pkgdatadir)
gtkextra_PYTHON = gtk3_chooserbutton.py

icondir = $(datadir)/icons/hicolor
iconFILES = icons/*/apps/*

EXTRA_DIST = $(bin_SCRIPTS) \
	$(sbin_SCRIPTS) \
	firewall/*.py \
	firewall/*/*.py \
	firewall/*/*.py.in \
	firewall/*/*/*.py \
	$(iconFILES)

CLEANFILES = *~ *\# .\#* *.py?

install-data-local:
	install -d $(DESTDIR)/$(pythondir)
	cp -fpR firewall $(DESTDIR)/$(pythondir)
	find $(DESTDIR)/$(pythondir) -name "*.in" -exec rm {} \;

	install -d $(DESTDIR)/$(icondir)
	cp -fpR icons/* $(DESTDIR)/$(icondir)
