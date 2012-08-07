bin_SCRIPTS = firewall-applet firewall-cmd firewall-convert-scfw-config
#firewall-config
sbin_SCRIPTS = firewalld

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
