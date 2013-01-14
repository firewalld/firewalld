SUBDIRS = icons

dist_bin_SCRIPTS = firewall-applet firewall-cmd firewall-offline-cmd firewall-config
dist_sbin_SCRIPTS = firewalld

gladedir = $(pkgdatadir)
dist_glade_DATA = firewall-config.glade

gtkextradir = $(pkgdatadir)
dist_gtkextra_DATA = gtk3_chooserbutton.py

nobase_dist_python_DATA = \
	$(wildcard firewall/*.py) \
	$(wildcard firewall/*/*.py) \
	$(wildcard firewall/*/*/*.py)

EXTRA_DIST = \
	firewall/config/__init__.py.in

CLEANFILES = *~ *\# .\#* *.py?

install-data-local:
	@echo "Fixing python shebang"
	@list='$(bin_SCRIPTS)'; \
	for p in $$list; do \
	  echo $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(bindir)/$$p"; \
	  $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(bindir)/$$p"; \
	done
	@list='$(sbin_SCRIPTS)'; \
	for p in $$list; do \
	  echo $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(sbindir)/$$p"; \
	  $(top_srcdir)/fix_python_shebang.sh "$(DESTDIR)$(sbindir)/$$p"; \
	done
