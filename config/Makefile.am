sconfdir = $(sysconfdir)/firewalld
prefixlibdir = ${prefix}/lib/firewalld
dist_sconf_DATA = firewalld.conf lockdown-whitelist.xml

desktop_FILES = firewall-applet.desktop.in firewall-config.desktop.in
desktopdir = $(datadir)/applications
desktop_DATA = $(desktop_FILES:.in=)

polkit1_action_FILES = org.fedoraproject.FirewallD1.policy.in
polkit1_actiondir = $(datadir)/polkit-1/actions
polkit1_action_DATA = $(polkit1_action_FILES:.in=)

dbus_policydir = $(sysconfdir)/dbus-1/system.d
dist_dbus_policy_DATA = FirewallD.conf

gsettings_in_file = org.fedoraproject.FirewallApplet.gschema.xml.in
gsettings_SCHEMAS = $(gsettings_in_file:.xml.in=.xml)

BUILT_SOURCES = \
	$(desktop_DATA) \
	$(polkit1_action_DATA) \
	$(gsettings_SCHEMAS) \
	firewalld.service

@INTLTOOL_DESKTOP_RULE@
@INTLTOOL_POLICY_RULE@
@INTLTOOL_XML_NOMERGE_RULE@
@GSETTINGS_RULES@

all: $(desktop_DATA) $(polkit1_action_DATA) $(gsettings_SCHEMAS)

CLEANFILES = *~ *\# .\#* firewalld.service

DISTCLEANFILES = \
	$(desktop_DATA) \
	$(polkit1_action_DATA) \
	$(gsettings_SCHEMAS)

EXTRA_DIST = \
	$(desktop_FILES) \
	$(polkit1_action_FILES) \
	$(gsettings_in_file) \
	icmptypes \
	services \
	zones \
	firewalld.init \
	firewalld.service.in \
	firewalld.sysconfig

INSTALL_TARGETS = install-config install-sysconfig
UNINSTALL_TARGETS = uninstall-config uninstall-sysconfig
if USE_SYSTEMD
INSTALL_TARGETS += install-service
UNINSTALL_TARGETS += uninstall-service
else
INSTALL_TARGETS += install-init
UNINSTALL_TARGETS += uninstall-init
endif

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g'

firewalld.service: firewalld.service.in
	$(edit) $< >$@

install-sysconfig:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/firewalld.sysconfig $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/firewalld
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

install-init: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) $(srcdir)/firewalld.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld

uninstall-init: uninstall-sysconfig
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld
	rmdir $(DESTDIR)$(sysconfdir)/rc.d/init.d || :

install-service: install-sysconfig
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNITDIR)
	$(INSTALL_DATA) firewalld.service $(DESTDIR)$(SYSTEMD_UNITDIR)/firewalld.service

uninstall-service: uninstall-sysconfig
	rm -f $(DESTDIR)$(SYSTEMD_UNITDIR)/firewalld.service
	rmdir $(DESTDIR)$(SYSTEMD_UNITDIR) || :

install-config:
	$(MKDIR_P) $(DESTDIR)$(sconfdir)
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/icmptypes
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/services
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/zones
	$(MKDIR_P) $(DESTDIR)$(prefixlibdir)
	cp -r icmptypes $(DESTDIR)$(prefixlibdir)
	cp -r services $(DESTDIR)$(prefixlibdir)
	cp -r zones $(DESTDIR)$(prefixlibdir)

uninstall-config:
	rmdir $(DESTDIR)$(sconfdir)/icmptypes
	rmdir $(DESTDIR)$(sconfdir)/services
	rmdir $(DESTDIR)$(sconfdir)/zones
	rm -f $(DESTDIR)$(prefixlibdir)/icmptypes/*
	rmdir $(DESTDIR)$(prefixlibdir)/icmptypes
	rm -f $(DESTDIR)$(prefixlibdir)/services/*
	rmdir $(DESTDIR)$(prefixlibdir)/services
	rm -f $(DESTDIR)$(prefixlibdir)/zones/*
	rmdir $(DESTDIR)$(prefixlibdir)/zones

install-data-local: $(INSTALL_TARGETS)

uninstall-local: $(UNINSTALL_TARGETS)
