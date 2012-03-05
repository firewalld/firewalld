sconfdir = $(sysconfdir)/firewalld
prefixlibdir = ${prefix}/lib/firewalld
dist_sconf_DATA = firewalld.conf

desktop_FILES = firewall-applet.desktop.in
#firewall-config.desktop.in
desktopdir = $(datadir)/applications
dist_desktop_DATA = $(desktop_FILES:.in=)

polkit1_action_FILES = org.fedoraproject.FirewallD.policy.in
polkit1_actiondir = $(datadir)/polkit-1/actions
dist_polkit1_action_DATA = $(polkit1_action_FILES:.in=)

dbus_policydir = $(sysconfdir)/dbus-1/system.d
dist_dbus_policy_DATA = FirewallD.conf

gsettings_in_file = org.fedoraproject.FirewallApplet.gschema.xml.in
gsettings_SCHEMAS = $(gsettings_in_file:.xml.in=.xml)

@INTLTOOL_DESKTOP_RULE@
@INTLTOOL_POLICY_RULE@
@INTLTOOL_XML_NOMERGE_RULE@
@GSETTINGS_RULES@

all: $(dist_desktop_DATA) $(dist_polkit1_action_DATA)

CLEANFILES = *~ *\# .\#*

DISTCLEANFILES = \
	$(dist_desktop_DATA) \
	$(dist_polkit1_action_DATA)

EXTRA_DIST = \
	$(pam_FILES) \
	$(console_FILES) \
	$(desktop_FILES) \
	$(polkit1_action_FILES) \
	$(gsettings_in_file) \
	icmptypes/*.xml \
	services/*.xml \
	zones/*.xml \
	firewalld.init \
	firewalld.service \
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

install-sysconfig:
	mkdir -p $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL) firewalld.sysconfig $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

uninstall-sysconfig:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

install-init: firewalld.init firewalld.sysconfig
	mkdir -p $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) firewalld.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld

uninstall-init:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

install-service:
	mkdir -p $(DESTDIR)$(SYSTEMD_UNITDIR)
	$(INSTALL) firewalld.service $(DESTDIR)$(SYSTEMD_UNITDIR)

uninstall-service:
	rm -f $(DESTDIR)$(SYSTEMD_UNITDIR)/firewalld.service

install-config:
	mkdir -p $(DESTDIR)$(sconfdir)
	mkdir -p $(DESTDIR)$(sconfdir)/icmptypes
	mkdir -p $(DESTDIR)$(sconfdir)/services
	mkdir -p $(DESTDIR)$(sconfdir)/zones
	mkdir -p $(DESTDIR)$(prefixlibdir)
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
