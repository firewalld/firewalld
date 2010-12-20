sconfdir = $(sysconfdir)/firewalld
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

@INTLTOOL_DESKTOP_RULE@
@INTLTOOL_POLICY_RULE@

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
	firewalld.init \
	firewalld.sysconfig

install-init: firewalld.init firewalld.sysconfig
	mkdir -p $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) firewalld.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld
	mkdir -p $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL) firewalld.sysconfig $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

uninstall-init:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/firewalld
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/firewalld

install-data-local: install-init

uninstall-local: uninstall-init
