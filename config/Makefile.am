sconfdir = $(sysconfdir)/firewalld
prefixlibdir = ${prefix}/lib/firewalld
dist_sconf_DATA = firewalld.conf lockdown-whitelist.xml

desktop_FILES = firewall-config.desktop.in
desktopdir = $(datadir)/applications
desktop_DATA = $(desktop_FILES:.in=)

appdata_FILES = firewall-config.appdata.xml.in
appdatadir = $(datadir)/appdata/
appdata_DATA = $(appdata_FILES:.in=)

applet_desktop_FILES = firewall-applet.desktop.in
applet_desktopdir = $(sysconfdir)/xdg/autostart
applet_desktop_DATA = $(applet_desktop_FILES:.in=)

confdir = $(sysconfdir)/firewall
dist_conf_DATA = applet.conf

polkit1_action_FILES = org.fedoraproject.FirewallD1.server.policy.in \
                       org.fedoraproject.FirewallD1.desktop.policy.in
polkit1_actiondir = $(datadir)/polkit-1/actions
polkit1_action_DATA = $(polkit1_action_FILES:.in=)

dbus_policydir = $(sysconfdir)/dbus-1/system.d
dist_dbus_policy_DATA = FirewallD.conf

gsettings_in_file = org.fedoraproject.FirewallConfig.gschema.xml.in
gsettings_SCHEMAS = $(gsettings_in_file:.xml.in=.xml)

xmlschemadir = $(prefixlibdir)/xmlschema
dist_xmlschema_DATA = \
	xmlschema/icmptype.xsd \
	xmlschema/ipset.xsd \
	xmlschema/service.xsd \
	xmlschema/zone.xsd
dist_xmlschema_SCRIPTS = xmlschema/check.sh

BUILT_SOURCES = \
	$(desktop_DATA) \
	$(appdata_DATA) \
	$(applet_desktop_DATA) \
	$(polkit1_action_DATA) \
	$(gsettings_SCHEMAS) \
	firewalld.service

@INTLTOOL_DESKTOP_RULE@
@INTLTOOL_POLICY_RULE@
@INTLTOOL_XML_NOMERGE_RULE@
@GSETTINGS_RULES@

all: $(desktop_DATA) $(appdata_DATA) $(applet_desktop_DATA) $(polkit1_action_DATA) $(gsettings_SCHEMAS)

CLEANFILES = *~ *\# .\#* firewalld.service

DISTCLEANFILES = \
	$(desktop_DATA) \
	$(appdata_DATA) \
	$(applet_desktop_DATA) \
	$(polkit1_action_DATA) \
	$(gsettings_SCHEMAS)

EXTRA_DIST = \
	$(desktop_FILES) \
	$(appdata_FILES) \
	$(applet_desktop_FILES) \
	$(polkit1_action_FILES) \
	$(gsettings_in_file) \
	icmptypes/destination-unreachable.xml \
	icmptypes/echo-reply.xml \
	icmptypes/echo-request.xml \
	icmptypes/parameter-problem.xml \
	icmptypes/redirect.xml \
	icmptypes/router-advertisement.xml \
	icmptypes/router-solicitation.xml \
	icmptypes/source-quench.xml \
	icmptypes/time-exceeded.xml \
	icmptypes/timestamp-reply.xml \
	icmptypes/timestamp-request.xml \
	ipsets/README \
	services/amanda-client.xml \
	services/amanda-k5-client.xml \
	services/bacula-client.xml \
	services/bacula.xml \
	services/ceph-mon.xml \
	services/ceph.xml \
	services/dhcp.xml \
	services/dhcpv6-client.xml \
	services/dhcpv6.xml \
	services/dns.xml \
	services/docker-registry.xml \
	services/dropbox-lansync.xml \
	services/freeipa-ldap.xml \
	services/freeipa-ldaps.xml \
	services/freeipa-replication.xml \
	services/ftp.xml \
	services/high-availability.xml \
	services/http.xml \
	services/https.xml \
	services/imap.xml \
	services/imaps.xml \
	services/ipp-client.xml \
	services/ipp.xml \
	services/ipsec.xml \
	services/iscsi-target.xml \
	services/kadmin.xml \
	services/kerberos.xml \
	services/kpasswd.xml \
	services/ldap.xml \
	services/ldaps.xml \
	services/libvirt-tls.xml \
	services/libvirt.xml \
	services/mdns.xml \
	services/mosh.xml \
	services/mountd.xml \
	services/ms-wbt.xml \
	services/mysql.xml \
	services/nfs.xml \
	services/ntp.xml \
	services/openvpn.xml \
	services/pmcd.xml \
	services/pmproxy.xml \
	services/pmwebapi.xml \
	services/pmwebapis.xml \
	services/pop3.xml \
	services/pop3s.xml \
	services/postgresql.xml \
	services/privoxy.xml \
	services/proxy-dhcp.xml \
	services/ptp.xml \
	services/pulseaudio.xml \
	services/puppetmaster.xml \
	services/radius.xml \
	services/rpc-bind.xml \
	services/rsyncd.xml \
	services/samba-client.xml \
	services/samba.xml \
	services/sane.xml \
	services/smtp.xml \
	services/smtps.xml \
	services/snmp.xml \
	services/snmptrap.xml \
	services/squid.xml \
	services/ssh.xml \
	services/synergy.xml \
	services/syslog-tls.xml \
	services/syslog.xml \
	services/telnet.xml \
	services/tftp-client.xml \
	services/tftp.xml \
	services/tinc.xml \
	services/tor-socks.xml \
	services/transmission-client.xml \
	services/vdsm.xml \
	services/vnc-server.xml \
	services/wbem-https.xml \
	services/xmpp-bosh.xml \
	services/xmpp-client.xml \
	services/xmpp-local.xml \
	services/xmpp-server.xml \
	zones/block.xml \
	zones/dmz.xml \
	zones/drop.xml \
	zones/external.xml \
	zones/home.xml \
	zones/internal.xml \
	zones/public.xml \
	zones/trusted.xml \
	zones/work.xml \
	$(dist_xmlschema_DATA) \
	firewalld.init \
	firewalld.service.in \
	firewalld.sysconfig \
	macros.firewalld

INSTALL_TARGETS = install-config
UNINSTALL_TARGETS = uninstall-config

if USE_SYSTEMD
INSTALL_TARGETS += install-service
UNINSTALL_TARGETS += uninstall-service
else
INSTALL_TARGETS += install-init
UNINSTALL_TARGETS += uninstall-init
endif

if INSTALL_SYSCONFIG
INSTALL_TARGETS += install-sysconfig
UNINSTALL_TARGETS += uninstall-sysconfig
endif

if INSTALL_RPMMACROS
INSTALL_TARGETS += install-rpmmacros
UNINSTALL_TARGETS += uninstall-rpmmacros
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

install-rpmmacros:
	$(MKDIR_P) $(DESTDIR)$(prefix)/lib/rpm/macros.d
	$(INSTALL_DATA) $(srcdir)/macros.firewalld $(DESTDIR)$(prefix)/lib/rpm/macros.d

uninstall-rpmmacros:
	rm -f $(DESTDIR)$(prefix)/lib/rpm/macros.d/macros.firewalld
	rmdir $(DESTDIR)$(prefix)/lib/rpm/macros.d || :

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
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/ipsets
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/services
	$(MKDIR_P) $(DESTDIR)$(sconfdir)/zones
	$(MKDIR_P) $(DESTDIR)$(prefixlibdir)
	cp -r icmptypes $(DESTDIR)$(prefixlibdir)
	cp -r ipsets $(DESTDIR)$(prefixlibdir)
	cp -r services $(DESTDIR)$(prefixlibdir)
	cp -r zones $(DESTDIR)$(prefixlibdir)

uninstall-config:
	rmdir $(DESTDIR)$(sconfdir)/icmptypes
	rmdir $(DESTDIR)$(sconfdir)/ipsets
	rmdir $(DESTDIR)$(sconfdir)/services
	rmdir $(DESTDIR)$(sconfdir)/zones
	rm -f $(DESTDIR)$(prefixlibdir)/icmptypes/*
	rmdir $(DESTDIR)$(prefixlibdir)/icmptypes
	rm -f $(DESTDIR)$(prefixlibdir)/ipsets/*
	rmdir $(DESTDIR)$(prefixlibdir)/ipsets
	rm -f $(DESTDIR)$(prefixlibdir)/services/*
	rmdir $(DESTDIR)$(prefixlibdir)/services
	rm -f $(DESTDIR)$(prefixlibdir)/zones/*
	rmdir $(DESTDIR)$(prefixlibdir)/zones

install-data-local: $(INSTALL_TARGETS)

uninstall-local: $(UNINSTALL_TARGETS)

install-data-hook:
	cd $(DESTDIR)$(polkit1_actiondir) && \
		rm -f org.fedoraproject.FirewallD1.policy && \
		$(LN_S) org.fedoraproject.FirewallD1.server.policy org.fedoraproject.FirewallD1.policy
