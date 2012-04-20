%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(0)")}

Summary: A firewall daemon with D-BUS interface providing a dynamic firewall
Name: firewalld
Version: 0.2.5
Release: 1%{?dist}
URL: http://fedorahosted.org/firewalld
License: GPLv2+
ExclusiveOS: Linux
Group: System Environment/Base
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildArch: noarch
Source0: https://fedorahosted.org/released/firewalld/%{name}-%{version}.tar.bz2
BuildRequires: desktop-file-utils
BuildRequires: gettext
BuildRequires: intltool
# glib2-devel is needed for gsettings.m4
BuildRequires: glib2, glib2-devel
BuildRequires: systemd-units
Requires: dbus-python
Requires: python-slip-dbus >= 0.2.7
Requires: iptables, ebtables
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(post): systemd-sysv
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

%description
firewalld is a firewall service daemon that provides a dynamic customizable 
firewall with a D-BUS interface.

%package -n firewall-applet
Summary: Firewall panel applet
Group: System Environment/Base
Requires: %{name} = %{version}-%{release}
#Requires: firewall-config = %{version}-%{release}
Requires: hicolor-icon-theme
Requires: gtk3
Requires: pygobject3

%description -n firewall-applet
The firewall panel applet provides a status information of firewalld and also 
the firewall settings.

#%package -n firewall-config
#Summary: Firewall configuration application
#Group: System Environment/Base
#Requires: %{name} = %{version}-%{release}
#Requires: hicolor-icon-theme
#Requires: pygtk2
#Requires: pygtk2-libglade
#Requires: gtk2 >= 2.6
#
#%description -n firewall-config
#The firewall configuration application provides an configuration interface for 
#firewalld.

%prep
%setup -q

%build
./autogen.sh
%configure --with-systemd-unitdir=%{_unitdir}

%install
rm -rf %{buildroot}

make install DESTDIR=%{buildroot}

desktop-file-install --delete-original \
  --dir %{buildroot}%{_datadir}/applications \
  %{buildroot}%{_datadir}/applications/firewall-applet.desktop
#desktop-file-install --delete-original \
#  --dir %{buildroot}%{_datadir}/applications \
#  %{buildroot}%{_datadir}/applications/firewall-config.desktop

%find_lang %{name} --all-name

%clean
rm -rf %{buildroot}

%post
if [ $1 -eq 1 ] ; then # Initial installation
   /bin/systemctl daemon-reload >/dev/null 2>&1 || :
   /bin/systemctl enable firewalld.service >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ]; then # Package removal, not upgrade
   /bin/systemctl --no-reload disable firewalld.service > /dev/null 2>&1 || :
   /bin/systemctl stop firewalld.service > /dev/null 2>&1 || :
fi

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then # Package upgrade, not uninstall
   /bin/systemctl try-restart firewalld.service >/dev/null 2>&1 || :
fi

%triggerun -- firewalld < 0.1.3-3
# Save the current service runlevel info
# User must manually run systemd-sysv-convert --apply firewalld
# to migrate them to systemd targets
/usr/bin/systemd-sysv-convert --save firewalld >/dev/null 2>&1 ||:

# Run these because the SysV package being removed won't do them
/sbin/chkconfig --del firewalld >/dev/null 2>&1 || :
/bin/systemctl try-restart firewalld.service >/dev/null 2>&1 || :

%post -n firewall-applet
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
  gtk-update-icon-cache -q %{_datadir}/icons/hicolor
fi

%postun -n firewall-applet
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
  gtk-update-icon-cache -q %{_datadir}/icons/hicolor
fi
if [ $1 -eq 0 ] ; then
  /usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :
fi

%posttrans -n firewall-applet
/usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :


%files -f %{name}.lang
%defattr(-,root,root)
%doc COPYING
%{_sbindir}/firewalld
%{_bindir}/firewall-cmd
%defattr(0640,root,root)
%attr(0750,root,root) %dir %{_prefix}/lib/firewalld
%attr(0750,root,root) %dir %{_prefix}/lib/firewalld/icmptypes
%attr(0750,root,root) %dir %{_prefix}/lib/firewalld/services
%attr(0750,root,root) %dir %{_prefix}/lib/firewalld/zones
%{_prefix}/lib/firewalld/icmptypes/*.xml
%{_prefix}/lib/firewalld/services/*.xml
%{_prefix}/lib/firewalld/zones/*.xml
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld
%config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/icmptypes
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/services
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/zones
%defattr(0644,root,root)
%config(noreplace) %{_sysconfdir}/sysconfig/firewalld
#%attr(0755,root,root) %{_initrddir}/firewalld
%{_unitdir}/firewalld.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/FirewallD.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy
%attr(0755,root,root) %dir %{python_sitelib}/firewall
%attr(0755,root,root) %dir %{python_sitelib}/firewall/config
%attr(0755,root,root) %dir %{python_sitelib}/firewall/core
%attr(0755,root,root) %dir %{python_sitelib}/firewall/core/io
%attr(0755,root,root) %dir %{python_sitelib}/firewall/server
%{python_sitelib}/firewall/*.py*
%{python_sitelib}/firewall/config/*.py*
%{python_sitelib}/firewall/core/*.py*
%{python_sitelib}/firewall/core/io/*.py*
%{python_sitelib}/firewall/server/*.py*
%{_mandir}/man1/firewall*.1*
%{_mandir}/man5/firewall*.5*

%files -n firewall-applet
%defattr(-,root,root)
%{_bindir}/firewall-applet
%defattr(0644,root,root)
%{_datadir}/applications/firewall-applet.desktop
%{_datadir}/icons/hicolor/*/apps/firewall-applet*.*
%{_datadir}/glib-2.0/schemas/org.fedoraproject.FirewallApplet.gschema.xml

#%files -n firewall-config
#%defattr(-,root,root)
#%{_bindir}/firewall-config
#%defattr(0644,root,root)
#%{_datadir}/firewalld/firewall-config.glade
#%{_datadir}/applications/firewall-config.desktop
#%{_datadir}/icons/hicolor/*/apps/firewall-config*.*

%changelog
* Fri Apr 20 2012 Thomas Woerner <twoerner@redhat.com> 0.2.5-1
- Fixed traceback in firewall-cmd for failed or canceled authorization, 
  return proper error codes, new error codes NOT_RUNNING and NOT_AUTHORIZED
- Enhanced firewalld service file (RHBZ#806868) and (RHBZ#811240)
- Fixed duplicates in zone after reload, enabled timed settings after reload
- Removed conntrack --ctstate INVALID check from default ruleset, because it
  results in ICMP problems (RHBZ#806017).
- Update interfaces in default zone after reload (rhbz#804814)
- New man pages for firewalld(1), firewalld.conf(5), firewalld.icmptype(5),
  firewalld.service(5) and firewalld.zone(5), updated firewall-cmd man page
  (RHBZ#811257)
- Fixed firewall-cmd help output
- Fixed missing icon for firewall-applet (RHBZ#808759)
- Added root user check for firewalld (RHBZ#767654)
- Fixed requirements of firewall-applet sub package (RHBZ#808746)
- Update interfaces in default zone after changing of default zone (RHBZ#804814)
- Start firewalld before NetworkManager (RHBZ#811240)
- Add Type=dbus and BusName to service file (RHBZ#811240)

* Fri Mar 16 2012 Thomas Woerner <twoerner@redhat.com> 0.2.4-1
- fixed firewalld.conf save exception if no temporary file can be written to 
  /etc/firewalld/

* Thu Mar 15 2012 Thomas Woerner <twoerner@redhat.com> 0.2.3-1
- firewall-cmd: several changes and fixes
- code cleanup
- fixed icmp protocol used for ipv6 (rhbz#801182)
- added and fixed some comments
- properly restore zone settings, timeout is always set, check for 0
- some FirewallError exceptions were actually not raised
- do not REJECT in each zone
- removeInterface() don't require zone
- new tests in firewall-test script
- dbus_to_python() was ignoring certain values
- added functions for the direct interface: chains, rules, passthrough
- fixed inconsistent data after reload
- some fixes for the direct interface: priority positions are bound to ipv,
  table and chain
- added support for direct interface in firewall-cmd:
- added isImmutable(zone) to zone D-Bus interface
- renamed policy file
- enhancements for error messages, enables output for direct.passthrough
- added allow_any to firewald policies, using at leas auth_admin for policies
- replaced ENABLE_FAILED, DISABLE_FAILED, ADD_FAILED and REMOVE_FAILED by
  COMMAND_FAILED, resorted error codes
- new firewalld configuration setting CleanupOnExit
- enabled polkit again, found a fix for property problem with slip.dbus.service
- added dhcpv6-client to 'public' (the default) and to 'internal' zones.
- fixed missing settings form zone config files in
  "firewall-cmd --list=all --zone=<zone>" call
- added list functions for services and icmptypes, added --list=services and
  --list=icmptypes to firewall-cmd

* Tue Mar  6 2012 Thomas Woerner <twoerner@redhat.com> 0.2.2-1
- enabled dhcpv6-client service for zones home and work
- new dhcpv6-client service
- firewall-cmd: query mode returns reversed values
- new zone.changeZone(zone, interface)
- moved zones, services and icmptypes to /usr/lib/firewalld, can be overloaded
  by files in /etc/firewalld (no overload of immutable zones block, drop,
  trusted)
- reset MinimalMark in firewalld.cnf to default value
- fixed service destination (addresses not used)
- fix xmlplus to be compatible with the python xml sax parser and python 3
  by adding __contains__ to xml.sax.xmlreader.AttributesImpl
- use icon and glib related post, postun and posttrans scriptes for firewall
- firewall-cmd: fix typo in state
- firewall-cmd: fix usage()
- firewall-cmd: fix interface action description in usage()
- client.py: fix definition of queryInterface()
- client.py: fix typo in getInterfaces()
- firewalld.service: do not fork
- firewall-cmd: fix bug in --list=port and --port action help message
- firewall-cmd: fix bug in --list=service

* Mon Mar  5 2012 Thomas Woerner <twoerner@redhat.com>
- moved zones, services and icmptypes to /usr/lib/firewalld, can be overloaded
  by files in /etc/firewalld (no overload of immutable zones block, drop,
  trusted)

* Tue Feb 21 2012 Thomas Woerner <twoerner@redhat.com> 0.2.1-1
- added missing firewall.dbus_utils

* Tue Feb  7 2012 Thomas Woerner <twoerner@redhat.com> 0.2.0-2
- added glib2-devel to build requires, needed for gsettings.m4
- added --with-system-unitdir arg to fix installaiton of system file
- added glib-compile-schemas calls for postun and posttrans
- added EXTRA_DIST file lists

* Mon Feb  6 2012 Thomas Woerner <twoerner@redhat.com> 0.2.0-1
- version 0.2.0 with new FirewallD1 D-BUS interface
- supports zones with a default zone
- new direct interface as a replacement of the partial virt interface with 
  additional passthrough functionality
- dropped custom rules, use direct interface instead
- dropped trusted interface funcionality, use trusted zone instead
- using zone, service and icmptype configuration files
- not using any system-config-firewall parts anymore

* Mon Feb 14 2011 Thomas Woerner <twoerner@redhat.com> 0.1.3-1
- new version 0.1.3
- restore all firewall features for reload: panic and virt rules and chains
- string fixes for firewall-cmd man page (by Jiri Popelka)
- fixed firewall-cmd port list (by Jiri Popelka)
- added firewall dbus client connect check to firewall-cmd (by Jiri Popelka)
- translation updates: de, es, gu, it, ja, kn, ml, nl, or, pa, pl, ru, ta,
                       uk, zh_CN

* Mon Jan  3 2011 Thomas Woerner <twoerner@redhat.com> 0.1.2-1
- fixed package according to package review (rhbz#665395):
  - non executable scripts: dropped shebang
  - using newer GPL license file
  - made /etc/dbus-1/system.d/FirewallD.conf config(noreplace)
  - added requires(post) and (pre) for chkconfig

* Mon Jan  3 2011 Thomas Woerner <twoerner@redhat.com> 0.1.1-1
- new version 0.1.1
- fixed source path in POTFILES*
- added missing firewall_config.py.in
- added misssing space for spec_ver line
- using firewall_config.VARLOGFILE
- added date to logging output
- also log fatal and error logs to stderr and firewall_config.VARLOGFILE
- make log message for active_firewalld fatal

* Mon Dec 20 2010 Thomas Woerner <twoerner@redhat.com> 0.1-1
- initial package (proof of concept implementation)
