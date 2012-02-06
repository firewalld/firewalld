%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(0)")}

Summary: A firewall daemon with D-BUS interface providing a dynamic firewall
Name: firewalld
Version: 0.2.0
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
BuildRequires: glib2
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
Requires: pygtk2
Requires: pygtk2-libglade
Requires: gtk2 >= 2.6

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
%configure

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
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
  gtk-update-icon-cache -q %{_datadir}/icons/hicolor
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
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
  gtk-update-icon-cache -q %{_datadir}/icons/hicolor
fi

%triggerun -- firewalld < 0.1.3-3
# Save the current service runlevel info
# User must manually run systemd-sysv-convert --apply firewalld
# to migrate them to systemd targets
/usr/bin/systemd-sysv-convert --save firewalld >/dev/null 2>&1 ||:

# Run these because the SysV package being removed won't do them
/sbin/chkconfig --del firewalld >/dev/null 2>&1 || :
/bin/systemctl try-restart firewalld.service >/dev/null 2>&1 || :


%files -f %{name}.lang
%defattr(-,root,root)
%doc COPYING
%{_sbindir}/firewalld
%{_bindir}/firewall-cmd
%defattr(0640,root,root)
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/icmptypes
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/services
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/zones
%{_sysconfdir}/firewalld/icmptypes/*.xml
%{_sysconfdir}/firewalld/services/*.xml
%{_sysconfdir}/firewalld/zones/*.xml
%config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%defattr(0644,root,root)
%config(noreplace) %{_sysconfdir}/sysconfig/firewalld
#%attr(0755,root,root) %{_initrddir}/firewalld
%{_unitdir}/firewalld.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/FirewallD.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD.policy
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
%{_mandir}/man1/firewall-cmd.1*

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
