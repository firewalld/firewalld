Summary: A firewall daemon with D-BUS interface providing a dynamic firewall
Name: firewalld
Version: 0.1
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
Requires: system-config-firewall-base >= 1.2.28
Requires: dbus-python
Requires: python-slip-dbus >= 0.2.7
Requires: iptables, ebtables

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
#	--dir %{buildroot}%{_datadir}/applications \
#	%{buildroot}%{_datadir}/applications/firewall-config.desktop

%find_lang %{name} --all-name

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add firewalld
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
  gtk-update-icon-cache -q %{_datadir}/icons/hicolor
fi

%preun
if [ $1 = 0 ]; then
        %{_initrddir}/firewalld stop >/dev/null 2>&1
        /sbin/chkconfig --del firewalld
fi
exit 0

%postun
touch --no-create %{_datadir}/icons/hicolor
if [ -x /usr/bin/gtk-update-icon-cache ]; then
  gtk-update-icon-cache -q %{_datadir}/icons/hicolor
fi


%files -f %{name}.lang
%defattr(-,root,root)
%doc COPYING
%{_sbindir}/firewalld
%{_bindir}/firewall-cmd
%defattr(0644,root,root)
%attr(0755,root,root) %dir %{_sysconfdir}/firewalld
%config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%config(noreplace) %{_sysconfdir}/sysconfig/firewalld
%attr(0755,root,root) %{_initrddir}/firewalld
%{_sysconfdir}/dbus-1/system.d/FirewallD.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD.policy
%attr(0755,root,root) %dir %{_datadir}/firewalld/
%{_datadir}/firewalld/*.py*
%{_mandir}/man1/firewall-cmd.1*

%files -n firewall-applet
%defattr(-,root,root)
%{_bindir}/firewall-applet
%defattr(0644,root,root)
%{_datadir}/applications/firewall-applet.desktop
%{_datadir}/icons/hicolor/*/apps/firewall-applet*.*

#%files -n firewall-config
#%defattr(-,root,root)
#%{_bindir}/firewall-config
#%defattr(0644,root,root)
#%{_datadir}/firewalld/firewall-config.glade
#%{_datadir}/applications/firewall-config.desktop
#%{_datadir}/icons/hicolor/*/apps/firewall-config*.*

%changelog
* Mon Dec 20 2010 Thomas Woerner <twoerner@redhat.com> 0.1-1
- initial package (proof of concept implementation)
