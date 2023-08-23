# SPEC file to build firewalld for testing. It aims to be the template for
# RHEL/Fedora.
#
# This spec file is not directly usable. Instead, it contains __PLACEHOLDERS__ that
# are adjusted by the accompanying "build.sh" script.

%global version __VERSION__
%global release_version __RELEASE_VERSION__
%global snapshot __SNAPSHOT__
%global git_sha __COMMIT__

%if "x%{?snapshot}" != "x"
%global snapshot_dot .%{snapshot}
%endif
%if "x%{?git_sha}" != "x"
%global git_sha_dot .%{git_sha}
%endif

%global snap %{?snapshot_dot}%{?git_sha_dot}

Summary: A firewall daemon with D-Bus interface providing a dynamic firewall
Name: firewalld
Version: %{version}
Release: %{release_version}%{?snap}%{?dist}
URL:     http://firewalld.org
License: GPLv2+
Source0: https://github.com/firewalld/firewalld/releases/download/v%{version}/firewalld-%{version}.tar.bz2
Source1: FedoraServer.xml
Source2: FedoraWorkstation.xml
Source3: org.fedoraproject.FirewallD1.desktop.rules.choice
Patch0: fedora-only-MDNS-default.patch
BuildArch: noarch
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: desktop-file-utils
BuildRequires: gettext
BuildRequires: intltool
# glib2-devel is needed for gsettings.m4
BuildRequires: glib2, glib2-devel
BuildRequires: systemd-units
BuildRequires: docbook-style-xsl
BuildRequires: libxslt
BuildRequires: iptables, ebtables, ipset
BuildRequires: python3-devel
BuildRequires: make
Recommends: iptables, ebtables, ipset
Suggests: iptables-nft
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires: firewalld-filesystem = %{version}-%{release}
Requires: python3-firewall  = %{version}-%{release}
Conflicts: selinux-policy < 3.14.1-28
Conflicts: cockpit-ws < 173-2
Recommends: libcap-ng-python3

Provides: variant_config(Server)
Provides: variant_config(Workstation)
Provides: variant_config(KDE Plasma)

%description
firewalld is a firewall service daemon that provides a dynamic customizable
firewall with a D-Bus interface.

%package -n python3-firewall
Summary: Python3 bindings for firewalld

%{?python_provide:%python_provide python3-firewall}

Obsoletes: python-firewall < 0.5.2-2
Obsoletes: python2-firewall < 0.5.2-2
Requires: python3-dbus
Requires: python3-gobject-base
Requires: python3-nftables

%description -n python3-firewall
Python3 bindings for firewalld.

%package -n firewalld-filesystem
Summary: Firewalld directory layout and rpm macros

%description -n firewalld-filesystem
This package provides directories and rpm macros which
are required by other packages that add firewalld configuration files.

%package -n firewalld-test
Summary: Firewalld testsuite

%description -n firewalld-test
This package provides the firewalld testsuite.

%package -n firewall-applet
Summary: Firewall panel applet
Requires: %{name} = %{version}-%{release}
Requires: firewall-config = %{version}-%{release}
Requires: hicolor-icon-theme
%if (0%{?fedora} >= 39 || 0%{?rhel} >= 10)
Requires: python3-pyqt6
%else
Requires: python3-qt5-base
%endif
Requires: python3-gobject
Requires: libnotify
Requires: NetworkManager-libnm
Requires: dbus-x11

%description -n firewall-applet
The firewall panel applet provides a status information of firewalld and also
the firewall settings.

%package -n firewall-config
Summary: Firewall configuration application
Requires: %{name} = %{version}-%{release}
Requires: hicolor-icon-theme
Requires: gtk3
Requires: python3-gobject
Requires: NetworkManager-libnm
Requires: dbus-x11
Recommends: polkit

%description -n firewall-config
The firewall configuration application provides an configuration interface for
firewalld.

%prep
%autosetup -p1

%build
%configure --enable-sysconfig --enable-rpmmacros PYTHON="%{__python3} %{py3_shbang_opts}"
# Enable the make line if there are patches affecting man pages to
# regenerate them
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
desktop-file-install --delete-original \
  --dir %{buildroot}%{_sysconfdir}/xdg/autostart \
  %{buildroot}%{_sysconfdir}/xdg/autostart/firewall-applet.desktop
desktop-file-install --delete-original \
  --dir %{buildroot}%{_datadir}/applications \
  %{buildroot}%{_datadir}/applications/firewall-config.desktop

install -d -m 755 %{buildroot}%{_prefix}/lib/firewalld/zones/
install -c -m 644 %{SOURCE1} %{buildroot}%{_prefix}/lib/firewalld/zones/FedoraServer.xml
install -c -m 644 %{SOURCE2} %{buildroot}%{_prefix}/lib/firewalld/zones/FedoraWorkstation.xml
install -m 644 -D %{SOURCE3} %{buildroot}%{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.desktop.rules.choice

# standard firewalld.conf
mv %{buildroot}%{_sysconfdir}/firewalld/firewalld.conf \
    %{buildroot}%{_sysconfdir}/firewalld/firewalld-standard.conf

# server firewalld.conf
cp -a %{buildroot}%{_sysconfdir}/firewalld/firewalld-standard.conf \
    %{buildroot}%{_sysconfdir}/firewalld/firewalld-server.conf
sed -i 's|^DefaultZone=.*|DefaultZone=FedoraServer|g' \
    %{buildroot}%{_sysconfdir}/firewalld/firewalld-server.conf

# workstation firewalld.conf
cp -a %{buildroot}%{_sysconfdir}/firewalld/firewalld-standard.conf \
    %{buildroot}%{_sysconfdir}/firewalld/firewalld-workstation.conf
sed -i 's|^DefaultZone=.*|DefaultZone=FedoraWorkstation|g' \
    %{buildroot}%{_sysconfdir}/firewalld/firewalld-workstation.conf

rm -f %{buildroot}%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy

# remove file mistakenly added to upstream dist tarball
rm -f %{buildroot}%{_datadir}/man/man1/firewallctl.1

# conflicts with kodi-firewalld package, bug #2129946
rm -f %{buildroot}%{_prefix}/lib/firewalld/services/kodi-*.xml

%find_lang %{name} --all-name

%post
%systemd_post firewalld.service

%preun
%systemd_preun firewalld.service

%postun
%systemd_postun_with_restart firewalld.service

%posttrans
# If we don't yet have a symlink or existing file for firewalld.conf,
# create it. Note: this will intentionally reset the policykit policy
# at the same time, so they are in sync.

# Import /etc/os-release to get the variant definition
. /etc/os-release || :

if [ ! -e %{_sysconfdir}/firewalld/firewalld.conf ]; then
    case "$VARIANT_ID" in
        server)
            ln -sf firewalld-server.conf %{_sysconfdir}/firewalld/firewalld.conf || :
            ;;
        workstation | silverblue | kde | kinoite)
            ln -sf firewalld-workstation.conf %{_sysconfdir}/firewalld/firewalld.conf || :
            ;;
        *)
            ln -sf firewalld-standard.conf %{_sysconfdir}/firewalld/firewalld.conf
            ;;
    esac
fi

if [ ! -e %{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy ]; then
    case "$VARIANT_ID" in
        workstation | silverblue | kde | kinoite)
            ln -sf org.fedoraproject.FirewallD1.desktop.policy.choice %{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy || :
            ln -sf org.fedoraproject.FirewallD1.desktop.rules.choice  %{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.rules ||:
            ;;
        *)
            # For all other editions, we'll use the Server polkit policy
            ln -sf org.fedoraproject.FirewallD1.server.policy.choice %{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy || :
            # no extra rules choice here (yet)
            rm -f %{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.rules || :
    esac
fi

%files -f %{name}.lang
%doc COPYING README.md
%{_sbindir}/firewalld
%{_bindir}/firewall-cmd
%{_bindir}/firewall-offline-cmd
%dir %{_datadir}/bash-completion/completions
%{_datadir}/bash-completion/completions/firewall-cmd
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_firewalld
%{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.desktop.rules.choice
%ghost %config(missingok,noreplace) %{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.rules
%{_prefix}/lib/firewalld/helpers/*.xml
%{_prefix}/lib/firewalld/icmptypes/*.xml
%{_prefix}/lib/firewalld/ipsets/README.md
%{_prefix}/lib/firewalld/policies/*.xml
%{_prefix}/lib/firewalld/services/*.xml
%{_prefix}/lib/firewalld/zones/*.xml
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld
%ghost %config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%config(noreplace) %{_sysconfdir}/firewalld/firewalld-standard.conf
%config(noreplace) %{_sysconfdir}/firewalld/firewalld-server.conf
%config(noreplace) %{_sysconfdir}/firewalld/firewalld-workstation.conf
%config(noreplace) %{_sysconfdir}/firewalld/lockdown-whitelist.xml
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/helpers
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/icmptypes
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/ipsets
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/policies
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/services
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/zones
%defattr(0644,root,root)
%config(noreplace) %{_sysconfdir}/sysconfig/firewalld
%{_unitdir}/firewalld.service
%config(noreplace) %{_datadir}/dbus-1/system.d/FirewallD.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.desktop.policy.choice
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.server.policy.choice
%ghost %{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy
%{_mandir}/man1/firewall*cmd*.1*
%{_mandir}/man1/firewalld*.1*
%{_mandir}/man5/firewall*.5*
%{_sysconfdir}/modprobe.d/firewalld-sysctls.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/firewalld

%files -n python3-firewall
%attr(0755,root,root) %dir %{python3_sitelib}/firewall
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/__pycache__
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/config
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/config/__pycache__
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/core
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/core/__pycache__
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/core/io
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/core/io/__pycache__
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/server
%attr(0755,root,root) %dir %{python3_sitelib}/firewall/server/__pycache__
%{python3_sitelib}/firewall/__pycache__/*.py*
%{python3_sitelib}/firewall/*.py*
%{python3_sitelib}/firewall/config/*.py*
%{python3_sitelib}/firewall/config/__pycache__/*.py*
%{python3_sitelib}/firewall/core/*.py*
%{python3_sitelib}/firewall/core/__pycache__/*.py*
%{python3_sitelib}/firewall/core/io/*.py*
%{python3_sitelib}/firewall/core/io/__pycache__/*.py*
%{python3_sitelib}/firewall/server/*.py*
%{python3_sitelib}/firewall/server/__pycache__/*.py*

%files -n firewalld-filesystem
%dir %{_prefix}/lib/firewalld
%dir %{_prefix}/lib/firewalld/helpers
%dir %{_prefix}/lib/firewalld/icmptypes
%dir %{_prefix}/lib/firewalld/ipsets
%dir %{_prefix}/lib/firewalld/policies
%dir %{_prefix}/lib/firewalld/services
%dir %{_prefix}/lib/firewalld/zones
%{_rpmconfigdir}/macros.d/macros.firewalld

%files -n firewalld-test
%dir %{_datadir}/firewalld/testsuite
%{_datadir}/firewalld/testsuite/README.md
%{_datadir}/firewalld/testsuite/testsuite
%dir %{_datadir}/firewalld/testsuite/integration
%{_datadir}/firewalld/testsuite/integration/testsuite
%dir %{_datadir}/firewalld/testsuite/python
%{_datadir}/firewalld/testsuite/python/firewalld_config.py
%{_datadir}/firewalld/testsuite/python/firewalld_direct.py
%{_datadir}/firewalld/testsuite/python/firewalld_rich.py
%{_datadir}/firewalld/testsuite/python/firewalld_misc.py

%files -n firewall-applet
%{_bindir}/firewall-applet
%defattr(0644,root,root)
%config(noreplace) %{_sysconfdir}/xdg/autostart/firewall-applet.desktop
%dir %{_sysconfdir}/firewall
%config(noreplace) %{_sysconfdir}/firewall/applet.conf
%{_datadir}/icons/hicolor/*/apps/firewall-applet*.*
%{_mandir}/man1/firewall-applet*.1*

%files -n firewall-config
%{_bindir}/firewall-config
%defattr(0644,root,root)
%{_datadir}/firewalld/firewall-config.glade
%{_datadir}/firewalld/gtk3_chooserbutton.py*
%{_datadir}/firewalld/gtk3_niceexpander.py*
%{_datadir}/applications/firewall-config.desktop
%{_datadir}/metainfo/firewall-config.appdata.xml
%{_datadir}/icons/hicolor/*/apps/firewall-config*.*
%{_datadir}/glib-2.0/schemas/org.fedoraproject.FirewallConfig.gschema.xml
%{_mandir}/man1/firewall-config*.1*

%changelog
__CHANGELOG__
