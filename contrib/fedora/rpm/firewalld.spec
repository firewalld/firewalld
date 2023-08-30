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

%if 0%{?fedora}
%bcond_without fedora_variant
%else
%bcond_with    fedora_variant
%endif

%if 0%{?rhel}
%bcond_with    firewalld_test
%else
%bcond_without firewalld_test
%endif

Summary: A firewall daemon with D-Bus interface providing a dynamic firewall
Name: firewalld
Version: %{version}
Release: %{release_version}%{?snap}%{?dist}
URL:     http://firewalld.org
License: GPL-2.0-or-later
Source0: https://github.com/firewalld/firewalld/releases/download/v%{version}/firewalld-%{version}.tar.bz2
Source1: FedoraServer.xml
Source2: FedoraWorkstation.xml
Source3: org.fedoraproject.FirewallD1.desktop.rules.choice

# The patches starting from 0001+ are downstream-only patches that apply
# on both Fedora and RHEL.
# They always apply, also after are rebase to a newer release tarball.
#Patch0001: 0001-some.patch

%if 0%{?fedora}
# The patches starting from 1001+ are downstream-only patches only for Fedora.
# They always apply, also after are rebase to a newer release tarball.
Patch1001: 1001-fedora-only-MDNS-default.patch
%else
Source1001: 1001-fedora-only-MDNS-default.patch
%endif

%if 0%{?rhel}
# The patches starting from 2001+ are downstream-only patches only for RHEL.
# They always apply, also after are rebase to a newer release tarball.
Patch2001: 2001-RHEL-only-Add-cockpit-by-default-to-some-zones.patch
%else
Source2001: 2001-RHEL-only-Add-cockpit-by-default-to-some-zones.patch
%endif

# The patches starting from 9001+ are bugfix patches.
# They can be dropped after the rebase of the tarball (as the fix is already
# upstream).
#Patch9001: 9001-some.patch

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

%if %{with fedora_variant}
Provides: variant_config(Server)
Provides: variant_config(Workstation)
Provides: variant_config(KDE Plasma)
%endif

%description
firewalld is a firewall service daemon that provides a dynamic customizable
firewall with a D-Bus interface.

%package -n python3-firewall
Summary: Python3 bindings for firewalld

%{?python_provide:%python_provide python3-firewall}

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

%if %{with firewalld_test}
%package -n firewalld-test
Summary: Firewalld testsuite

%description -n firewalld-test
This package provides the firewalld testsuite.
%endif

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

%if 0%{?rhel} && 0%{?rhel} < 10
%pretrans -p <lua>
-- HACK: Old rpm versions had an untracked (%ghost) symlink for
-- /etc/firewalld/firewalld.conf. RPM won't handle replacing the symlink due to
-- "%config(noreplace)". As such, we remove the symlink here before attempting
-- to install the new version which is a real file. Only replace the symlink if
-- the target matches one of the previous package's expected targets.
--
-- Unfortunately this must be done in pretrans in order to occur before RPM
-- makes decisions about file replacement.
--
local old_package_symlinks = {"firewalld-standard.conf", "firewalld-server.conf",
                              "firewalld-workstation.conf"}

local symlink_target = posix.readlink("%{_sysconfdir}/firewalld/firewalld.conf")
for k,v in ipairs(old_package_symlinks) do
  if symlink_target == v then
    posix.unlink("%{_sysconfdir}/firewalld/firewalld.conf")
    break
  end
end
%endif

%prep
%autosetup -p1

%build
%configure --enable-sysconfig --enable-rpmmacros PYTHON="%{__python3} %{py3_shbang_opts}"
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

%if 0%{?fedora}
install -c -m 644 %{SOURCE1} %{buildroot}%{_prefix}/lib/firewalld/zones/FedoraServer.xml
install -c -m 644 %{SOURCE2} %{buildroot}%{_prefix}/lib/firewalld/zones/FedoraWorkstation.xml
%endif

%if %{with fedora_variant}
install -m 644 -D %{SOURCE3} %{buildroot}%{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.desktop.rules.choice
%endif

%if %{with fedora_variant}
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
%endif

%find_lang %{name} --all-name

%post
%systemd_post firewalld.service

%preun
%systemd_preun firewalld.service

%postun
%systemd_postun_with_restart firewalld.service

%if %{with fedora_variant}
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
%endif

%files -f %{name}.lang
%doc COPYING README.md CODE_OF_CONDUCT.md
%{_sbindir}/firewalld
%{_bindir}/firewall-cmd
%{_bindir}/firewall-offline-cmd
%dir %{_datadir}/bash-completion/completions
%{_datadir}/bash-completion/completions/firewall-cmd
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_firewalld
%if %{with fedora_variant}
%{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.desktop.rules.choice
%ghost %config(missingok,noreplace) %{_datadir}/polkit-1/rules.d/org.fedoraproject.FirewallD1.rules
%endif
%{_prefix}/lib/firewalld/helpers/*.xml
%{_prefix}/lib/firewalld/icmptypes/*.xml
%{_prefix}/lib/firewalld/ipsets/README.md
%{_prefix}/lib/firewalld/policies/*.xml
%{_prefix}/lib/firewalld/services/*.xml
%{_prefix}/lib/firewalld/xmlschema/*.xsd
%{_prefix}/lib/firewalld/xmlschema/check.sh
%{_prefix}/lib/firewalld/zones/*.xml
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld
%if %{with fedora_variant}
%ghost %config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%config(noreplace) %{_sysconfdir}/firewalld/firewalld-standard.conf
%config(noreplace) %{_sysconfdir}/firewalld/firewalld-server.conf
%config(noreplace) %{_sysconfdir}/firewalld/firewalld-workstation.conf
%else
%config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%endif
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
%if %{with fedora_variant}
%ghost %{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy
%else
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy
%endif
%{_mandir}/man1/firewall*cmd*.1*
%{_mandir}/man1/firewalld*.1*
%{_mandir}/man5/firewall*.5*
%{_sysconfdir}/modprobe.d/firewalld-sysctls.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/firewalld

%if %{without firewalld_test}
%exclude %{_datadir}/firewalld/testsuite
%endif

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
%dir %{_prefix}/lib/firewalld/xmlschema
%{_rpmconfigdir}/macros.d/macros.firewalld

%if %{with firewalld_test}
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
%endif

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
