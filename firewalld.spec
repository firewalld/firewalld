%if (0%{?fedora} >= 13 || 0%{?rhel} > 7)
%global with_python3 1
%if (0%{?fedora} >= 23 || 0%{?rhel} >= 8)
%global use_python3 1
%endif
%endif

Summary: A firewall daemon with D-Bus interface providing a dynamic firewall
Name: firewalld
Version: 0.6.999
Release: 1%{?dist}
URL:     http://firewalld.org
License: GPLv2+
Source0: https://github.com/firewalld/firewalld/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
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
BuildRequires: python2-devel
BuildRequires: iptables, ebtables, ipset
BuildRequires: nftables >= 0.9.0
%if 0%{?with_python3}
BuildRequires:  python3-devel
%endif #0%{?with_python3}
Requires: iptables, ebtables, ipset
Requires: nftables >= 0.9.0
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires: firewalld-filesystem = %{version}-%{release}
%if 0%{?use_python3}
Requires: python3-firewall  = %{version}-%{release}
%else #0%{?use_python3}
Requires: python-firewall  = %{version}-%{release}
%endif #0%{?use_python3}

%description
firewalld is a firewall service daemon that provides a dynamic customizable 
firewall with a D-Bus interface.

%package -n python-firewall
Summary: Python2 bindings for firewalld
Provides: python2-firewall
Obsoletes: python2-firewall
Requires: dbus-python
Requires: python-slip-dbus
Requires: python-decorator
Requires: pygobject3-base

%description -n python-firewall
Python2 bindings for firewalld.

%if 0%{?with_python3}
%package -n python3-firewall
Summary: Python3 bindings for firewalld
Requires: python3-dbus
Requires: python3-slip-dbus
Requires: python3-decorator
%if (0%{?fedora} >= 23 || 0%{?rhel} >= 8)
Requires: python3-gobject-base
%else
Requires: python3-gobject
%endif

%description -n python3-firewall
Python3 bindings for firewalld.
%endif #0%{?with_python3}

%package -n firewalld-filesystem
Summary: Firewalld directory layout and rpm macros

%description -n firewalld-filesystem
This package provides directories and rpm macros which
are required by other packages that add firewalld configuration files.

%package -n firewall-applet
Summary: Firewall panel applet
Requires: %{name} = %{version}-%{release}
Requires: firewall-config = %{version}-%{release}
Requires: hicolor-icon-theme
%if 0%{?use_python3}
Requires: python3-qt5
Requires: python3-gobject
%else
Requires: python-qt5
Requires: pygobject3-base
%endif
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
%if 0%{?use_python3}
Requires: python3-gobject
%else
Requires: pygobject3-base
%endif
Requires: NetworkManager-libnm
Requires: dbus-x11

%description -n firewall-config
The firewall configuration application provides an configuration interface for 
firewalld.

%prep
%autosetup
./autogen.sh

%if 0%{?with_python3}
rm -rf %{py3dir}
cp -a . %{py3dir}
%endif #0%{?with_python3}

%build
%configure --enable-sysconfig --enable-rpmmacros
%if 0%{?use_python3}
make -C src %{?_smp_mflags}
%else
make %{?_smp_mflags}
%endif

%if 0%{?with_python3}
pushd %{py3dir}
%configure --enable-sysconfig --enable-rpmmacros PYTHON=%{__python3}
%if 0%{?use_python3}
make %{?_smp_mflags}
%else
make -C src %{?_smp_mflags}
%endif
popd
%endif #0%{?with_python3}

%install
%if 0%{?use_python3}
make -C src install-nobase_dist_pythonDATA PYTHON=%{__python2} DESTDIR=%{buildroot}
%else
make install PYTHON=%{__python2} DESTDIR=%{buildroot}
%endif #0%{?use_python3}

%if 0%{?with_python3}
pushd %{py3dir}
%if 0%{?use_python3}
make install PYTHON=%{__python3} DESTDIR=%{buildroot}
%else
make -C src install-nobase_dist_pythonDATA PYTHON=%{__python3} DESTDIR=%{buildroot}
%endif #0%{?use_python3}
popd
%endif #0%{?with_python3}

desktop-file-install --delete-original \
  --dir %{buildroot}%{_sysconfdir}/xdg/autostart \
  %{buildroot}%{_sysconfdir}/xdg/autostart/firewall-applet.desktop
desktop-file-install --delete-original \
  --dir %{buildroot}%{_datadir}/applications \
  %{buildroot}%{_datadir}/applications/firewall-config.desktop

%find_lang %{name} --all-name

%post
%systemd_post firewalld.service

%preun
%systemd_preun firewalld.service

%postun
%systemd_postun_with_restart firewalld.service 


%post -n firewall-applet
/bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :

%postun -n firewall-applet
if [ $1 -eq 0 ] ; then
    /bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null
    /usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
    /usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :
fi

%posttrans -n firewall-applet
/usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
/usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :


%post -n firewall-config
/bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :

%postun -n firewall-config
if [ $1 -eq 0 ] ; then
    /bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null
    /usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
    /usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :
fi

%posttrans -n firewall-config
/usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
/usr/bin/glib-compile-schemas %{_datadir}/glib-2.0/schemas &> /dev/null || :

%files -f %{name}.lang
%doc COPYING README
%{_sbindir}/firewalld
%{_bindir}/firewall-cmd
%{_bindir}/firewall-offline-cmd
%dir %{_datadir}/bash-completion/completions
%{_datadir}/bash-completion/completions/firewall-cmd
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_firewalld
%{_prefix}/lib/firewalld/icmptypes/*.xml
%{_prefix}/lib/firewalld/ipsets/README
%{_prefix}/lib/firewalld/services/*.xml
%{_prefix}/lib/firewalld/zones/*.xml
%{_prefix}/lib/firewalld/helpers/*.xml
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld
%config(noreplace) %{_sysconfdir}/firewalld/firewalld.conf
%config(noreplace) %{_sysconfdir}/firewalld/lockdown-whitelist.xml
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/helpers
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/icmptypes
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/ipsets
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/services
%attr(0750,root,root) %dir %{_sysconfdir}/firewalld/zones
%defattr(0644,root,root)
%config(noreplace) %{_sysconfdir}/sysconfig/firewalld
#%attr(0755,root,root) %{_initrddir}/firewalld
%{_unitdir}/firewalld.service
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/FirewallD.conf
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.desktop.policy.choice
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.server.policy.choice
%{_datadir}/polkit-1/actions/org.fedoraproject.FirewallD1.policy
%{_mandir}/man1/firewall*cmd*.1*
%{_mandir}/man1/firewalld*.1*
%{_mandir}/man5/firewall*.5*
%{_sysconfdir}/modprobe.d/firewalld-sysctls.conf

%files -n python-firewall
%attr(0755,root,root) %dir %{python2_sitelib}/firewall
%attr(0755,root,root) %dir %{python2_sitelib}/firewall/config
%attr(0755,root,root) %dir %{python2_sitelib}/firewall/core
%attr(0755,root,root) %dir %{python2_sitelib}/firewall/core/io
%attr(0755,root,root) %dir %{python2_sitelib}/firewall/server
%{python2_sitelib}/firewall/*.py*
%{python2_sitelib}/firewall/config/*.py*
%{python2_sitelib}/firewall/core/*.py*
%{python2_sitelib}/firewall/core/io/*.py*
%{python2_sitelib}/firewall/server/*.py*

%if 0%{?with_python3}
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
%endif #0%{?with_python3}

%files -n firewalld-filesystem
%dir %{_prefix}/lib/firewalld
%dir %{_prefix}/lib/firewalld/helpers
%dir %{_prefix}/lib/firewalld/icmptypes
%dir %{_prefix}/lib/firewalld/ipsets
%dir %{_prefix}/lib/firewalld/services
%dir %{_prefix}/lib/firewalld/zones
%{_rpmconfigdir}/macros.d/macros.firewalld

%files -n firewall-applet
%attr(0755,root,root) %dir %{_sysconfdir}/firewall
%{_bindir}/firewall-applet
%defattr(0644,root,root)
%{_sysconfdir}/xdg/autostart/firewall-applet.desktop
%{_sysconfdir}/firewall/applet.conf
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
* Fri Apr 20 2018 Eric Garver <e@erig.me> - 0.6.0-1
- bump package to v0.6.0

* Thu Jan 25 2018 Eric Garver <e@erig.me> - 0.5.0-1
- rebase package to v0.5.0

* Tue Jun  6 2017 Thomas Woerner <twoerner@redhat.com> - 0.4.4.5-1
- Fix build from spec without fedorahosted.org archives
- firewalld.spec: Add missing autotools dependencies
- firewall-offline-cmd: Fix --remove-service-from-zone option RHBZ#1438127
- Merge pull request 213 from hwoarang/add-missing-autotools
- Support sctp and dccp in ports, source-ports, forward-ports, helpers and
  rich rules
- firewall-cmd: Fix --{set,get}-{short,description} for zone
- firewall.core.ipXtables: Use new wait option for restore commands if
  available
- Merge pull request 212 from leongold/ovirt-imageio-service
- config/Makefile.am: Install new ovirt-imageio service
- README: Use firewalld.org/documentation as documentation link
- Fix misspelled word in documentation
- Merge pull request 216 from tobiasvl/fix-protocol-spelling
- Man pages: Mention sctp and dccp protocols for remaining ports, ..
- Adding ovirt-vmconsole service file
- Adding oVirt storage-console service.
- Adding ctdb service file.
- Merge pull request 219 from leongold/ctdb-service
- Fixing incorrect port number
- Merge pull request 217 from leongold/ovirt-vmconsole
- Merge pull request 218 from leongold/ovirt-storageconsole
- config/Makefile.am: New services ctdb, ovirt-storageconsole and
  ovirt-vmconsole
- Adding service file for nrpe.
- Merge pull request 220 from leongold/nrpe-service
- config/Makefile.am: New services nrpe
- Rename extension for policy choices (server and desktop) to .policy.choice
  (RHBZ#1449754)
- D-Bus interfaces: Fix GetAll for interfaces without properties
  (RHBZ#1452017)
- firewall.core.fw_config: Fix wrong variable use in repr output
- firewall.core.fw_icmptype: Add missing import for copy
- firewall.core.fw_test: Fix wrong format string in repr
- firewall.core.io.zone: Fix __getattr__ use on super(Zone)
- firewall.functions: New function get_nf_nat_helpers
- firewall.core.fw: Get NAT helpers and store them internally.
- firewall.core.fw_zone: Load NAT helpers with conntrack helpers
- firewalld.dbus: Add missing properties nf_conntrach_helper_setting and
  nf_conntrack_helpers
- firewall.server.firewalld: New property for NAT helpers supported by the
  kernel
- Translation updates

* Mon Mar 27 2017 Thomas Woerner <twoerner@redhat.com> - 0.4.4.4-1
- Drop references to fedorahosted.org from spec file and Makefile.am
- Fix inconsistent ordering of rules in INPUT_ZONE_SOURCE (issue#166)
- Fix ipset overloading from /etc/firewalld/ipsets
- Fix permanent rich rules using icmp-type elements (RHBZ#1434594)
- firewall-config: Deactivate edit, remove, .. buttons if there are no items
- Check if ICMP types are supported by kernel before trying to use them
- firewall-config: Show invalid ipset type in the ipset configuration dialog
  in a special label

* Thu Feb  9 2017 Thomas Woerner <twoerner@redhat.com> - 0.4.4.3-1
- New service freeipa-trust (RHBZ#1411650)
- Complete icmp types for IPv4 and IPv6
- New h323 helper container
- Support helper container: h323
- firewall.server.decorators: ALREADY_ errors should be logged as warnings
- firewall.command: ALREADY_SET should also result in zero exit code
- tests/firewall-offline-cmd_test.sh: Only use firewall-offline-cmd
- Support more ipset types: hash:ip,port, hash:ip,port,ip, hash:ip,port,net,
  hash:ip,mark, hash:net,net, hash:net,port, hash:net,port,net, hash:net,iface
- New checks for ipset entry validation
- Use ipset dimension for match
- firewall.core.base: New ZONE_SOURCE_IPSET_TYPES list
- New firewall.core.icmp providing names and types for icmp and icmpv6 values
- firewall.core.fw_ipset: New methods to get ipset dimension and applied state
- firewall.errors: New error NOT_APPLIED
- firewall-cmd man page: Add missing --get-ipset-types
- firewall.core.fw_nm: No trace back on failed get_connection call
  (RHBZ#1413345)
- firewall.core.prog: Fix addition of the error output in runProg
- Speed up ipset handling, (re)loading and import from file
- Support --family option for --new-ipset
- Handle FirewallError for query sequences in command line tools
- Fail to alter entries of ipsets with timeout
- Extended tests for ipset options
- Return empty list for ipsets using timeouts
- firewall.functions: Fix checks in checkIPnMask and checkIP6nMask (issue#186)
- firewalld.conf man page: New section about AutomaticHelpers
- firewall-offline-cmd man page: Added -v and -q options, fixed section ids
- firewall{-cmd, ctl}: Fix scope of final return in try_set_zone_of_interface
- firewall.core.fw_zone: Limit masquerading forward rule to new connections
- firewall-config: Update active zones on reloaded signal
- firewall-applet: Update active zones and tooltip on reloaded signal
- firewall.core.fw_zone: Fix missing chain for helper in rich rules using
  service (RHBZ#1416578)
- Support icmp-type usage in rich rules (RHBZ#1409544)
- firewall[-offline]-cmd: Fix --{set,get}-{short,description} for ipset and
  helper (RHBZ#1416325)
- firewall.core.ipset: Solve ipset creation issues with -exist and more flag
  tests
- Speed up start and restart for ipsets with lots of entries (RHBZ#1416817)
- Speed up of ipset alteration by adding and removing entries using a file
  (RHBZ#1416817)
- Code cleanup and minor bug fixes
- firewall.core.prog: Fix addition of the error output in runProg
- New services mssql, kibana, elasticsearch, quassel, bitcoin-rpc,
  bitcoin-testnet-rpc, bitcoin-testnet, bitcoin and spideroak-lansync
- Translation updates

* Thu Dec  1 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.4.2-1
- firewalld.spec: Added helpers and ipsets paths to firewalld-filesystem
- firewall.core.fw_nm: create NMClient lazily
- Do not use hard-coded path for modinfo, use autofoo to detect it
- firewall.core.io.ifcfg: Dropped invalid option warning with bad format
  string
- firewall.core.io.ifcfg: Properly handle quoted ifcfg values
- firewall.core.fw_zone: Do not reset ZONE with ifdown
- Updated translations from zanata
- firewall-config: Extra grid at bottom to visualize firewalld settings

* Wed Nov  9 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.4.1-1
- firewall-config: Use proper source check in sourceDialog (fixes issue#162)
- firewallctl: New support for helpers
- Translation updates

* Fri Oct 28 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.4-1
- Fix dist-check
- src/Makefile.am: Install new helper files
- config/Makefile.am: Install helpers
- Merged translations
- Updated translations from zanata
- firewalld.spec: Adapt requires for PyQt5
- firewall-applet: Fix fromUTF8 for python2 PyQt5 usage
- firewall-applet: Use PyQt5
- firewall-config: New nf_conntrack_select dialog, use nf_conntrack_helpers D-Bus property
- shell-completion/bash/firewall-cmd: Updates for helpers and also some fixes
- src/tests/firewall-[offline-]cmd_test.sh: New helper tests, adapted module tests for services
- doc/xml/seealso.xml: Add firewalld.helper(5) man page
- doc/xml/seealso.xml: Add firewalld.ipset(5) man page
- Fixed typo in firewalld.ipset(5) man page
- Updated firewalld.dbus(5) man page
- New firewalld.helper(5) man page
- doc/xml/firewall-offline-cmd.xml: Updated firewall-offline-cmd man page
- doc/xml/firewall-cmd.xml: Updated firewall-cmd man page
- firewall-offline-cmd: New support for helpers
- firewall-cmd: New support for helpers
- firewall.command: New check_helper_family, check_module and print_helper_info methods
- firewall.core.fw_test: Add helpers also to offline backend
- firewall.server.config: New AutomaticHelpers property (rw)
- firewall.server.config: Fix an dict size changed error for firewall.conf file changes
- firewall.server.config: Make LogDenied property readwrite to be consistent
- Some renames of nf_conntrack_helper* functions and structures, helpers is a dict
- firewall.core.fw: Properly check helper setting in set_automatic_helpers
- firewall.errors: Add missing BUILTIN_HELPER error code
- No extra interface for helpers needed in runtime, dropped DBUS_INTERFACE_HELPER
- firewall.server.firewalld: Drop unused queryHelper D-Bus method
- New helpers Q.931 and RAS from nf_conntrack_h323
- firewall.core.io.helper: Allow dots in helper names, remove underscore
- firewall.core.io.firewalld_conf: Fixed typo in FALLBACK_AUTOMATIC_HELPERS
- firewall-[offline-]cmd: Use sys.excepthook to force exception_handler usage always
- firewall.core.fw_config: new_X methods should also check builtins
- firewall.client: Set helper family to "" if None
- firewall.client: Add missing module string to FirewallClientHelperSettings.settings
- config/firewalld.conf: Add possible values description for AutomaticHelpers
- helpers/amanda.xml: Fix typo in helper module
- firewall-config: Added support for helper module setting
- firewall.client: Added support for helper module setting
- firewall.server.config_helper: Added support for helper module setting
- firewall.core.io.service, firewall.server.config_service: Only replace underscore by dash if module start with nf_conntrack_
- firewall.core.fw_zone: Use helper module instead of a generated name from helper name
- helpers: Added kernel module
- firewall.core.io.helper: Add module to helper
- firewall-cmd: Removed duplicate --get-ipset-types from help output
- firewall.core.fw_zone: Add zone bingings for PREROUTING in the raw table
- firewall.core.ipXtables: Add PREROUTING default rules for zones in raw table
- firewall-config: New support to handle helpers, new dialogs, new helper tab, ..
- config/org.fedoraproject.FirewallConfig.gschema.xml.in: New show-helpers setting
- firewall.client: New helper management for runtime and permanent configuration
- firewall.server.firewalld: New runtime helper management, new nf_conntrack_helper property
- firewall.server.config_service: Fix module name handling (no nf_conntrack_ prefix needed)
- firewall.server.config: New permanent D-Bus helper management
- New firewall.server.config_helper to provide the permanent D-Bus interface for helpers
- firewall.core.fw_zone: Use helpers fw.nf_conntrack_helper for services using helpers
- firewall.core.fw: New helper management, new _automatic_helpers and nf_conntrack_helper settings
- firewall.core.fw_config: Add support for permanent helper handling
- firewall.core.io.service: The module does not need to start with nf_conntrack_ anymore
- firewall.functions: New functions to get and set nf_conntrack_helper kernel setting
- firewall.core.io.firewalld_conf: New support for AutomaticHelpers setting
- firewall.config.dbus: New D-Bus definitions for helpers, new DBUS_INTERFACE_REVISION 12
- New firewall.core.fw_helper providing FirewallHelper backend
- New firewall.core.helper with HELPER_MAXNAMELEN definition
- config/firewalld.conf: New AutomaticHelpers setting with description
- firewall.config.__init__.py.in: New helpers variables
- firewalld.spec: Add new helpers directory
- config/Makefile.am: Install new helpers
- New helper configuration files for amanda, ftp, irc, netbios-ns, pptp, sane, sip, snmp and tftp
- firewall.core.io.helper: New IO handler for netfilter helpers
- firewall.errors: New INVALID_HELPER error code
- firewall.core.io.ifcfg: Use .bak for save files
- firewall-config: Set internal log_denied setting after changing
- firewall.server.config: Copy props before removing items
- doc/xml/firewalld.ipset: Replaced icmptype name remains with ipset
- firewall.core.fw_zone: Fix LOG rule placement for LogDenied
- firewall.command: Use "source-ports" in print_zone_info
- firewall.core.logger: Use syslog.openlog() and syslog.closelog()
- firewall-[offline-]cmd man pages: Document --path-{zone,icmptype,ipset,service}
- firewall-cmd: Enable --path-{zone,icmptype,service} options again
- firewall.core.{ipXtables,ebtables}: Copy rule before extracting items in set_rules
- firewall.core.fw: Do not abort transaction on failed ipv6_rpfilter rules
- config/Makefile.am: Added cfengine, condor-collector and smtp-submission services
- Makefile.am: New dist-check used in the archive target
- src/Makefile.am: Reordered nobase_dist_python_DATA to be sorted
- config/Makefile.am: New CONFIG_FILES variable to contain the config files
- Merge pull request #150 from hspaans/master
- Merge pull request #146 from canvon/bugfix/spelling
- Merge pull request #145 from jcpunk/condor
- Command line tools man pages: New section about sequence options and exit codes
- Creating service file for SMTP-Submission.
- Creating service file for CFEngine.
- Fix typo in documentation: iptables mangle table
- Only use sort on lists of main items, but not for item properties
- firewall.core.io.io_object: import_config should not change ordering of lists
- firewall.core.fw_transaction: Load helper modules in FirewallZoneTransaction
- firewall.command: Fail with NOT_AUTHORIZED if authorization fails (RHBZ#1368549)
- firewall.command: Fix sequence exit code with at least one succeeded item
- Add condor collector service
- firewall-cmd: Fixed --{get,set}-{description,short} for permanent zones
- firewall.command: Do not use error code 254 for {ALREADY,NOT}_ENABLED sequences

* Tue Aug 16 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.3.3-1
- Fix CVE-2016-5410: Firewall configuration can be modified by any logged in
  user
- firewall/server/firewalld: Make getXSettings and getLogDenied CONFIG_INFO
- Update AppData configuration file.
- tests/firewalld_rich.py: Use new import structure and FirewallClient classes
- tests/firewalld_direct.py: Use new import structure
- tests: firewalld_direct: Fix assert to check for True instead of False
- tests: firewalld_config: Fix expected value when querying the zone target
- tests: firewalld_config: Use real nf_conntrack modules
- firewalld.spec: Added comment about make call for %build
- firewall-config: Use also width_request and height_request with default size
- Updated firewall-config screenshot
- firewall-cmd: Fixed typo in help output (RHBZ#1367171)
- test-suite: Ignore stderr to get default zone also for missing firewalld.conf
- firewall.core.logger: Warnings should be printed to stderr per default
- firewall.core.fw_nm: Ignore NetworkManager if NM.Client connect fails
- firewall-cmd, firewallctl: Gracefully fail if SystemBus can not be aquired
- firewall.client: Generate new DBUS_ERROR if SystemBus can not be aquired
- test-suite: Do not fail on ALREADY_ENABLED --add-destination tests
- firewall.command: ALREADY_ENABLED, NOT_ENABLED, ZONE_ALREADY_SET are warnings
- doc/xml/firewalld.dbus.xml: Removed undefined reference
- doc/xml/transform-html.xsl.in: Fixed references in the document
- doc/xml/firewalld.{dbus,zone}.xml: Embed programlisting in para
- doc/xml/transform-html.xsl.in: Enhanced html formatting closer to the man page
- firewall: core: fw_nm: Instantiate the NM client only once
- firewall/core/io/*.py: Do not traceback on a general sax parsing issue
- firewall-offline-cmd: Fix --{add,remove}-entries-from-file
- firewall-cmd: Add missing action to fix --{add,remove}-entries-from-file
- firewall.core.prog: Do not output stderr, but return it in the error case
- firewall.core.io.ifcfg.py: Fix ifcfg file reader and writer (RHBZ#1362171)
- config/firewall.service.in: use KillMode=mixed
- config/firewalld.service.in: use network-pre.target
- firewall-config: Add missing gettext.textdomain call to fix translations
- Add UDP to transmission-client.xml service
- tests/firewall-[offline-]cmd_test.sh: Hide errors and warnings
- firewall.client: Fix ALREADY_ENABLED errors in icmptype destination calls
- firewall.client: Fix NOT_ENABLED errors in icmptype destination calls
- firewall.client: Use {ALREADY,NOT}_ENABLED errors in icmptype destination
  calls
- firewall.command: Add the removed FirewallError handling to the action
  (a17ce50)
- firewall.command: Do not use query methods for sequences and also single
  options
- Add missing information about MAC and ipset sources to man pages and help
  output
- firewalld.spec: Add BuildRequires for libxslt to enable rebuild of man pages
- firewall[-offline]-cmd, firewallctl, firewall.command: Use sys.{stdout,stderr}
- firewallctl: Fix traceback if not connected to firewalld
- firewall-config: Initialize value in on_richRuleDialogElementChooser_clicked
- firewall.command: Convert errors to string for Python3
- firewall.command: Get proper firewall error code from D-BusExceptions
- firewall-cmd: Fixed traceback without args
- Add missing service files to Makefile.am
- shell-completion: Add shell completion support for
  --{get,set}--{description,short}

* Mon Jul  4 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.3.2-1
- Fix regression with unavailable optional commands
- All missing backend messages should be warnings
- Individual calls for missing restore commands
- Only one authenticate call for add and remove options and also sequences
- New service RH-Satellite-6

* Tue Jun 28 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.3.1-1
- firewall.command: Fix python3 DBusException message not interable error
- src/Makefile.am: Fix path in firewall-[offline-]cmd_test.sh while installing
- firewallctl: Do not trace back on list command without further arguments
- firewallctl (man1): Added remaining sections zone, service, ..
- firewallctl: Added runtime-to-permanent, interface and source parser,
  IndividualCalls setting
- firewall.server.config: Allow to set IndividualCalls property in config
  interface
- Fix missing icmp rules for some zones
- runProg: Fix issue with running programs
- firewall-offline-cmd: Fix issues with missing system-config-firewall
- firewall.core.ipXtables: Split up source and dest addresses for transaction
- firewall.server.config: Log error in case of loading malformed files in
  watcher
- Install and package the firewallctl man page

* Wed Jun 22 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.3-1
- New firewallctl utility (RHBZ#1147959)
- doc.xml.seealso: Show firewalld.dbus in See Also sections
- firewall.core.fw_config: Create backup on zone, service, ipset and icmptype
  removal (RHBZ#1339251)
- {zone,service,ipset,icmptype}_writer: Do not fail on failed backup
- firewall-[offline-]cmd: Fix --new-X-from-file options for files in cwd
- firewall-cmd: Dropped duplicate setType call in --new-ipset
- radius service: Support also tcp ports (RBZ#1219717)
- xmlschemas: Support source-port, protocol, icmp-block-inversion and ipset
  sources
- config.xmlschema.service.xsd: Fix service destination conflicts
  (RHBZ#1296573)
- firewall-cmd, firewalld man: Information about new NetworkManager and ifcfg
- firewall.command: Only print summary and description in print_X_info with
  verbose
- firewall.command: print_msg should be able to print empty lines
- firewall-config: No processing of runtime passthroughs signals in permanent
- Landspace.io fixes and pylint calm downs
- firewall.core.io.zone: Add zone_reader and zone_writer to __all__, pylint
  fixes
- firewall-config: Fixed titles of command and context dialogs, also entry
  lenths
- firewall-config: pylint calm downs
- firewall.core.fw_zone: Fix use of MAC source in rich rules without ipv limit
- firewall-config: Use self.active_zoens in conf_zone_added_cb
- firewall.command: New parse_port, extended parse methods with more checks
- firewall.command: Fixed parse_port to use the separator in the split call
- firewall.command: New [de]activate_exception_handler, raise error in parse_X
- services ha: Allow corosync-qnetd port
- firewall-applet: Support for kde5-nm-connection-editor
- tests/firewall-offline-cmd_test.sh: New tests for service and icmptype
  modifications
- firewall-offline-cmd: Use FirewallCommand for simplification and sequence
  options
- tests/firewall-cmd_test.sh: New tests for service and icmptype modifications
- firewall-cmd: Fixed set, remove and query destination options for services
- firewall.core.io.service: Source ports have not been checked in _check_config
- firewall.core.fw_zone: Method check_source_port is not used, removed
- firewall.core.base: Added default to ZONE_TARGETS
- firewall.client: Allow to remove ipv:address pair for service destinations
- tests/firewall-offline-cmd_test.sh: There is no timeout option in permanent
- firewall-cmd: Landscape.io fixes, pylint calm downs
- firewall-cmd: Use FirewallCommand for simplification and sequence options
- firewall.command: New FirewallCommand for command line client simplification
- New services: kshell, rsh, ganglia-master, ganglia-client
- firewalld: Cleanup of unused imports, do not translate some deamon messages
- firewalld: With fd close interation in runProg, it is not needed here anymore
- firewall.core.prog: Add fd close iteration to runProg
- firewall.core.fw_nm: Hide NM typelib import, new nm_get_dbus_interface
  function
- firewalld.spec: Require NetworkManager-libnm instead of NetworkManager-glib
- firewall-config: New add/remove ipset entries from file, remove all entries
- firewall-applet: Fix tooltip after applet start with connection to firewalld
- firewall-config: Select new zone, service or icmptype if the view was empty
- firewalld.spec: Added build requires for iptables, ebtables and ipset
- Adding nf_conntrack_sip module to the service SIP
- firewall: core: fw_ifcfg: Quickly return if ifcfg directory does not exist
- Drop unneeded python shebangs
- Translation updates

* Mon May 30 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.2-1
- New module to search for and change ifcfg files for interfaces not under
  control of NM
- firewall_config: Enhanced messages in status bar
- firewall-config: New message window as overlay if not connected
- firewall-config: Fix sentivity of option, view menus and main paned if not
  connected
- firewall-applet: Quit on SIGINT (Ctrl-C), reduced D-Bus calls, some cleanup
- firewall-[offline]cmd: Show target in zone information
- D-Bus: Completed masquerade methods in FirewallClientZoneSettings
- Fixed log-denied rules for icmp-blocks
- Keep sorting of interfaces, services, icmp-blocks and other settings in zones
- Fixed runtime-to-permanent not to save interfaces under control of NM
- New icmp-block-inversion flag in the zones
- ICMP type filtering in the zones
- New services: sip, sips, managesieve
- rich rules: Allow destination action (RHBZ#1163428)
- firewall-offline-cmd: New option -q/--quiet
- firewall-[offline-]cmd: New --add-[zone,service,ipset,icmptype]-from-file
- firewall-[offline-]cmd: Fix option for setting the destination address
- firewall-config: Fixed resizing behaviour
- New transaction model for speed ups in start, restart, stop and other actions
- firewall-cmd: New options --load{zone,service,ipset,icmptype}-defaults
- Fixed memory leak in dbus_introspection_add_properties
- Landscape.io fixes, pylint calm downs
- New D-Bus getXnames methods to speed up firewall-config and firewall-cmd
- ebtables-restore: No support for COMMIT command
- Source port support in services, zones and rich rules
- firewall-offline-cmd: Added --{add,remove}-entries-from-file for ipsets
- firewall-config: New active bindings side bar for simple binding changes
- Reworked NetworkManager module
- Proper default zone handling for NM connections
- Try to set zone binding with NM if interface is under control of NM
- Code cleanup and bug fixes
- Include test suite in the release and install in /usr/share/firewalld/tests
- New Travis-CI configuration file
- Fixed more broken frensh translations
- Translation updates

* Wed Apr 20 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.1.2-1
- Install fw_nm module
- firewalld: Do not fail if log file could not be opened
- Make ipsets visible per default in firewall-config
- Fixed translations with python3

* Tue Apr 19 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.1.1-1
- Fixed broken frensh translation

* Tue Apr 19 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.1-1
- Enhancements of ipset handling
  - No cleanup of ipsets using timeouts while reloading
  - Only destroy conflicting ipsets
  - Only use ipset types supported by the system
  - Add and remove several ipset entries in one call using a file
- Reduce time frame where builtin chains are on policy DROP while reloading
- Include descriptions in --info-X calls
- Command line interface support to get and alter descriptions of zones,
  services, ipsets and icmptypes with permanent option
- Properly watch changes in combined zones
- Fix logging in rich rule forward rules
- Transformed direct.passthrough errors into warnings
- Rework of import structures
- Reduced calls to get ids for port and protocol names (RHBZ#1305434)
- Build and installation fixes by Markos Chandras
- Provide D-Bus properties in introspection data
- Fix for flaws found by landscape.io
- Fix for repeated SUGHUP
- New NetworkManager module to get and set zones of connections, used in
  firewall-applet and firewall-config
- configure: Autodetect backend tools ({ip,ip6,eb}tables{,-restore}, ipset)
- Code cleanups
- Bug fixes

* Fri Jan 29 2016 Thomas Woerner <twoerner@redhat.com> - 0.4.0-1
- Several new services
- Lots of bug fixes
- Speed up: Using -restore commands
- Optimizations
- ipset support
- MAC address support
- Enhancements
  - Rich language
  - documentation
  - firewall-config
  - firewall-applet
  - Command line tools
- Log of denied packets

* Tue Jun 16 2015 Thomas Woerner <twoerner@redhat.com> - 0.3.14.2-0
- fixed requirements for -applet and -config
- adapted firewall-applet man page to new version
- firewall-applet, firewall-config: Only honour active connections
- firewall-applet: Change QSettings path and file names
- Updated translations, marked translations for "Connections" as fuzzy

* Fri Jun 12 2015 Thomas Woerner <twoerner@redhat.com> - 0.3.14.1-0
- spec file adaptions from Fedora
- dropped gtk applet remain: org.fedoraproject.FirewallApplet.gschema.xml

* Fri Jun 12 2015 Thomas Woerner <twoerner@redhat.com> - 0.3.14-1
- firewalld:
  - print real zone names in error messages
  - iptables 1.4.21 does not accept limits of 1/day, minimum is 2/day now
  - rate limit fix for rich rules
  - fix readdition of removed permanent direct settings
  - adaption of the polkit domains to use PK_ACTION_DIRECT_INFO
  - fixed two minor Python3 issues in firewall.core.io.direct
  - fixed use of fallback configuration values
  - fixed use without firewalld.conf
  - firewalld main restructureization
  - IPv6_rpfilter now also available as a property on D-Bus in the config interface
  - fixed wait option use for ipXtables
  - added --concurrent support for ebtables
  - richLanguage: allow masquerading with destination
  - richLanguage: limit masquerading forward rule to new connections
  - ipXtables: No dns lookups in available_tables and _detect_wait_option
  - full ebtables support: start, stop, reload, panic mode, direct chains and rules
  - fix for reload with direct rules
  - fix or flaws found by landscape.io
  - pid file handling fixes in case of pid file removal
  - fix for client issue in case of a dbus NoReply error
- configuration
  - new services: dropbox-lansync, ptp
  - new icmptypes: timestamp-request, timestamp-reply
- man pages:
  - firewalld.zones(5): fixed typos
  - firewalld.conf(5): Fixed wrong reference to firewalld.lockdown-whitelist page
- firewall-applet:
  - new version using Qt4 fixing several issues with the Gtk version
- spec file:
  - enabled Python3 support: new backends python-firewall and python3-firewall
  - some cleanup
- git:
  - migrated to github
- translations:
  - migrated to zanata
- build environment:
  - no need for autoconf-2.69, 2.68 is sufficient

* Wed Jan 28 2015 Thomas Woerner <twoerner@redhat.com> - 0.3.14-0
- enable python2 and python3 bindings for fedora >= 20 and rhel >= 7
- use python3 bindings on fedora >= 22 and rhel >= 8 for firewalld,
  firewall-config and firewall-applet

* Thu Dec 04 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.13-1
- firewalld:
  - ipXtables: use -w or -w2 if supported (RHBZ#1161745, RHBZ#1151067)
  - DROP INVALID packets (RHBZ#1169837)
  - don't use ipv6header for protocol matching. (RHBZ#1065565)
  - removeAllPassthroughs(): remove passthroughs in reverse order (RHBZ#1167100)
  - fix config.service.removeDestination() (RHBZ#1164584)
- firewall-config:
  - portProtoDialog: other protocol excludes port number/range
  - better fix for updating zoneStore also in update_active_zones()
  - fix typo in menu
- configuration:
  - new services: tinc, vdsm, mosh, iscsi-target, rsyncd
  - ship and install XML Schema files. (#8)
- man pages:
  - firewalld.dbus, firewalld.direct, firewalld, firewall-cmd
- spec file:
  - filesystem subpackage
  - make dirs&files in /usr/lib/ world-readable (RHBZ#915988)

* Tue Oct 14 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.12-1
- firewalld:
  - new runtimeToPermanent and tracked passsthrough support
  - make permanent D-Bus interfaces more fine grained like the runtime versions (RHBZ#1127706)
  - richLanguage: allow using destination with forward-port
  - Rich_Rule.check(): action can't be used with icmp-block/forward-port/masquerade
  - fixed Python specific D-Bus exception (RHBZ#1132441)
- firewall-cmd:
  - new --runtime-to-permanent to create permanent from runtime configuration
  - use new D-Bus methods for permanent changes
  - show target REJECT instead of %%REJECT%% (RHBZ#1058794)
  - --direct: make fail messages consistent (RHBZ#1141835)
- firewall-config:
  - richRuleDialog - OK button tooltip indicates problem
  - use new D-Bus methods for permanent changes
  - show target REJECT instead of %%REJECT%% (RHBZ#1058794)
  - update "Change Zones of Connections" menu on default zone change (RHBZ#11120212)
  - fixed rename of zones, services and icmptypes to not create new entry (RBHZ#1131064)
- configuration:
  - new service for Squid HTTP proxy server
  - new service for Kerberos admin server
  - new services for syslog and syslog-tls
  - new services for SNMP and SNMP traps
  - add Keywords to .desktop to improve software searchability
- docs:
  - updated translations
  - firewalld.richlanguage: improvements suggested by Rufe Glick
  - firewalld.dbus: various improvements
  - firewalld.zone: better description of Limit tag
  - mention new homepage everywhere

* Mon Aug 25 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.11-2
- add few Requires to spec (RHBZ#1133167)

* Wed Aug 20 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.11-1
- firewalld:
  - improve error messages
  - check built-in chains in direct chain handling functions (RHBZ#1120619)
  - dbus_to_python() check whether input is of expected type (RHBZ#1122018)
  - handle negative timeout values (RHBZ#1124476)
  - warn when Command/Uid/Use/Context already in lockdown whitelist (RHBZ#1126405)
  - make --lockdown-{on,off} work again (RHBZ#1111573)
- firewall-cmd:
  - --timeout now accepts time units (RHBZ#994044)
- firewall-config:
  - show active (not default) zones in bold (RHBZ#993655)
- configuration:
  - remove ipp-client service from all zones (RHBZ#1105639).
  - fallbacks for missing values in firewalld.conf
  - create missing dirs under /etc if needed
  - add -Es to python command in lockdown-whitelist.xml (RHBZ#1099065)
- docs:
  - 'direct' methods concern only chains/rules added via 'direct' (RHBZ#1120619)
  - --remove-[interface/source] don't need a zone to be specified (RHBZ#1125851)
  - various fixes in firewalld.zone(5), firewalld.dbus(5), firewalld.direct(5)
- others:
  - rpm macros for easier packaging of e.g. services

* Wed May 28 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.10-1
- new services: freeipa-*, puppermaster, amanda-k5, synergy,
                xmpp-*, tor, privoxy, sane
- do not use at_console in D-Bus policies (RHBZ#1094745)
- apply all rich rules for non-default targets
- AppData file (RHBZ#1094754)
- separate Polkit actions for desktop & server (RHBZ#1091068)
- sanitize missing ip6t_rpfilter (RHBZ#1074427)
- firewall/core/io/*: few improvements (RHBZ#1065738)
- no load failed error for absent direct.xml file
- new DBUS_INTERFACE.getZoneSettings to get all run-time zone settings
- fixed creation and deletion of zones, services and icmptypes over D-Bus signals
- FirewallClientZoneSettings: Set proper default target
- if Python2 then encode strings from sax parser (RHBZ#1059104, RHBZ#1058853)
- firewall-cmd:
  - don't colour output of query commands (RHBZ#1097841)
  - use "default" instead of {chain}_{zone} (RHBZ#1075675)
  - New --get-target and --set-target
  - Create and remove permanent zones, services and icmptypes
- firewall-config:
  - Adding services and icmptypes resulted in duplicates in UI
  - Use left button menu of -applet in Option menu
- firewall-offline-cmd: same functionality as 'firewall-cmd --permanent'
- firewall-applet: ZoneConnectionEditor was missing the Default Zone entry
- bash-completion: getting zones/services/icmps is different with/without --permanent
- firewalld.zone(5): removed superfluous slash (RHBZ#1091575)
- updated translations

* Wed Feb 05 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.9.3-1
- Fixed persistent port forwarding (RHBZ#1056154)
- Stop default zone rules being applied to all zones (RHBZ#1057875)
- Enforce trust, block and drop zones in the filter table only (RHBZ#1055190)
- Allow RAs prior to applying IPv6_rpfilter (RHBZ#1058505)
- Fix writing of rule.audit in zone_writer()

* Fri Jan 17 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.9.2-1
- fix regression introduced in 0.3.9 (RHBZ#1053932)

* Thu Jan 16 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.9.1-1
- fix regressions introduced in 0.3.9 (RHBZ#1054068, RHBZ#1054120)

* Mon Jan 13 2014 Jiri Popelka <jpopelka@redhat.com> - 0.3.9-1
- translation updates
- New IPv6_rpfilter setting to enable source address validation (RHBZ#847707)
- Do not mix original and customized zones in case of target changes,
  apply only used zones
- firewall-cmd: fix --*_lockdown_whitelist_uid to work with uid 0
- Don't show main window maximized. (RHBZ#1046811)
- Use rmmod instead of 'modprobe -r' (RHBZ#1031102)
- Deprecate 'enabled' attribute of 'masquerade' element
- firewall-config: new zone was added twice to the list
- firewalld.dbus(5)
- Enable python shebang fix again
- firewall/client: handle_exceptions: Use loop in decorator
- firewall-offline-cmd: Do not mask firewalld service with disabled option
- firewall-config: richRuleDialogActionRejectType Entry -> ComboBox
- Rich_Rule: fix parsing of reject element (RHBZ#1027373)
- Show combined zones in permanent configuration (RHBZ#1002016)
- firewall-cmd(1): document exit code 2 and colored output (RHBZ#1028507)
- firewall-config: fix RHBZ#1028853

* Tue Nov 05 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.8-1
- fix memory leaks
- New option --debug-gc
- Python3 compatibility
- Better non-ascii support
- several firewall-config & firewall-applet fixes
- New --remove-rules commands for firewall-cmd and removeRules methods for D-Bus
- Fixed FirewallDirect.get_rules to return proper list
- Fixed LastUpdatedOrderedDict.keys()
- Enable rich rule usage in trusted zone (RHBZ#994144)
- New error codes: INVALID_CONTEXT, INVALID_COMMAND, INVALID_USER and INVALID_UID

* Thu Oct 17 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.7-1
- Don't fail on missing ip[6]tables/ebtables table. (RHBZ#967376)
- bash-completion: --permanent --direct options
- firewall/core/fw.py: fix checking for iptables & ip6tables (RHBZ#1017087)
- firewall-cmd: use client's exception_handler instead of catching exceptions ourselves
- FirewallClientZoneSettings: fix {add|remove|query}RichRule()
- Extend amanda-client service with 10080/tcp (RHBZ#1016867)
- Simplify Rich_Rule()_lexer() by using functions.splitArgs()
- Fix encoding problems in exception handling (RHBZ#1015941)

* Fri Oct 04 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.6.2-1
- firewall-offline-cmd: --forward-port 'toaddr' is optional (RHBZ#1014958)
- firewall-cmd: fix variable name (RHBZ#1015011)

* Thu Oct 03 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.6.1-1
- remove superfluous po files from archive

* Wed Oct 02 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.6-1
- firewalld.richlanguage.xml: correct log levels (RHBZ#993740)
- firewall-config: Make sure that all zone settings are updated properly on firewalld restart
- Rich_Limit: Allow long representation for duration (RHBZ#994103
- firewall-config: Show "Changes applied." after changes (RHBZ#993643)
- Use own connection dialog to change zones for NM connections
- Rename service cluster-suite to high-availability (RHBZ#885257)
- Permanent direct support for firewall-config and firewall-cmd
- Try to avoid file descriptor leaking (RHBZ#951900)
- New functions to split and join args properly (honoring quotes)
- firewall-cmd(1): 2 simple examples
- Better IPv6 NAT checking.
- Ship firewalld.direct(5).

* Mon Sep 30 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.5-1
- Only use one PK action for configuration (RHBZ#994729)
- firewall-cmd: indicate non-zero exit code with red color
- rich-rule: enable to have log without prefix & log_level & limit
- log-level warn/err -> warning/error (RHBZ#1009436)
- Use policy DROP while reloading, do not reset policy in restart twice
- Add _direct chains to all table and chain combinations
- documentation improvements
- New firewalld.direct(5) man page docbook source
- tests/firewall-cmd_test.sh: make rich language tests work
- Rich_Rule._import_from_string(): improve error messages (RHBZ#994150)
- direct.passthrough wasn't always matching out_signature (RHBZ#967800)
- firewall-config: twist ICMP Type IP address family logic.
- firewall-config: port-forwarding/masquerading dialog (RHBZ#993658)
- firewall-offline-cmd: New --remove-service=<service> option (BZ#969106)
- firewall-config: Options->Lockdown was not changing permanent.
- firewall-config: edit line on doubleclick (RHBZ#993572)
- firewall-config: System Default Zone -> Default Zone (RHBZ#993811)
- New direct D-Bus interface, persistent direct rule handling, enabled passthough
- src/firewall-cmd: Fixed help output to use more visual parameters
- src/firewall-cmd: New usage output, no redirection to man page anymore
- src/firewall/core/rich.py: Fixed forwad port destinations
- src/firewall-offline-cmd: Early enable/disable handling now with mask/unmask
- doc/xml/firewalld.zone.xml: Added more information about masquerade use
- Prefix to log message is optional (RHBZ#998079)
- firewall-cmd: fix --permanent --change-interface (RHBZ#997974)
- Sort zones/interfaces/service/icmptypes on output.
- wbem-https service (RHBZ#996668)
- applet&config: add support for KDE NetworkManager connection editor
- firewall/core/fw_config.py: New method update_lockdown_whitelist
- Added missing file watcher for lockdown whitelist in config D-Bus interface
- firewall/core/watcher: New add_watch_file for lockdown-whitelist and direct
- Make use of IPv6 NAT conditional, based on kernel number (RHBZ#967376)

* Tue Jul 30 2013 Thomas Woerner <twoerner@redhat.com> 0.3.4-1
- several rich rule check enhancements and fixes
- firewall-cmd: direct options - check ipv4|ipv6|eb (RHBZ#970505)
- firewall-cmd(1): improve description of direct options (RHBZ#970509)
- several firewall-applet enhancements and fixes
- New README
- several doc and man page fixes
- Service definitions for PCP daemons (RHBZ#972262)
- bash-completion: add lockdown and rich language options
- firewall-cmd: add --permanent --list-all[-zones]
- firewall-cmd: new -q/--quiet option
- firewall-cmd: warn when default zone not active (RHBZ#971843)
- firewall-cmd: check priority in --add-rule (RHBZ#914955)
- add dhcpv6 (for server) service (RHBZ#917866)
- firewall-cmd: add --permanent --get-zone-of-interface/source --change-interface/source
- firewall-cmd: print result (yes/no) of all --query-* commands
- move permanent-getZoneOf{Interface|Source} from firewall-cmd to server
- Check Interfaces/sources when updating permanent zone settings.
- FirewallDConfig: getZoneOfInterface/Source can actually return more zones
- Fixed toaddr check in forward port to only allow single address, no range
- firewall-cmd: various output improvements
- fw_zone: use check_single_address from firewall.functions
- getZoneOfInterface/Source does not need to throw exception
- firewall.functions: Use socket.inet_pton in checkIP, fixed checkIP*nMask
- firewall.core.io.service: Properly check port/proto and destination address
- Install applet desktop file into /etc/xdg/autostart
- Fixed option problem with rich rule destinations (RHBZ#979804)
- Better exception creation in dbus_handle_exceptions() decorator (RHBZ#979790)
- Updated firewall-offline-cmd
- Use priority in add, remove, query and list of direct rules (RHBZ#979509)
- New documentation (man pages are created from docbook sources)
- firewall/core/io/direct.py: use prirority for rule methods, new get_all_ methods
- direct: pass priority also to client.py and firewall-cmd
- applet: New blink and blink-count settings
- firewall.functions: New function ppid_of_pid
- applet: Check for gnome3 and fix it, use new settings, new size-changed cb
- firewall-offline-cmd: Fix use of systemctl in chroot
- firewall-config: use string.ascii_letters instead of string.letters
- dbus_to_python(): handle non-ascii chars in dbus.String.
- Modernize old syntax constructions.
- dict.keys() in Python 3 returns a "view" instead of list
- Use gettext.install() to install _() in builtins namespace.
- Allow non-ascii chars in 'short' and 'description'
- README: More information for "Working With The Source Repository"
- Build environment fixes
- firewalld.spec: Added missing checks for rhel > 6 for pygobject3-base
- firewall-applet: New setting show-inactive
- Don't stop on reload when lockdown already enabled (RHBZ#987403)
- firewall-cmd: --lockdown-on/off did not touch firewalld.conf
- FirewallApplet.gschema.xml: Dropped unused sender-info setting
- doc/firewall-applet.xml: Added information about gsettings
- several debug and log message fixes
- Add chain for sources so they can be checked before interfaces (RHBZ#903222)
- Add dhcp and proxy-dhcp services (RHBZ#986947)
- io/Zone(): don't error on deprecated family attr of source elem
- Limit length of zone file name (to 12 chars) due to Netfilter internals.
- It was not possible to overload a zone with defined source(s).
- DEFAULT_ZONE_TARGET: {chain}_ZONE_{zone} -> {chain}_{zone}
- New runtime get<X>Settings for services and icmptypes, fixed policies callbacks
- functions: New functions checkUser, checkUid and checkCommand
- src/firewall/client: Fixed lockdown-whitelist-updated signal handling
- firewall-cmd(1): move firewalld.richlanguage(5) reference in --*-rich-rule
- Rich rule service: Only add modules for accept action
- firewall/core/rich: Several fixes and enhanced checks
- Fixed reload of direct rules
- firewall/client: New functions to set and get the exception handler
- firewall-config: New and enhanced UI to handle lockdown and rich rules
- zone's immutable attribute is redundant
- Do not allow to set settings in config for immutable zones.
- Ignore deprecated 'immutable' attribute in zone files.
- Eviscerate 'immutable' completely.
- FirewallDirect.query_rule(): fix it
- permanent direct: activate firewall.core.io.direct:Direct reader
- core/io/*: simplify getting of character data
- FirewallDirect.set_config(): allow reloading

* Thu Jun 20 2013  Jiri Popelka <jpopelka@redhat.com>
- Remove migrating to a systemd unit file from a SysV initscript
- Remove pointless "ExclusiveOS" tag

* Fri Jun  7 2013 Thomas Woerner <twoerner@redhat.com> 0.3.3-2
- Fixed rich rule check for use in D-Bus

* Thu Jun  6 2013 Thomas Woerner <twoerner@redhat.com> 0.3.3-1
- new service files
- relicensed logger.py under GPLv2+
- firewall-config: sometimes we don't want to use client's exception handler
- When removing Service/IcmpType remove it from zones too (RHBZ#958401)
- firewall-config: work-around masquerade_check_cb() being called more times
- Zone(IO): add interfaces/sources to D-Bus signature
- Added missing UNKNOWN_SOURCE error code
- fw_zone.check_source: Raise INVALID_FAMILY if family is invalid
- New changeZoneOfInterface method, marked changeZone as deprecated
- Fixed firewall-cmd man page entry for --panic-on
- firewall-applet: Fixed possible problems of unescaped strings used for markup
- New support to bind zones to source addresses and ranges (D-BUS, cmd, applet
- Cleanup of unused variables in FirewallD.start
- New firewall/fw_types.py with LastUpdatedOrderedDict
- direct.chains, direct.rules: Using LastUpdatedOrderedDict
- Support splitted zone files
- New reader and writer for stored direct chains and rules
- LockdownWhitelist: fix write(), add get_commands/uids/users/contexts()
- fix service_writer() and icmptype_writer() to put newline at end of file
- firewall-cmd: fix --list-sources
- No need to specify whether source address family is IPv4 or IPv6
- add getZoneOfSource() to D-Bus interface
- Add tests and bash-completion for the new "source" operations
- Convert all input args in D-Bus methods
- setDefaultZone() was calling accessCheck() *after* the action
- New uniqify() function to remove duplicates from list whilst preserving order
- Zone.combine() merge also services and ports
- config/applet: silence DBusException during start when FirewallD is not running (RHBZ#966518)
- firewall-applet: more fixes to make the address sources family agnostic
- Better defaults for lockdown white list
- Use auth_admin_keep for allow_any and allow_inactive also
- New D-Bus API for lockdown policies
- Use IPv4, IPv6 and BRIDGE for FirewallD properties
- Use rich rule action as audit type
- Prototype of string-only D-Bus interface for rich language
- Fixed wrongly merged source family check in firewall/core/io/zone.py
- handle_cmr: report errors, cleanup modules in error case only, mark handling
- Use audit type from rule action, fixed rule output
- Fixed lockdown whitelist D-Bus handling method names
- New rich rule handling in runtime D-Bus interface
- Added interface, source and rich rule handling (runtime and permanent)
- Fixed dbus_obj in FirewallClientConfigPolicies, added queryLockdown
- Write changes in setLockdownWhitelist
- Fixed typo in policies log message in method calls
- firewall-cmd: Added rich rule, lockdown and lockdown whitelist handling
- Don't check access in query/getLockdownWhitelist*()
- firewall-cmd: Also output masquerade flag in --list-all
- firewall-cmd: argparse is able to convert argument to desired type itself
- firewall-cmd_test.sh: tests for permanent interfaces/sources and lockdown whitelist
- Makefile.am: add missing files
- firewall-cmd_test.sh: tests for rich rules
- Added lockdown, source, interface and rich rule docs to firewall-cmd
- Do not masquerade lo if masquerade is enabled in the default zone (RHBZ#904098)
- Use <rule> in metavar for firewall-cmd parser

* Fri May 10 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.2-2
- removed unintentional en_US.po from tarball

* Tue Apr 30 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.2-1
- Fix signal handling for SIGTERM
- Additional service files (RHBZ#914859)
- Updated po files
- s/persistent/permanent/ (Trac Ticket #7)
- Better behaviour when running without valid DISPLAY (RHBZ#955414)
- client.handle_exceptions(): do not loop forever
- Set Zone.defaults in zone_reader (RHBZ#951747)
- client: do not pass the dbus exception name to handler
- IO_Object_XMLGenerator: make it work with Python 2.7.4 (RHBZ#951741)
- firewall-cmd: do not use deprecated BaseException.message
- client.py: fix handle_exceptions() (RHBZ#951314)
- firewall-config: check zone/service/icmptype name (RHBZ#947820)
- Allow 3121/tcp (pacemaker_remote) in cluster-suite service. (RHBZ#885257)
- firewall-applet: fix default zone hangling in 'shields-up' (RHBZ#947230)
- FirewallError.get_code(): check for unknown error

* Wed Apr 17 2013 Jiri Popelka <jpopelka@redhat.com> - 0.3.1-2
- Make permanenent changes work with Python 2.7.4 (RHBZ#951741)

* Thu Mar 28 2013 Thomas Woerner <twoerner@redhat.com> 0.3.1-1
- Use explicit file lists for make dist
- New rich rule validation check code
- New global check_port and check_address functions
- Allow source white and black listing with the rich rule
- Fix error handling in case of unsupported family in rich rule
- Enable ip_forwarding in masquerade and forward-port
- New functions to read and write simple files using filename and content
- Add --enable-sysconfig to install Fedora-specific sysconfig config file.
- Add chains for security table (RHBZ#927015)
- firewalld.spec: no need to specify --with-systemd-unitdir
- firewalld.service: remove syslog.target and dbus.target
- firewalld.service: replace hard-coded paths
- Move bash-completion to new location.
- Revert "Added configure for new build env"
- Revert "Added Makefile.in files"
- Revert "Added po/Makefile.in.in"
- Revert "Added po/LINGUAS"
- Revert "Added aclocal.m4"
- Amend zone XML Schema

* Wed Mar 20 2013 Thomas Woerner <twoerner@redhat.com> 0.3.0-1
- Added rich language support
- Added lockdown feature
- Allow to bind interfaces and sources to zones permanently
- Enabled IPv6 NAT support
  masquerading and port/packet forwarding for IPv6 only with rich language
- Handle polkit errors in client class and firewall-config
- Added priority description for --direct --add-rule in firewall-cmd man page
- Add XML Schemas for zones/services/icmptypes XMLs
- Don't keep file descriptors open when forking
- Introduce --nopid option for firewalld
- New FORWARD_IN_ZONES and FORWARD_OUT_ZONES chains (RHBZ#912782)
- Update cluster-suite service (RHBZ#885257)
- firewall-cmd: rename --enable/disable-panic to --panic-on/off (RHBZ#874912)
- Fix interaction problem of changed event of gtk combobox with polkit-kde
  by processing all remaining events (RHBZ#915892)
- Stop default zone rules being applied to all zones (RHBZ#912782)
- Firewall.start(): don't call set_default_zone()
- Add wiki's URL to firewalld(1) and firewall-cmd(1) man pages
- firewalld-cmd: make --state verbose (RHBZ#886484)
- improve firewalld --help (RHBZ#910492)
- firewall-cmd: --add/remove-* can be used multiple times (RHBZ#879834)
- Continue loading zone in case of wrong service/port etc. (RHBZ#909466)
- Check also services and icmptypes in Zone() (RHBZ#909466)
- Increase the maximum length of the port forwarding fields from 5 to 11 in
  firewall-config
- firewall-cmd: add usage to fail message
- firewall-cmd: redefine usage to point to man page
- firewall-cmd: fix visible problems with arg. parsing
- Use argparse module for parsing command line options and arguments
- firewall-cmd.1: better clarify where to find ACTIONs
- firewall-cmd Bash completion
- firewall-cmd.1: comment --zone=<zone> usage and move some options
- Use zone's target only in %s_ZONES chains
- default zone in firewalld.conf was set to public with every restart (#902845)
- man page cleanup
- code cleanup

* Thu Mar 07 2013 Jiri Popelka <jpopelka@redhat.com> - 0.2.12-5
- Another fix for RHBZ#912782

* Wed Feb 20 2013 Jiri Popelka <jpopelka@redhat.com> - 0.2.12-4
- Stop default zone rules being applied to all zones (RHBZ#912782)

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.2.12-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Tue Jan 22 2013 Jiri Popelka <jpopelka@redhat.com> - 0.2.12-2
- Default zone in firewalld.conf was reseted with every restart (RHBZ#902845)
- Add icon cache related scriptlets for firewall-config (RHBZ#902680)
- Fix typo in firewall-config (RHBZ#895812)
- Fix few mistakes in firewall-cmd(1) man page

* Mon Jan 14 2013 Thomas Woerner <twoerner@redhat.com> 0.2.12-1
- firewall-cmd: use -V instead of -v for version info (RHBZ#886477)
- firewall-cmd: don't check reload()'s return value (RHBZ#886461)
- actually install firewalld.zones.5
- firewall-config: treat exceptions when adding new zone/service/icmp
  (RHBZ#886602)
- firewalld.spec: Fixed requirements of firewall-config to use gtk2 and
  pygobject3
- Fail gracefully when running in non X environment.(RHBZ#886551)
- offline-cmd: fail gracefully when no s-c-f config
- fix duplicated iptables rules (RHBZ#886515)
- detect errors and duplicates in config file (RHBZ#886581)
- firewall-config: don't make 'Edit Service' and 'Edit ICMP Type' insensitive
- firewalld.spec: fixed requirements, require pygobject3-base
- frewall-applet: Unused code cleanup
- firewall-applet: several usability fixes and enhancements
  (RHBZ#886531) (RHBZ#886534)
- firewall/server/server.py: fixed KeyboardInterrupt message (RHBZ#886558)
- Moved fallback zone and minimal_mark to firewall.config.__init__
- Do not raise ZONE_ALREADY_SET in change_zone if old zone is set again
  (RHBZ#886432)
- Make default zone default for all unset connections/interfaces
  (RHBZ#888288) (RHBZ#882736)
- firewall-config: Use Gtk.MessageType.WARNING for warning dialog
- firewall-config: Handle unknown services and icmptypes in persistent mode
- firewall-config: Do not load settings more than once
- firewall-config: UI cleanup and fixes (RHBZ#888242)
- firewall-cmd: created alias --change-zone for --change-interface
- firewall-cmd man page updates (RHBZ#806511)
- Merged branch 'build-cleanups'
- dropped call to autogen.sh in build stage, not needed anymore due to 
  'build-cleanups' merge

* Thu Dec 13 2012 Thomas Woerner <twoerner@redhat.com> 0.2.11-2
- require pygobject3-base instead of pygobject3 (no cairo needed) (RHBZ#874378)
- fixed dependencies of firewall-config to use gtk3 with pygobject3-base and 
  not pygtk2

* Tue Dec 11 2012 Thomas Woerner <twoerner@redhat.com> 0.2.11-1
- Fixed more _xmlplus (PyXML) incompatibilities to python xml
- Several man page updates
- Fixed error in addForwardPort, removeForwardPort and queryForwardPort
- firewall-cmd: use already existing queryForwardPort()
- Update firewall.cmd man page, use man page as firewall-cmd usage (rhbz#876394)
- firewall-config: Do not force to show labels in the main toolbar
- firewall-config: Dropped "Change default zone" from toolbar
- firewall-config: Added menu entry to change zones of connections
- firewall-applet: Zones can be changed now using nm-connection-editor
  (rhbz#876661)
- translation updates: cs, hu, ja

* Tue Nov 20 2012 Thomas Woerner <twoerner@redhat.com> 0.2.10-1
- tests/firewalld_config.py: tests for config.service and config.icmptype
- FirewallClientConfigServiceSettings(): destinations are dict not list
- service/zone/icmptype: do not write deprecated name attribute
- New service ntp
- firewall-config: Fixed name of about dialog
- configure.in: Fixed getting of error codes
- Added coding to all pyhton files
- Fixed copyright years
- Beautified file headers
- Force use of pygobject3 in python-slip (RHBZ#874378)
- Log: firewall.server.config_icmptype, firewall.server.config_service and
  firewall.server.config_zone: Prepend full path
- Allow ":" in interface names for interface aliases
- Add name argument to Updated and Renamed signal
- Disable IPv4, IPv6 and EB tables if missing - for IPv4/IPv6 only environments
- firewall-config.glade file cleanup
- firewall-config: loadDefaults() can throw exception
- Use toolbars for Add/Edit/Remove/LoadDefaults buttons for zones, services
  and icmp types
- New vnc-server service, opens ports for displays :0 to :3 (RHBZ#877035)
- firewall-cmd: Fix typo in help output, allow default zone usage for
  permanenent options
- Translation updates: cs, fr, ja, pt_BR and zh_CN

* Wed Oct 17 2012 Thomas Woerner <twoerner@redhat.com> 0.2.9-1
- firewall-config: some UI usability changes
- firewall-cmd: New option --list-all-zones, output of --list-all changed,
  more option combination checks
- firewall-applet: Replaced NMClient by direct DBUS calls to fix python core
  dumps in case of connection activates/deactivates
- Use fallback 'C' locale if current locale isn't supported (RHBZ#860278)
- Add interfaces to zones again after reload
- firewall-cmd: use FirewallClient().connected value
- firewall-cmd: --remove-interface was not working due to a typo
- Do not use restorecon for new and backup files
- Fixed use of properties REJECT and DROP
- firewalld_test.py: check interfaces after reload
- Translation updates
- Renamed firewall-convert-scfw-config to firewall-offline-cmd, used by
  anaconda for firewall configuration (e.g. kickstart)
- Fix python shebang to use -Es at installation time for bin_SCRIPTS and
  sbin_SCRIPTS and at all times in gtk3_chooserbutton.py
- tests/firewalld_config.py: update test_zones() test case
- Config interface: improve renaming of zones/services/icmp_types
- Move emiting of Added signals closer to source.
- FirewallClient(): config:ServiceAdded signal was wrongly mapped
- Add argument 'name' to Removed signal
- firewall-config: Add callbacks for config:[service|icmp]-[added|removed]
- firewall-config: catch INVALID_X error when removing zone/service/icmp_type
- firewall-config: remove unused code
- Revert "Neutralize _xmlplus instead of conforming it"
- firewall-applet: some UI usability changes
- firewall-cmd: ALREADY_ENABLED, NOT_ENABLED, ZONE_ALREADY_SET are warnings

* Fri Sep  7 2012 Thomas Woerner <twoerner@redhat.com> 0.2.8-1
- Do not apply old settings to zones after reload
- FirewallClient: Added callback structure for firewalld signals
- New firewall-config with full zone, service and icmptype support
- Added Shields Up/Down configuration dialog to firewall-applet
- Name attribute of main tag deprecated for zones, services and icmptypes,
  will be ignored if present
- Fixed wrong references in firewalld man page
- Unregister DBus interfaces after sending out the Removed signal
- Use proper DBus signature in addIcmpType, addService and addZone
- New builtin property for config interfaces
- New test case for Config interface
- spec: use new systemd-rpm macros (rhbz#850110)
- More config file verifications
- Lots of smaller fixes and enhancements

* Tue Aug 21 2012 Jiri Popelka <jpopelka@redhat.com> 0.2.7-2
- use new systemd-rpm macros (rhbz#850110)

* Mon Aug 13 2012 Thomas Woerner <twoerner@redhat.com> 0.2.7-1
- Update of firewall-config
- Some bug fixes

* Tue Aug  7 2012 Thomas Woerner <twoerner@redhat.com> 0.2.6-1
- New D-BUS interface for persistent configuration
- Aded support for persistent zone configuration in firewall-cmd
- New Shields Up feature in firewall-applet
- New requirements for python-decorator and pygobject3
- New firewall-config sub-package
- New firewall-convert-scfw-config config script

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
