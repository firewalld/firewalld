TESTSUITE = $(srcdir)/testsuite
TESTSUITE_INTEGRATION = $(srcdir)/integration/testsuite

TESTSUITE_FILES = \
	$(wildcard $(srcdir)/*.at) \
	$(wildcard $(srcdir)/cli/*.at) \
	$(wildcard $(srcdir)/dbus/*.at) \
	$(wildcard $(srcdir)/features/*.at) \
	$(wildcard $(srcdir)/integration/*.at) \
	$(wildcard $(srcdir)/python/*.at) \
	$(wildcard $(srcdir)/regression/*.at)

EXTRA_DIST = \
	$(TESTSUITE) \
	$(TESTSUITE_INTEGRATION) \
	$(TESTSUITE_FILES) \
	$(wildcard $(srcdir)/python/*.py) \
	$(wildcard $(srcdir)/unit/*.py) \
	$(srcdir)/package.m4 \
	atlocal.in

DISTCLEANFILES = \
	$(TESTSUITE) \
	$(TESTSUITE_INTEGRATION) \
	atconfig

testsuitedir = $(pkgdatadir)/testsuite
dist_testsuite_SCRIPTS = $(TESTSUITE)
dist_testsuite_DATA = README.md

testsuite_integrationdir = $(pkgdatadir)/testsuite/integration
dist_testsuite_integration_SCRIPTS = $(TESTSUITE_INTEGRATION)

testsuite_pythondir = $(pkgdatadir)/testsuite/python
dist_testsuite_python_DATA = python/*.py

$(srcdir)/package.m4: $(top_srcdir)/configure.ac $(top_srcdir)/firewalld.spec $(srcdir)/Makefile
	:;{ \
	echo 'm4_define([AT_PACKAGE_NAME],[$(PACKAGE_NAME)])' && \
	echo 'm4_define([AT_PACKAGE_VERSION],[$(PACKAGE_VERSION)])' && \
	echo 'm4_define([AT_PACKAGE_STRING],[$(PACKAGE_STRING)])' && \
	echo 'm4_define([AT_PACKAGE_URL],[http://firewalld.org/])' && \
	echo 'm4_define([AT_PACKAGE_BUGREPORT],[https://github.com/firewalld/firewalld])' ; \
	} > "$@"

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS) \
		AUTOTEST_PATH="src" \
		PYTHONPATH="${abs_top_srcdir}/src:${PYTHONPATH}" \
		FIREWALLD_DEFAULT_CONFIG="${abs_top_srcdir}/config"

installcheck-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' --clean
	-rm $(srcdir)/package.m4

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE) $(TESTSUITE_INTEGRATION): $(TESTSUITE_FILES) $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

CONTAINER_TARGETS = check-container-debian-sid \
                    check-container-fedora-rawhide \
                    check-container-centos8-stream \
                    check-container-centos9-stream

check-container-debian-sid-image: check-container-%-image:
	(cd $(abs_top_srcdir) && { \
	echo "FROM debian:sid" && \
	echo "RUN apt-get update" && \
	echo "RUN apt-get install -y autoconf automake pkg-config intltool libglib2.0-dev \
	                             xsltproc docbook-xsl docbook-xml iproute2 iptables ipset ebtables \
	                             nftables libxml2-utils libdbus-1-dev libgirepository1.0-dev \
	                             python3-dbus python3-gi python3-nftables \
	                             procps network-manager gir1.2-nm-1.0 time" && \
	echo "COPY . /tmp/firewalld"; \
	} | $(PODMAN) build -t firewalld-testsuite-$* -f - . )

check-container-fedora-rawhide-image: check-container-%-image:
	(cd $(abs_top_srcdir) && { \
	echo "FROM fedora:rawhide" && \
	echo "RUN dnf -y makecache" && \
	echo "RUN dnf -y install autoconf automake conntrack-tools desktop-file-utils \
	                 docbook-style-xsl file gettext glib2-devel intltool ipset \
	                 iptables iptables-nft libtool libxml2 libxslt make nftables \
	                 python3-nftables python3-gobject-base python3-dbus \
	                 diffutils procps-ng iproute which dbus-daemon \
	                 NetworkManager NetworkManager-ovs time" && \
	echo "RUN alternatives --set ebtables /usr/sbin/ebtables-nft" && \
	echo "COPY . /tmp/firewalld"; \
	} | $(PODMAN) build -t firewalld-testsuite-$* -f - . )

check-container-centos8-stream-image: check-container-%-image:
	(cd $(abs_top_srcdir) && { \
	echo "FROM centos:stream8" && \
	echo "RUN dnf -y makecache" && \
	echo "RUN dnf -y install autoconf automake conntrack-tools desktop-file-utils \
	                 docbook-style-xsl file gettext glib2-devel intltool ipset \
	                 iptables iptables-ebtables nftables libtool libxml2 \
	                 libxslt make nftables python3-nftables python3-dbus \
	                 python3-gobject-base diffutils procps-ng iproute which dbus-daemon \
	                 NetworkManager NetworkManager-ovs time" && \
	echo "COPY . /tmp/firewalld"; \
	} | $(PODMAN) build -t firewalld-testsuite-$* -f - . )

check-container-centos9-stream-image: check-container-%-image:
	(cd $(abs_top_srcdir) && { \
	echo "FROM centos:stream9" && \
	echo "RUN dnf -y makecache" && \
	echo "RUN dnf -y install autoconf automake conntrack-tools desktop-file-utils \
	                 docbook-style-xsl file gettext glib2-devel intltool ipset \
	                 iptables-nft nftables libtool libxml2 \
	                 libxslt make nftables python3-nftables python3-dbus \
	                 python3-gobject-base diffutils procps-ng iproute which dbus-daemon \
	                 NetworkManager NetworkManager-ovs time" && \
	echo "COPY . /tmp/firewalld"; \
	} | $(PODMAN) build -t firewalld-testsuite-$* -f - . )

check-container-debian-sid: PYTHON=/usr/bin/python3
check-container-fedora-rawhide: PYTHON=/usr/bin/python3
check-container-centos8-stream: PYTHON=/usr/libexec/platform-python
check-container-centos9-stream: PYTHON=/usr/libexec/platform-python
$(CONTAINER_TARGETS): check-container-%: check-container-%-image
	$(PODMAN) run -i --rm --privileged firewalld-testsuite-$* bash -c " \
	cd /tmp/firewalld && \
	./autogen.sh && \
	./configure PYTHON=\"${PYTHON}\" && \
	make && \
	{ make -C src/tests check-local TESTSUITEFLAGS=\"$(TESTSUITEFLAGS)\" || \
	  make -C src/tests check-local TESTSUITEFLAGS=\"--recheck --errexit --verbose\" ; } && \
	make -C src/tests check-integration TESTSUITEFLAGS=\"$(TESTSUITEFLAGS)\" "
	$(PODMAN) rmi firewalld-testsuite-$*

check-container: $(CONTAINER_TARGETS)

.PHONY: check-container
.PHONY: $(CONTAINER_TARGETS) $(foreach container,$(CONTAINER_TARGETS),$(container)-image)

check-integration: atconfig atlocal $(TESTSUITE_INTEGRATION)
	$(SHELL) '$(TESTSUITE_INTEGRATION)' $(TESTSUITEFLAGS) -j1 \
		AUTOTEST_PATH="src" \
		PYTHONPATH="${abs_top_srcdir}/src:${PYTHONPATH}" \
		FIREWALLD_DEFAULT_CONFIG="${abs_top_srcdir}/config"

installcheck-integration: atconfig atlocal $(TESTSUITE_INTEGRATION)
	$(SHELL) '$(TESTSUITE_INTEGRATION)' $(TESTSUITEFLAGS) -j1

.PHONY: check-integration installcheck-integration
