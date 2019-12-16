TESTSUITE = $(srcdir)/testsuite
TESTSUITE_INTEGRATION = $(srcdir)/integration/testsuite

TESTSUITE_FILES = \
	$(wildcard $(srcdir)/*.at) \
	$(wildcard $(srcdir)/dbus/*.at) \
	$(wildcard $(srcdir)/features/*.at) \
	$(wildcard $(srcdir)/integration/*.at) \
	$(wildcard $(srcdir)/regression/*.at)

EXTRA_DIST = \
	$(TESTSUITE) \
	$(TESTSUITE_INTEGRATION) \
	$(TESTSUITE_FILES) \
	$(wildcard $(srcdir)/python/*.py) \
	$(srcdir)/package.m4 \
	atlocal.in

DISTCLEANFILES = atconfig

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

check-container-debian-sid:
	(cd $(abs_top_srcdir) && tar -c . ) | \
	$(PODMAN) run -i --rm --privileged debian:sid bash -c \
	"mkdir -p /tmp/firewalld && cd /tmp/firewalld && tar -x && \
	apt-get update && \
	apt-get install -y autoconf automake pkg-config intltool libglib2.0-dev \
	                   xsltproc docbook-xsl docbook-xml iptables ipset ebtables \
	                   nftables libxml2-utils libdbus-1-dev libgirepository1.0-dev \
	                   python3-dbus python3-gi python3-slip-dbus python3-nftables \
	                   procps && \
	apt-get install -y libnftables-dev && \
	./autogen.sh && \
	./configure PYTHON=/usr/bin/python3 && \
	make && \
	make -C src/tests check-local TESTSUITEFLAGS=\"$(TESTSUITEFLAGS)\" "

check-container-fedora-rawhide:
	(cd $(abs_top_srcdir) && tar -c . ) | \
	$(PODMAN) run -i --rm --privileged fedora:rawhide bash -c \
	"mkdir -p /tmp/firewalld && cd /tmp/firewalld && tar -x && \
	dnf -y makecache && \
	dnf -y install autoconf automake conntrack-tools desktop-file-utils \
	               docbook-style-xsl file gettext glib2-devel intltool ipset \
	               iptables iptables-nft libtool libxml2 libxslt make nftables \
	               python3-nftables python3-slip-dbus python3-gobject-base \
	               diffutils procps-ng iproute which dbus-daemon && \
	alternatives --set ebtables /usr/sbin/ebtables-nft && \
	./autogen.sh && \
	./configure PYTHON=/usr/bin/python3 && \
	make && \
	make -C src/tests check-local TESTSUITEFLAGS=\"$(TESTSUITEFLAGS)\" "

check-container: check-container-debian-sid
check-container: check-container-fedora-rawhide

.PHONY: check-container
.PHONY: check-container-debian-sid
.PHONY: check-container-fedora-rawhide

check-integration: atconfig atlocal $(TESTSUITE_INTEGRATION)
	$(SHELL) '$(TESTSUITE_INTEGRATION)' $(TESTSUITEFLAGS) \
		AUTOTEST_PATH="src" \
		PYTHONPATH="${abs_top_srcdir}/src:${PYTHONPATH}" \
		FIREWALLD_DEFAULT_CONFIG="${abs_top_srcdir}/config"

installcheck-integration: atconfig atlocal $(TESTSUITE_INTEGRATION)
	$(SHELL) '$(TESTSUITE_INTEGRATION)' $(TESTSUITEFLAGS)

.PHONY: check-integration installcheck-integration
