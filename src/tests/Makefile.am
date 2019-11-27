TESTSUITE = $(srcdir)/testsuite
TESTSUITE_FILES = \
	$(wildcard $(srcdir)/*.at) \
	$(wildcard $(srcdir)/dbus/*.at) \
	$(wildcard $(srcdir)/features/*.at) \
	$(wildcard $(srcdir)/regression/*.at)

EXTRA_DIST = \
	$(TESTSUITE) \
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
$(TESTSUITE): $(TESTSUITE_FILES) $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

check-container:

.PHONY: check-container
