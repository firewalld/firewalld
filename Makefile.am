SUBDIRS = config doc po shell-completion src
DIST_TARGETS = dist-gzip

EXTRA_DIST = \
	COPYING \
	README \
	autogen.sh \
	${PACKAGE_NAME}.spec \
	fix_python_shebang.sh

CLEANFILES = *~ *\# .\#* *.tar*

DISTCLEANFILES = config.log intltool-*

DISTCLEANDIRS = autom4te.cache ${PACKAGE_NAME}-*

all: report

tag:
	@spec_ver=`awk '/Version:/ { print $$2}' ${PACKAGE_NAME}.spec`; \
	if test "$$spec_ver" != "${PACKAGE_VERSION}"; then \
		echo "Spec file and package versions differ: $$spec_ver != ${PACKAGE_VERSION}"; \
		secs=10; \
		echo -n "Using ./autogen.sh in $$secs seconds: "; \
		for i in `seq $$secs -1 1`; do echo -n "."; sleep 1; done; echo; \
		./autogen.sh; \
		echo; \
		echo "Please run make again to apply version changes."; \
		exit 1; \
	fi
	@if ! git diff --quiet --exit-code; then \
		clear; \
		echo -n "========================================"; \
		echo "========================================"; \
		PAGER= git diff; \
		echo -n "========================================"; \
		echo "========================================"; \
		echo "Do you want to commit these changes? (y/N)"; \
		read answer; \
		[ "$$answer" == "Y" -o "$$answer" == "y" ] || exit 1; \
		git commit -a -m "$(PACKAGE_TAG)"; \
	fi
	git tag -f $(PACKAGE_TAG)
	git push
	git push --tags

dist: clean-docs update-docs

dist-check:
	@rm -f _dist_check_failed
	@(cat config/Makefile.am | sed -n '/^CONFIG_FILES/,/^$$/p' | head -n-1 | tail -n+2) > _config
	@(cd config; git ls-files icmptypes helpers ipsets services zones | sort | sed -e 's/^/\t/' | sed ':a;N;$$!ba;s/\n/ \\\n/g') > _provided_config
	@diff -u1B _config _provided_config > _missing_config; \
	if [ $$? -ne 0 ]; then \
		echo; \
		echo "============================================================================="; \
		echo "    Fix config/Makefile.am:"; \
		echo "============================================================================="; \
		touch _dist_check_failed; \
		cat _missing_config | tail -n +3; \
		echo; \
	fi
	@rm -f _config _provided_config _missing_config
	@(cat src/Makefile.am | sed -n '/^nobase_dist_python_DATA/,/^$$/p' | head -n-1 | tail -n+2) > _config
	@(cd src; git ls-files firewall | sort | sed -e 's/^/\t/' -e "s/.py.in/.py/" | sed ':a;N;$$!ba;s/\n/ \\\n/g') > _provided_config
	@diff -u1B _config _provided_config > _missing_config; \
	if [ $$? -ne 0 ]; then \
		echo; \
		echo "============================================================================="; \
		echo "    Fix src/Makefile.am:"; \
		echo "============================================================================="; \
		touch _dist_check_failed; \
		cat _missing_config | tail -n +3; \
		echo; \
	fi
	@rm -f _config _provided_config _missing_config
	@if [ -f "_dist_check_failed" ]; then \
		rm -f _dist_check_failed; \
		exit 1; \
	fi

update-docs:
	$(MAKE) -C doc/xml

clean-docs:
	$(MAKE) -C doc/xml clean

pull-translations:
	zanata-cli -B pull

push-translations:
	zanata-cli -B push

update-translations: pull-translations update-po push-translations 

archive: dist-check $(desktop_DATA) tag dist

local: distclean
	@rm -rf ${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.gz
	@rm -rf /tmp/${PACKAGE_NAME}-$(PACKAGE_VERSION) /tmp/${PACKAGE_NAME}
	@dir=$$PWD; cd /tmp; cp -a $$dir ${PACKAGE_NAME}
	@mv /tmp/${PACKAGE_NAME} /tmp/${PACKAGE_NAME}-$(PACKAGE_VERSION)
	@dir=$$PWD; cd /tmp; tar --gzip -cSpf $$dir/${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.gz ${PACKAGE_NAME}-$(PACKAGE_VERSION)
	@rm -rf /tmp/${PACKAGE_NAME}-$(PACKAGE_VERSION)	
	@echo "The archive is in ${PACKAGE_NAME}-$(PACKAGE_VERSION).tar.gz"

test-rpm: dist
	@rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

test-srpm: dist
	@rpmbuild -ts $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

update-po:
	ls $(top_srcdir)/po/*.po | sed 's/.*\/po\///;s/.po//' > $(top_srcdir)/po/LINGUAS
	$(MAKE) -C po update-po ${PACKAGE_NAME}.pot

clean-po:
	@for cat in `cat ${top_srcdir}/po/LINGUAS`; do \
		msgattrib --translated --no-fuzzy --no-obsolete --force-po --no-location --clear-previous --strict $(top_srcdir)/po/$$cat.po -o $(top_srcdir)/po/$$cat.out; \
		mv -f $(top_srcdir)/po/$$cat.out $(top_srcdir)/po/$$cat.po; \
	done

report:
	@for cat in `cat ${top_srcdir}/po/LINGUAS`; do \
		echo -n "$$cat: "; \
		$(MSGFMT) --statistics -o /dev/null $(top_srcdir)/po/$$cat.po; \
	done

distclean-local:
	-test -z "$(DISTCLEANDIRS)" || rm -rf $(DISTCLEANDIRS)
