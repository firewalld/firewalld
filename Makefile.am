SUBDIRS = config doc po shell-completion src
DIST_TARGETS = dist-gzip

EXTRA_DIST = \
	CODE_OF_CONDUCT.md \
	COPYING \
	README.md \
	autogen.sh \
	${PACKAGE_NAME}.spec

CLEANFILES = *~ *\# .\#* *.tar*

DISTCLEANFILES = config.log intltool-*

DISTCLEANDIRS = autom4te.cache ${PACKAGE_NAME}-*

dist: clean-docs update-docs

dist-container:
	$(PODMAN) build --squash-all -t firewalld -f $(abs_top_srcdir)/Dockerfile $(abs_top_srcdir)
	$(PODMAN) tag firewalld firewalld:$(PACKAGE_VERSION)
	$(PODMAN) tag firewalld firewalld:latest
	$(PODMAN) tag firewalld:$(PACKAGE_VERSION) quay.io/firewalld/firewalld:$(PACKAGE_VERSION)
	$(PODMAN) tag firewalld:latest quay.io/firewalld/firewalld:latest
	$(PODMAN) push quay.io/firewalld/firewalld:$(PACKAGE_VERSION)
	$(PODMAN) push quay.io/firewalld/firewalld:latest
	$(PODMAN) save --format oci-archive --output firewalld-oci-$(PACKAGE_VERSION).tar firewalld:$(PACKAGE_VERSION)

check-container check-integration installcheck-integration:
	$(MAKE) -C src/tests $@

.PHONY: check-container check-integration installcheck-integration
.PHONY: dist-container

update-docs:
	$(MAKE) -C doc/xml

clean-docs:
	$(MAKE) -C doc/xml clean

rpm test-rpm: dist-gzip
	@rpmbuild -ta $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

srpm test-srpm: dist-gzip
	@rpmbuild -ts $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

update-po:
	ls $(top_srcdir)/po/*.po | sed 's/.*\/po\///;s/.po//' > $(top_srcdir)/po/LINGUAS
	$(MAKE) -C po update-po ${PACKAGE_NAME}.pot
	cp po/${PACKAGE_NAME}.pot po/${PACKAGE_NAME}.weblate.pot

# This merges translations from the upstream master branch.
# It's only meant to be used from the stable branches. Translations
# contributions are only done against master.
merge-po: update-po
	git fetch -q https://github.com/firewalld/firewalld master; \
	for po in $(top_srcdir)/po/*.po; do \
		mv $${po} $${po}.old; \
		git checkout -q FETCH_HEAD $${po}; \
		msgcat --use-first -o $${po}.merged $${po} $${po}.old; \
		mv $${po}.merged $${po}; \
		git add $${po}; \
	done

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
