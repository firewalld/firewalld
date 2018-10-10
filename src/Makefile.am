SUBDIRS = icons tests

dist_bin_SCRIPTS_in = firewall-applet.in firewall-cmd.in firewall-offline-cmd.in firewall-config.in
dist_sbin_SCRIPTS_in = firewalld.in

dist_bin_SCRIPTS = $(dist_bin_SCRIPTS_in:.in=)
dist_sbin_SCRIPTS = $(dist_sbin_SCRIPTS_in:.in=)

gladedir = $(pkgdatadir)
dist_glade_DATA = firewall-config.glade

gtkextradir = $(pkgdatadir)
dist_gtkextra_DATA = gtk3_chooserbutton.py gtk3_niceexpander.py

nobase_dist_python_DATA = \
	firewall/client.py \
	firewall/command.py \
	firewall/config/dbus.py \
	firewall/config/__init__.py \
	firewall/core/base.py \
	firewall/core/ebtables.py \
	firewall/core/fw_config.py \
	firewall/core/fw_direct.py \
	firewall/core/fw_helper.py \
	firewall/core/fw_icmptype.py \
	firewall/core/fw_ifcfg.py \
	firewall/core/fw_ipset.py \
	firewall/core/fw_nm.py \
	firewall/core/fw_policies.py \
	firewall/core/fw.py \
	firewall/core/fw_service.py \
	firewall/core/fw_test.py \
	firewall/core/fw_transaction.py \
	firewall/core/fw_zone.py \
	firewall/core/helper.py \
	firewall/core/icmp.py \
	firewall/core/__init__.py \
	firewall/core/io/direct.py \
	firewall/core/io/firewalld_conf.py \
	firewall/core/io/functions.py \
	firewall/core/io/helper.py \
	firewall/core/io/icmptype.py \
	firewall/core/io/ifcfg.py \
	firewall/core/io/__init__.py \
	firewall/core/io/io_object.py \
	firewall/core/io/ipset.py \
	firewall/core/io/lockdown_whitelist.py \
	firewall/core/io/service.py \
	firewall/core/io/zone.py \
	firewall/core/ipset.py \
	firewall/core/ipXtables.py \
	firewall/core/logger.py \
	firewall/core/modules.py \
	firewall/core/nftables.py \
	firewall/core/prog.py \
	firewall/core/rich.py \
	firewall/core/watcher.py \
	firewall/dbus_utils.py \
	firewall/errors.py \
	firewall/functions.py \
	firewall/fw_types.py \
	firewall/__init__.py \
	firewall/server/config_helper.py \
	firewall/server/config_icmptype.py \
	firewall/server/config_ipset.py \
	firewall/server/config.py \
	firewall/server/config_service.py \
	firewall/server/config_zone.py \
	firewall/server/decorators.py \
	firewall/server/firewalld.py \
	firewall/server/__init__.py \
	firewall/server/server.py

EXTRA_DIST = \
	firewall/config/__init__.py.in \
	$(dist_bin_SCRIPTS_in) $(dist_sbin_SCRIPTS_in)

CLEANFILES = *~ *\# .\#* *.py?

FLAKE8_IGNORE = E121,E122,E123,E124,E126,E127,E128,E201,E202,E203,E211,E221,E222,E225,E226,E231,E241,E251,E261,E262,E265,E266,W291,W293,E301,E302,E303,E305,E306,W391,E402,E501,E502,W503,W504,E722,E741
check-local:
	find . -name '*.py' -or -name '*.py.in' |xargs flake8 --ignore="$(FLAKE8_IGNORE)"
	flake8 --ignore="$(FLAKE8_IGNORE)" $(dist_bin_SCRIPTS_in) $(dist_sbin_SCRIPTS_in)
	@echo
	@for file in $(filter-out $(EXTRA_DIST:.in=),$(nobase_dist_python_DATA) $(dist_bin_SCRIPTS_in) $(dist_sbin_SCRIPTS_in)); do \
		if ! grep "$${file}" ${top_srcdir}/po/POTFILES.in > /dev/null; then \
			echo "$${file} should be in ${abs_top_srcdir}/po/POTFILES.in"; \
			exit 1; \
		fi; \
	done
