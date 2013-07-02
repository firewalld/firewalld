# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])

m4_define([PKG_NAME], firewalld)
m4_define([PKG_VERSION], m4_bpatsubst(m4_esyscmd([grep "Version:" firewalld.spec]), [Version:\W\([0-9.]*\)\W], [\1]))
m4_define([PKG_RELEASE], m4_bpatsubst(m4_esyscmd([grep "Release:" firewalld.spec]), [Release:\W\([0-9.]*\).*\W], [\1]))
m4_define([PKG_TAG], m4_bpatsubst(m4_format(r%s-%s, PKG_VERSION, PKG_RELEASE), [\.], [_]))

AC_INIT(PKG_NAME, PKG_VERSION)
AC_CONFIG_SRCDIR([src/firewalld])
AM_INIT_AUTOMAKE([1.9 tar-ustar no-define foreign dist-bzip2 no-dist-gzip])

AC_SUBST([PACKAGE_RELEASE], '[PKG_RELEASE]')
AC_DEFINE_UNQUOTED([PACKAGE_RELEASE], ["$PACKAGE_RELEASE"])
AC_SUBST([PACKAGE_TAG], '[PKG_TAG]')
AC_DEFINE_UNQUOTED([PACKAGE_TAG], ["$PACKAGE_TAG"])

AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PATH_PYTHON

m4_define([FWD_ERROR_CODES], m4_esyscmd([grep "=\s*[0-9]\+$" src/firewall/errors.py]))
AC_SUBST([FIREWALLD_ERROR_CODES], '[FWD_ERROR_CODES]')

GLIB_GSETTINGS

#############################################################

AC_ARG_ENABLE([systemd],
       AS_HELP_STRING([--disable-systemd], [Disable systemd support]),
       [use_systemd=$enableval], [use_systemd=yes])
AM_CONDITIONAL(USE_SYSTEMD, test x$use_systemd = xyes)
AC_SUBST(USE_SYSTEMD)

AC_ARG_ENABLE([sysconfig],
    [AS_HELP_STRING([--enable-sysconfig], [Install sysconfig file])],
    [INSTALL_SYSCONFIG="${enableval}"], [INSTALL_SYSCONFIG='no'])
AM_CONDITIONAL(INSTALL_SYSCONFIG, [test x$INSTALL_SYSCONFIG = xyes])
AC_SUBST(INSTALL_SYSCONFIG)

AC_ARG_WITH([systemd-unitdir],
       AS_HELP_STRING([--with-systemd-unitdir], [Directory for systemd service files]),
       [SYSTEMD_UNITDIR=$withval], [SYSTEMD_UNITDIR="${prefix}/lib/systemd/system"])
AC_SUBST(SYSTEMD_UNITDIR)

AC_ARG_WITH([bashcompletiondir],
       AS_HELP_STRING([--with-bashcompletiondir=DIR], [Bash completions directory]),
       [BASHCOMPLETIONDIR=$withval], [BASHCOMPLETIONDIR="${datadir}/bash-completion/completions"])
AC_SUBST(BASHCOMPLETIONDIR)

#############################################################

AC_SUBST([GETTEXT_PACKAGE], '[PKG_NAME]')
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE], ["$GETTEXT_PACKAGE"],)

IT_PROG_INTLTOOL([0.35.0], [no-xml])
AM_PO_SUBDIRS

PREFIX=`eval echo $prefix`
AC_SUBST(PREFIX)
SYSCONFDIR=`eval echo $sysconfdir`
AC_SUBST(SYSCONFDIR)

AC_CONFIG_FILES([Makefile
		 doxygen.conf
		 config/Makefile
		 doc/Makefile
		 doc/man/Makefile
		 doc/man/man1/Makefile
		 doc/man/man5/Makefile
		 doc/xml/transform-html.xsl
		 doc/xml/transform-man.xsl
		 po/Makefile.in
		 shell-completion/Makefile
		 src/firewall/config/__init__.py
		 src/Makefile
         src/icons/Makefile])
AC_OUTPUT
