#! /bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd $srcdir

rm -rf $srcdir/autom*
rm -f $srcdir/config.*

# create po/LINGUAS
ls po/*.po | sed -e 's/.po//' | sed -e 's/po\///' > po/LINGUAS

intltoolize --force --automake

autoreconf --force -v --install --symlink || exit 1
cd $ORIGDIR || exit $?

if test -z "$NOCONFIGURE"; then
	$srcdir/configure "$@"
fi
