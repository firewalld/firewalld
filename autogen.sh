#! /bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd $srcdir

rm -rf $srcdir/autom*
rm -f $srcdir/config.*

# create po/LINGUAS
ls po/*.po | sed -e 's/.po//' | sed -e 's/po\///' > po/LINGUAS

intltoolize --copy -f --automake

autoreconf -v --install || exit 1
cd $ORIGDIR || exit $?

$srcdir/configure "$@"
