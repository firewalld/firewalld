#! /bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd $srcdir

rm -rf $srcdir/autom*
rm -f $srcdir/config.*

# create po/POTFILES.in
rm -f po/POTFILES.in
for i in $(cat po/POTFILES.in.in); do echo $i>>po/POTFILES.in; done

# create po/LINGUAS
ls po/*.po | sed -e 's/.po//' | sed -e 's/po\///' > po/LINGUAS

intltoolize --copy -f --automake

autoreconf -v --install || exit 1
cd $ORIGDIR || exit $?

$srcdir/configure "$@"
