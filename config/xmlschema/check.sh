#!/bin/bash

# requires libxml2 packages for xmllint
XMLLINT=/usr/bin/xmllint
PACKAGE=libxml2

prog=$(basename $0)
BASEDIR=$(realpath $(dirname $0))

checkdir=$(pwd)
while getopts "d:h" arg; do
    case $arg in
	d)
	    checkdir=$OPTARG
	    ;;
	h)
	    cat <<EOF
Usage: $prog [options]

Checks zone, service and icmptype firewalld config files to be valid.
Use this script either in the directory containing the zones, services and
icmptypes directories containing the files to be checked, or use the -d option
to specify a directory.

Options:
  -h              Print this help
  -d <directory>  Check files in this directory

EOF
	    exit 0
	    ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
            ;;
    esac
done

if [ ! -f "$XMLLINT" ]; then
    echo "$XMLLINT is not installed, please install the $PACKAGE package."
    exit -1
fi

if [ ! -d "$checkdir" ]; then
    echo "Directory '${checkdir}' does not exist"
    exit -2
fi

# Stop execution if something failed
set -e

for keyword in zone service icmptype ipset; do
    if [ -d "${checkdir}/${keyword}s" ]; then
	echo "Checking ${keyword}s"
	cd "${checkdir}/${keyword}s"
	ls -f *.xml 2>/dev/null | while read -r file; do
	    echo -n "  "
	    $XMLLINT --noout --schema "$BASEDIR"/${keyword}.xsd "${file}"
	done
    else
	echo "Directory '${checkdir}/${keyword}s' does not exist"
    fi
done
