#!/bin/bash

set -e

# requires libxml2 packages for xmllint
XMLLINT=/usr/bin/xmllint
PACKAGE=libxml2

prog="$(basename $0)"
BASEDIR=$(realpath $(dirname $0))

checkdir="$PWD"
while getopts "d:h" arg; do
    case "$arg" in
        d)
            checkdir="$OPTARG"
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
    exit 1
fi

if [ ! -d "$checkdir" ]; then
    echo "Directory \"$checkdir\"' does not exist"
    exit 2
fi

shopt -s nullglob

ANY_FOUND=0

for keyword in \
        helper \
        icmptype \
        ipset \
        policy \
        service \
        zone \
    ; do
    if [ $keyword = policy ]; then
        dir="${checkdir%%/}/policies"
    else
        dir="${checkdir%%/}/${keyword}s"
    fi
    echo "Checking ${keyword} in \"$dir\""
    if [ ! -d "$dir" ]; then
        echo "  Directory \"$dir\" does not exist."
        continue
    fi
    for f in "$dir/"*.xml ; do
        ANY_FOUND=1
        echo -n "  "
        "$XMLLINT" --noout --schema "$BASEDIR/$keyword.xsd" "$f"
    done
done

test "$ANY_FOUND" = 1
