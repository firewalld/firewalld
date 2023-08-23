#!/bin/bash

set -e

die() {
    if [ "$SHOW_USAGE" = 1 ]; then
        usage >&2
        echo >&2
    fi
    printf "%s\n" "$*" >&2
    exit 1
}

LOG() {
    printf "%s\n" "$*"
}

get_bcond() {
    sed -n 's/^ *%bcond_with\(out\)\? \+\([a-z0-9_A-Z]\+\)$/\2/p' "$BASEDIR/$RPMDIR/firewalld.spec" | sort -u
}

list_contains() {
    local needle="$1"
    local a
    shift
    for a; do
        [ "$a" = "$needle" ] && return 0
    done
    return 1
}

list_add() {
    declare -n array="$1"
    local arg="$2"

    list_contains "$arg" "${array[@]}" && return 0
    array=( "${array[@]}" "$arg" )
}

list_del() {
    declare -n array="$1"
    local arg="$2"
    local array_tmp=()
    local a
    for a in "${array[@]}" ; do
        if [ "$a" != "$arg" ] ; then
            array_tmp=( "${array_tmp[@]}" "$a" )
        fi
    done
    array=( "${array_tmp[@]}" )
}

list_add_arg() {
    local array_name="$1"
    local prefix="$2"
    local a
    shift
    shift

    eval "unset $array_name"
    eval "$array_name=()"
    declare -n array="$array_name"
    for a ; do
        array=( "${array[@]}" "$prefix" "$a" )
    done
}

usage() {
    LOG "$0 [-h|--help] [OPTIONS...]"
    LOG
    LOG "OPTIONS:"
    LOG "  -f|--force          : run git-clean first and \`make dist\`."
    LOG "                        Otherwise, try to detect the existing tarball or fail."
    LOG "  -R|--rpm            : build an RPM (contrary to \"-S\") (default)"
    LOG "  -S|--srpm           : build an SRPM (contrary to \"-R\")"
    LOG "  --sources           : only generate the spec file and SOURCES (contrary to \"-R\")"
    LOG "  -w|--with OPTION    : pass \`--with OPTION\` to rpmbuild"
    LOG "  -W|--without OPTION : pass \`--without OPTION\` to rpmbuild"
    LOG "  -s|--snapshot TEXT  : use TEXT as the snapshot version for the new package"
    LOG "                        (overwrites \$FW_BUILD_SNAPSHOT environment)"
    LOG
    LOG "Supported with/without options:"
    for a in $(get_bcond) ; do
        LOG "  \"$a\""
    done
}

DATE="$(date '+%Y%m%d-%H%M%S.%3N')"

RPMDIR="contrib/fedora/rpm"
BASEDIR="$(readlink -f "$(dirname "$0")/../../..")"

ARG_FORCE=0
BUILDTYPE=rpm

ARGS_WITH=()
ARGS_WITHOUT=()

FW_BUILD_SNAPSHOT="${FW_BUILD_SNAPSHOT:-%{nil\}}"

while [ $# -gt 0 ] ; do
    A="$1"
    shift
    case "$A" in
        -f|--force):
            ARG_FORCE=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -S|--srpm)
            BUILDTYPE=srpm
            ;;
        -R|--rpm)
            BUILDTYPE=rpm
            ;;
        --sources)
            BUILDTYPE=sources
            ;;
        -w|--with)
            [ $# -gt 0 ] || SHOW_USAGE=1 die "Missing argument to $A"
            list_add ARGS_WITH    "$1"
            list_del ARGS_WITHOUT "$1"
            shift
            ;;
        -W|--without)
            [ $# -gt 0 ] || SHOW_USAGE=1 die "Missing argument to $A"
            list_add ARGS_WITHOUT "$1"
            list_del ARGS_WITH    "$1"
            shift
            ;;
        -s|--snapshot)
            [ $# -gt 0 ] || SHOW_USAGE=1 die "Missing argument to $A"
            FW_BUILD_SNAPSHOT="$1"
            shift
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done


if [ "$TARBALL" != "" ]; then
    test -f "$TARBALL" || die "Invalid \$TARBALL \"$TARBALL\""
    TARBALL="$(readlink -f "$TARBALL")"
fi

cd "$BASEDIR"

BUILDLOG="$(mktemp "$RPMDIR/Build.log.$DATE.XXXXXXX")"
chmod +r "$BUILDLOG"

exec > >(tee "$BUILDLOG")
exec 2>&1

UUID="$(uuidgen)"
FW_BUILD_USERNAME="${FW_BUILD_USERNAME:-"$(git config user.name) <$(git config user.email)>"}" || die "git directory not properly setup or working?"
CHANGELOG="$CHANGELOG"
VERSION="$(grep "^Version:" ./firewalld.spec |cut -f2 -d ' ')" || die "Failure to detect version from firewalld.spec"
RELEASE_VERSION="$(git rev-list HEAD | wc -l)" || die "Failure to detect RELEASE_VERSION from git"
SNAPSHOT="${SNAPSHOT:-%{nil\}}"
COMMIT_FULL="$(git rev-parse --verify HEAD)" || die "Error reading HEAD revision"
COMMIT="$(printf '%s' "$COMMIT_FULL" | sed 's/^\(.\{10\}\).*/\1/')"
RPMBUILD_ARGS="$RPMBUILD_ARGS"

LOG "conf: BASEDIR=\"$BASEDIR\""
LOG "conf: DATE=\"$DATE\""
LOG "conf: UUID=\"$UUID\""
LOG "conf: CHANGELOG=\"$CHANGELOG\""
LOG "conf: VERSION=\"$VERSION\""
LOG "conf: RELEASE_VERSION=\"$RELEASE_VERSION\""
LOG "conf: COMMIT_FULL=\"$COMMIT_FULL\""
LOG "conf: COMMIT=\"$COMMIT\""
LOG "conf: FORCE=\"$ARG_FORCE\""
LOG "conf: BUILDTYPE=\"$BUILDTYPE\""
LOG "conf: RPMBUILD_ARGS=\"$RPMBUILD_ARGS\""
LOG "conf: ARGS_WITH=\"${ARGS_WITH[@]}\""
LOG "conf: ARGS_WITHOUT=\"${ARGS_WITHOUT[@]}\""
LOG "conf: FW_BUILD_USERNAME=\"$FW_BUILD_USERNAME\""
LOG "conf: FW_BUILD_SNAPSHOT=\"$FW_BUILD_SNAPSHOT\""

TARBALL_NAME="firewalld-$VERSION.tar.bz2"
CALL_DIST=0

if [ "$TARBALL" = "" -a "$ARG_FORCE" != 1 -a -f "./$TARBALL_NAME" ]; then
    TARBALL="./$TARBALL_NAME"
fi

if [ "$TARBALL" != "" ]; then
    :
else
    if [ "$ARG_FORCE" = 1 ]; then
        git clean -fdx -- ":(exclude)$RPMDIR/" ":(exclude)firewalld-*.tar.bz"
    else
        if [ "$(git clean -ndx -- ":(exclude)$RPMDIR/" ":(exclude)firewalld-*.tar.bz")" != "" ] ; then
            die "Working directory is not clean. Rerun with --force. WARNING: this cleans the working directory!"
        fi
    fi
    CALL_DIST=1
fi

BUILDDIR="$(mktemp -d -p "$RPMDIR" "Builddir.$DATE.XXXXX")"

LOG "conf: BUILDDIR=\"$BUILDDIR\""

ln -snf "$(basename "$BUILDDIR")" "$RPMDIR/Builddir.building"
mkdir -p "$BUILDDIR/SPECS/"
mkdir -p "$BUILDDIR/SOURCES/"

ln "$BUILDLOG" "$BUILDDIR/build.log"
rm -f "$BUILDLOG"

SPECFILE="$BUILDDIR/SPECS/firewalld.spec"

dist() {
    ./autogen.sh
    ./configure
    make dist
    TARBALL="./$TARBALL_NAME"
}

if [ "$CALL_DIST" = "1" ]; then
    dist
fi

if [ ! -f "$TARBALL" -o "$(printf "%s" "$TARBALL" | wc -w)" -ne 1 ] ; then
    if [ "$CALL_DIST" = "1" ]; then
        die "Tarball not generated by \`make dist\`. Something went wrong."
    fi
    die "To tarball found. Build with --force (warning: cleans git tree)"
fi

write_changelog() {
    if [ -z "$CHANGELOG" ]; then
        cat <<- EOF
	* $(LC_TIME=C date '+%a %b %d %Y') $FW_BUILD_USERNAME - %{epoch_version}:%{version}-%{release_version}%{?snap}
	- build of firewalld ($DATE, uuid: $UUID, git: $COMMIT_FULL)
	$(git log -n20 --date=local --format='- %h %s [%an] (%ci)')
	- ...
	EOF
    else
        echo "$CHANGELOG"
    fi > "$BUILDDIR/SOURCES/CHANGELOG"
}

write_changelog

cat "$RPMDIR/firewalld.spec" \
  | sed \
        -e "s/__VERSION__/$VERSION/g" \
        -e "s/__RELEASE_VERSION__/$RELEASE_VERSION/g" \
        -e "s/__SNAPSHOT__/$FW_BUILD_SNAPSHOT/g" \
        -e "s/__COMMIT__/$COMMIT/g" \
        -e "s/__COMMIT_FULL__/$COMMIT_FULL/g" \
  | sed -e "/^__CHANGELOG__$/ \
        {
            r $BUILDDIR/SOURCES/CHANGELOG
            d
        }" > "$SPECFILE" || die "Error generating spec file \"$SPECFILE\""

for f in \
    contrib/fedora/rpm/1001-fedora-only-MDNS-default.patch \
    contrib/fedora/rpm/FedoraServer.xml \
    contrib/fedora/rpm/FedoraWorkstation.xml \
    contrib/fedora/rpm/org.fedoraproject.FirewallD1.desktop.rules.choice \
    "$TARBALL" \
    ; do
    cp "$f" "$BUILDDIR/SOURCES/" || die "Could not copy file \"$f\" to \"$BUILDDIR/SOURCES/\""
done

if [ "$BUILDTYPE" != "sources" ]; then
    if [ "$BUILDTYPE" = "srpm" ]; then
        RPM_BUILD_OPTION=-bs
    else
        RPM_BUILD_OPTION=-ba
    fi

    list_add_arg ARGS_WITH_X    "--with"    "${ARGS_WITH[@]}"
    list_add_arg ARGS_WITHOUT_X "--without" "${ARGS_WITHOUT[@]}"

    rpmbuild \
        --define "_topdir $BASEDIR/$BUILDDIR" \
        "$RPM_BUILD_OPTION" \
        "$SPECFILE" \
        "${ARGS_WITH_X[@]}" \
        "${ARGS_WITHOUT_X[@]}" \
        $RPMBUILD_ARGS \
        || die "ERROR: rpmbuild FAILED"
fi

ln -snf "$(basename "$BUILDDIR")" "$RPMDIR/Builddir.latest"

LOG
LOG
LOG "Finished with success."
LOG
LOG "See \"$BASEDIR/$RPMDIR/Builddir.latest\" which symlinks to \"$BASEDIR/$BUILDDIR\""
LOG
LOG "Result:"
if [ "$BUILDTYPE" = "sources" ]; then
    ls -dla \
        "$BASEDIR/$RPMDIR/Builddir.latest" \
        "$BASEDIR/$BUILDDIR" \
        "$BASEDIR/$BUILDDIR"/SPECS/* \
        "$BASEDIR/$BUILDDIR"/SOURCES/*
else
    ls -dla \
        "$BASEDIR/$RPMDIR/Builddir.latest" \
        "$BASEDIR/$BUILDDIR" \
        "$BASEDIR/$BUILDDIR"/RPMS/*/ \
        "$BASEDIR/$BUILDDIR"/RPMS/*/*.rpm \
        "$BASEDIR/$BUILDDIR"/SRPMS/ \
        "$BASEDIR/$BUILDDIR"/SRPMS/*.rpm
fi 2>/dev/null \
    | sed 's/^/    /'
LOG
if [ "$BUILDTYPE" = "sources" ]; then
    :
elif [ "$BUILDTYPE" = "srpm" ]; then
    LOG sudo "$(command -v dnf &>/dev/null && echo dnf builddep || echo yum-builddep)" "\"$BASEDIR/$RPMDIR/Builddir.latest/SRPMS\"/*.src.rpm"
    LOG
else
    LOG sudo "$(command -v dnf &>/dev/null && echo dnf || echo yum)" install "\"$BASEDIR/$RPMDIR/Builddir.latest/RPMS\"/*/*.rpm"
    LOG
fi
