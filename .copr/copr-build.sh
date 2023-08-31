#!/bin/bash -ex

env

dnf install -y \
        autoconf \
        automake \
        bzip2 \
        docbook-style-xsl \
        gettext-devel \
        git-core \
        glib2-devel \
        intltool \
        libxslt \
        make \
        rpm-build \
        ;

export FW_BUILD_SNAPSHOT="${SNAPSHOT-copr}"
export FW_BUILD_USERNAME=copr

contrib/fedora/rpm/build.sh -S

mv './contrib/fedora/rpm/Builddir.latest/SRPMS'/*.src.rpm "$OUTDIR"
