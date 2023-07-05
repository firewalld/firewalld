#!/bin/bash -e

if [ ! -d /tmp/sys2 ]; then
    # `ip -netns t exec ...` will try to mount sysfs. But kernel rejects that
    # in the container, unless a writable sysfs is already mounted. Due to
    # --privileged, we have /sys mounted rw, however, ip will first unmount
    # /sys before trying to remount it. We thus need it mounted as rw one
    # additional time.
    #
    # Let's do this setup step once, and never clean it up.
    # https://github.com/containers/podman/issues/11887#issuecomment-938706628
    mkdir /tmp/sys2
    mount -t sysfs --make-private /tmp/sys2
fi
