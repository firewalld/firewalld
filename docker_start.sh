#!/usr/bin/env bash

kill_all() {
	kill ${PID_FIREWALLD}
	kill ${PID_DBUS}
}

# let dbus run as "root"
sed -i '/<user>/d' /usr/share/dbus-1/system.conf
# for dbus socket
mkdir -p /run/dbus

dbus-daemon --system --nofork --nopidfile --nosyslog &
PID_DBUS=$!
sleep 1

firewalld --nofork --nopid &
PID_FIREWALLD=$!

trap kill_all TERM

wait -n
exit $?
