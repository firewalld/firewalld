#!/bin/bash

#set -x

# BEWARE:
# some tests modify default zone and will fail if default zone is immutable,
# i.e. block, drop, trusted

path="/usr/bin/firewall-cmd"

assert_good() {
  args="${1}"
  firewall-cmd ${args} > /dev/null
  if [ $? == 0 ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (expected: zero exit status)"
    exit 2
  fi
}

assert_good_notempty() {
  args="${1}"
  ret=$(firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a -n "${ret}" ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (expected: zero exit status and not-empty return value)"
    exit 2
  fi
}

assert_good_empty() {
  args="${1}"
  ret=$(firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a -z "${ret}" ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (expected: zero exit status and empty return value)"
    exit 2
  fi
}

assert_good_equals() {
  args="${1}"
  value="${2}"
  ret=$(firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a "${ret}" == "${value}" ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (expected: zero exit status and ${ret} == ${value})"
    exit 2
  fi
}

assert_good_contains() {
  args="${1}"
  value="${2}"
  ret=$(firewall-cmd ${args}) > /dev/null
  if [[ ( $? == 0 ) && ( "${ret}" = *${value}* ) ]]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (expected: zero exit status and ${ret} contains ${value})"
    exit 2
  fi
}

assert_bad() {
  args="${1}"
  firewall-cmd ${args} > /dev/null
  if [ $? != 0 ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (expected: non-zero exit status)"
    exit 2
  fi
}

# ... standalone options ...

assert_good "-h"
assert_good "--help"
assert_good "-V"
#assert_good "--reload"
#assert_good "--complete-reload"
assert_good "--enable-panic"
assert_good "--query-panic"
assert_good "--disable-panic"
assert_bad  "--query-panic"

old=$(firewall-cmd --get-default-zone)
assert_good_notempty "--get-default-zone"
assert_good          "--set-default-zone=home"
assert_good_equals   "--get-default-zone" "home"
assert_good          "--set-default-zone=${old}"

assert_good_notempty "--get-zones"
assert_good_notempty "--get-services"
assert_good_notempty "--get-icmptypes"

assert_good "--list-all-zones"
assert_good "--list-all"

iface="dummy0"
zone="work"
assert_good          "--zone=${zone} --add-interface=${iface}"
assert_good_equals   "--get-zone-of-interface=${iface}" "${zone}"
assert_good_contains "--get-active-zones" "${zone}"
assert_good          "--zone ${zone} --query-interface=${iface}"
zone="public"
assert_good          "--zone=${zone} --change-interface=${iface}"
assert_good_equals   "--get-zone-of-interface=${iface}" "${zone}"
zone="dmz"
assert_good          "--zone=${zone} --change-zone=${iface}"
assert_good_equals   "--get-zone-of-interface=${iface}" "${zone}"
assert_good_contains "--zone=${zone} --list-interfaces" "${iface}"
assert_good          "--zone=${zone} --remove-interface=${iface}"
assert_bad           "--zone=${zone} --query-interface ${iface}"
assert_good_empty    "--get-zone-of-interface=${iface}"


assert_good "--add-service=dns --timeout 60"
assert_good  "--query-service dns"
assert_good "--remove-service=dns"
assert_bad   "--query-service=dns"

assert_bad     "--add-port=666"
assert_bad     "--add-port=666/dummy"
assert_good    "--add-port=666/tcp"
assert_good "--remove-port=666/tcp"
assert_good    "--add-port=111-222/udp"
assert_good  "--query-port=111-222/udp"
assert_good "--remove-port 111-222/udp"
assert_bad   "--query-port=111-222/udp"

assert_good "--add-masquerade"
assert_good "--query-masquerade"
assert_good "--remove-masquerade"
assert_bad  "--query-masquerade"

assert_bad  "--zone=block --add-icmp-block=redirect"
assert_good "--zone=external --add-icmp-block=redirect"
assert_good "--zone=external --query-icmp-block=redirect"
assert_good "--remove-icmp-block redirect --zone=external"
assert_bad  "--zone=external --query-icmp-block=redirect"

assert_bad  "--add-forward-port=666"
assert_good    "--add-forward-port=port=11:proto=tcp:toport=22"
assert_good "--remove-forward-port=port=11:proto=tcp:toport=22"
assert_bad  "--add-forward-port=port=33:proto=tcp:toaddr=4444"
assert_good    "--add-forward-port=port=33:proto=tcp:toaddr=4.4.4.4"
assert_good "--remove-forward-port=port=33:proto=tcp:toaddr=4.4.4.4"
assert_good    "--add-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_good  "--query-forward-port port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_good "--remove-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_bad   "--query-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"

assert_good_contains "--zone=home --list-services" "ssh"
assert_good          "--zone home --list-ports"
assert_good          "--list-icmp-blocks"
assert_good          "--zone=home --list-forward-ports"

# ... --permanent ...
assert_good_notempty "--permanent --get-zones"
assert_good_notempty "--permanent --get-services"
assert_good_notempty "--permanent --get-icmptypes"

assert_good_contains "--permanent --zone=work --list-services" "ssh"
assert_good          "--permanent --list-forward-ports"

assert_good          "--permanent --zone=external --add-service=pop3s"
assert_good_contains "--permanent --zone=external --list-services" "pop3s"

# ... --direct  ...
assert_good_contains "--direct --passthrough ipv4 -nvL" "IN_ZONE_home_allow"
assert_good_empty    "--direct --get-chains ipv4 filter"
assert_good          "--direct --add-chain ipv4 filter mychain"
assert_good_equals   "--direct --get-chains ipv4 filter" "mychain"
assert_good          "--direct --query-chain ipv4 filter mychain"

assert_good_empty    "--direct --get-rules ipv4 filter mychain"
assert_good          "--direct --add-rule ipv4 filter mychain 3 -j ACCEPT"
assert_good_contains "--direct --get-rules ipv4 filter mychain" "ACCEPT"
assert_good          "--direct --query-rule ipv4 filter mychain -j ACCEPT"
assert_good          "--direct --remove-rule ipv4 filter mychain -j ACCEPT"
assert_good_empty    "--direct --get-rules ipv4 filter mychain"
assert_bad           "--direct --query-rule ipv4 filter mychain -j ACCEPT"

assert_good          "--direct --remove-chain ipv4 filter mychain"
assert_bad           "--direct --query-chain ipv4 filter mychain"
assert_good_empty    "--direct --get-chains ipv4 filter"
assert_good          "--direct --remove-chain ipv4 filter dummy" # removing nonexisting chain is just warning

echo "----------------------------------------------------------------------"
echo "Everything's OK, you rock :-)"
