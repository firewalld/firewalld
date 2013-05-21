#!/bin/bash

#set -x

# BEWARE:
# some tests modify default zone and will fail if default zone is
# set to immutable one, i.e. to block, drop, trusted

#path="/usr/bin/"
path="../"

assert_good() {
  args="${1}"
  ${path}firewall-cmd ${args} > /dev/null
  if [ $? == 0 ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (non-zero exit status)"
    ((failures++))
  fi
}

assert_good_notempty() {
  args="${1}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a -n "${ret}" ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (non-zero exit status or empty return value)"
    ((failures++))
  fi
}

assert_good_empty() {
  args="${1}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a -z "${ret}" ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (non-zero exit status or non-empty return value)"
    ((failures++))
  fi
}

assert_good_equals() {
  args="${1}"
  value="${2}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a "${ret}" == "${value}" ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (non-zero exit status or '${ret}' != '${value}')"
    ((failures++))
  fi
}

assert_good_contains() {
  args="${1}"
  value="${2}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [[ ( $? == 0 ) && ( "${ret}" = *${value}* ) ]]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (non-zero exit status or '${ret}' does not contain '${value}')"
    ((failures++))
  fi
}

assert_bad() {
  args="${1}"
  ${path}firewall-cmd ${args} 1> /dev/null 2>&1
  if [ $? != 0 ]; then
    echo "${args} ... OK"
  else
    echo "${args} ... FAILED (zero exit status)"
    ((failures++))
  fi
}


# MAIN
failures=0

assert_good "-h"
assert_good "--help"
assert_good "-V"
assert_good "--reload"
assert_good "--complete-reload"
assert_good "--panic-on"
assert_good "--query-panic"
assert_good "--panic-off"
assert_bad  "--query-panic"

default_zone=$(firewall-cmd --get-default-zone)
zone="home"
assert_good_notempty "--get-default-zone"
assert_good          "--set-default-zone=${zone}"
assert_good_equals   "--get-default-zone" "${zone}"
assert_good          "--set-default-zone=${default_zone}"
assert_bad           "--set-default-zone" # missing argument

assert_good_notempty "--get-zones"
assert_good_notempty "--get-services"
assert_good_notempty "--get-icmptypes"

assert_good_notempty "--permanent --get-zones"
assert_good_notempty "--permanent --get-services"
assert_good_notempty "--permanent --get-icmptypes"

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
assert_bad           "--get-zone-of-interface" # missing argument
assert_bad           "--zone=${zone} --get-zones" # impossible combination
assert_bad           "--zone=${zone} --get-services" # impossible combination
assert_bad           "--zone=${zone} --get-default-zone" # impossible combination
assert_bad           "--zone=${zone} --set-default-zone" # impossible combination
assert_bad           "--zone=${zone} --get-zone-of-interface" # impossible combination

zone="public"
sources=( "dead:beef::babe" "3ffe:501:ffff::/64" "1.2.3.4" "192.168.1.0/24" )
for (( i=0;i<${#sources[@]};i++)); do
  source=${sources[${i}]}
  assert_good          "--zone=${zone} --add-source=${source}"
  assert_good_equals   "--get-zone-of-source=${source}" "${zone}"
  assert_good_contains "--zone=${zone} --list-sources" "${source}"
  assert_good_contains "--zone=${zone} --list-all" "${source}"
  assert_good_contains "--get-active-zones" "${source}"
  assert_good          "--zone ${zone} --query-source=${source}"
  assert_good          "--zone=${zone} --remove-source=${source}"
  assert_bad           "--zone ${zone} --query-source=${source}"
  assert_good_empty    "--get-zone-of-source=${source}"
  assert_bad           "--get-zone-of-source" # missing argument
done 

iface1="foo"
iface2="bar"
zone="trusted"
assert_good        "--add-interface=${iface1}"
assert_good        "--add-interface=${iface2} --zone=${default_zone}"
assert_good        "--set-default-zone=${zone}"
assert_good_equals "--get-default-zone" "${zone}"
# check that changing default zone moves interfaces in that zone
assert_good        "--query-interface ${iface1} --zone=${zone}"
# check that *only* iface1 was moved to new default zone
assert_good        "--query-interface ${iface2} --zone=${default_zone}"
assert_good        "--set-default-zone=${default_zone}"
assert_good        "--remove-interface=${iface1}"
assert_good        "--remove-interface=${iface2}"

assert_good "   --add-service=dns --timeout 60 --zone=${default_zone}"
assert_good " --query-service dns"
assert_good "--remove-service=dns"
assert_bad  " --query-service=dns"
assert_bad  "   --add-service=smtps" # bad service name
assert_bad  "   --add-service=dns --timeout" # missing argument
assert_bad  "   --add-service=dns --add-interface=dummy0" # impossible combination

assert_bad           "--permanent --zone=external --add-service=dns --timeout 60" # impossible combination
assert_good          "--permanent --zone=external --add-service dns"
assert_good_contains "--permanent --zone=external --list-services" "dns"
assert_good          "--permanent --zone=external --query-service dns"
assert_good          "--permanent --zone=external --remove-service=dns"
assert_bad           "--permanent --zone=external --query-service=dns" # removed
assert_bad           "--permanent --zone=external --add-service=smtps" # bad service name
assert_bad           "--permanent --zone=external --add-service=dns --add-interface=dummy0" # impossible combination

assert_good "   --add-service=http --add-service=nfs"
assert_good " --query-service http"
assert_good " --query-service=nfs --zone=${default_zone}"
assert_good "--remove-service=nfs --remove-service=http"
assert_bad  " --query-service http"
assert_bad  " --query-service nfs"

assert_good "--permanent    --add-service=http --add-service=nfs"
assert_good "--permanent  --query-service http"
assert_good "--permanent  --query-service=nfs --zone=${default_zone}"
assert_good "--permanent --remove-service=nfs --remove-service=http"
assert_bad  "--permanent  --query-service http"
assert_bad  "--permanent  --query-service nfs"

assert_bad  "   --add-port=666" # no protocol
assert_bad  "   --add-port=666/dummy" # bad protocol
assert_good "   --add-port=666/tcp --zone=${default_zone}"
assert_good "--remove-port=666/tcp"
assert_good "   --add-port=111-222/udp"
assert_good " --query-port=111-222/udp --zone=${default_zone}"
assert_good "--remove-port 111-222/udp"
assert_bad  " --query-port=111-222/udp"

assert_bad  "--permanent    --add-port=666" # no protocol
assert_bad  "--permanent    --add-port=666/dummy" # bad protocol
assert_good "--permanent    --add-port=666/tcp"
assert_good "--permanent --remove-port=666/tcp     --zone=${default_zone}"
assert_good "--permanent    --add-port=111-222/udp --zone=${default_zone}"
assert_good "--permanent  --query-port=111-222/udp"
assert_good "--permanent --remove-port 111-222/udp"
assert_bad  "--permanent  --query-port=111-222/udp"

assert_good "   --add-port=80/tcp --add-port 443-444/udp"
assert_good " --query-port=80/tcp --zone=${default_zone}"
assert_good " --query-port=443-444/udp"
assert_good "--remove-port 80/tcp --remove-port=443-444/udp"
assert_bad  " --query-port=80/tcp"
assert_bad  " --query-port=443-444/udp"

assert_good "--permanent    --add-port=80/tcp --add-port 443-444/udp"
assert_good "--permanent  --query-port=80/tcp --zone=${default_zone}"
assert_good "--permanent  --query-port=443-444/udp"
assert_good "--permanent --remove-port 80/tcp --remove-port=443-444/udp"
assert_bad  "--permanent  --query-port=80/tcp"
assert_bad  "--permanent  --query-port=443-444/udp"

assert_good "   --add-masquerade --zone=${default_zone}"
assert_good " --query-masquerade "
assert_good "--remove-masquerade"
assert_bad  " --query-masquerade"

assert_good "--permanent    --add-masquerade"
assert_good "--permanent  --query-masquerade --zone=${default_zone}"
assert_good "--permanent --remove-masquerade --zone=${default_zone}"
assert_bad  "--permanent  --query-masquerade"

assert_bad  "--zone=external    --add-icmp-block=dummyblock" # invalid icmp type
assert_bad  "--zone=block       --add-icmp-block=redirect" # immutable zone
assert_good "--zone=external    --add-icmp-block=redirect"
assert_good "--zone=external  --query-icmp-block=redirect"
assert_good "--zone=external --remove-icmp-block redirect"
assert_bad  "--zone=external  --query-icmp-block=redirect"

assert_bad  "--permanent --zone=external    --add-icmp-block=dummyblock" # invalid icmp type
assert_good "--permanent --zone=external    --add-icmp-block=redirect"
assert_good "--permanent --zone=external  --query-icmp-block=redirect"
assert_good "--permanent --zone=external --remove-icmp-block redirect"
assert_bad  "--permanent --zone=external  --query-icmp-block=redirect"

assert_good "--zone=external    --add-icmp-block=echo-reply --add-icmp-block=router-solicitation"
assert_good "--zone=external  --query-icmp-block=echo-reply"
assert_good "--zone=external  --query-icmp-block=router-solicitation"
assert_good "--zone=external --remove-icmp-block echo-reply --remove-icmp-block=router-solicitation"
assert_bad  "--zone=external  --query-icmp-block=echo-reply"
assert_bad  "--zone=external  --query-icmp-block=router-solicitation"

assert_good "--permanent --zone=external    --add-icmp-block=echo-reply --add-icmp-block=router-solicitation"
assert_good "--permanent --zone=external  --query-icmp-block=echo-reply"
assert_good "--permanent --zone=external  --query-icmp-block=router-solicitation"
assert_good "--permanent --zone=external --remove-icmp-block echo-reply --remove-icmp-block=router-solicitation"
assert_bad  "--permanent --zone=external  --query-icmp-block=echo-reply"
assert_bad  "--permanent --zone=external  --query-icmp-block=router-solicitation"

assert_bad  "   --add-forward-port=666" # no protocol
assert_good "   --add-forward-port=port=11:proto=tcp:toport=22"
assert_good "--remove-forward-port=port=11:proto=tcp:toport=22 --zone=${default_zone}"
assert_bad  "   --add-forward-port=port=33:proto=tcp:toaddr=4444" # bad address
assert_good "   --add-forward-port=port=33:proto=tcp:toaddr=4.4.4.4 --zone=${default_zone}"
assert_good "--remove-forward-port=port=33:proto=tcp:toaddr=4.4.4.4"
assert_good "   --add-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_good " --query-forward-port port=55:proto=tcp:toport=66:toaddr=7.7.7.7 --zone=${default_zone}"
assert_good "--remove-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_bad  " --query-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"

assert_bad  "--permanent         --add-forward-port=666" # no protocol
assert_good "--permanent    --add-forward-port=port=11:proto=tcp:toport=22 --zone=${default_zone}"
assert_good "--permanent --remove-forward-port=port=11:proto=tcp:toport=22"
assert_bad  "--permanent    --add-forward-port=port=33:proto=tcp:toaddr=4444" # bad address
assert_good "--permanent    --add-forward-port=port=33:proto=tcp:toaddr=4.4.4.4"
assert_good "--permanent --remove-forward-port=port=33:proto=tcp:toaddr=4.4.4.4 --zone=${default_zone}"
assert_good "--permanent    --add-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_good "--permanent  --query-forward-port port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_good "--permanent --remove-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"
assert_bad  "--permanent  --query-forward-port=port=55:proto=tcp:toport=66:toaddr=7.7.7.7"

assert_good "   --add-forward-port=port=88:proto=udp:toport=99 --add-forward-port port=100:proto=tcp:toport=200"
assert_good " --query-forward-port=port=100:proto=tcp:toport=200"
assert_good " --query-forward-port=port=88:proto=udp:toport=99 --zone=${default_zone}"
assert_good "--remove-forward-port port=100:proto=tcp:toport=200 --remove-forward-port=port=88:proto=udp:toport=99"
assert_bad  " --query-forward-port port=100:proto=tcp:toport=200"
assert_bad  " --query-forward-port=port=88:proto=udp:toport=99"

assert_good "--permanent    --add-forward-port=port=88:proto=udp:toport=99 --add-forward-port port=100:proto=tcp:toport=200"
assert_good "--permanent  --query-forward-port=port=100:proto=tcp:toport=200"
assert_good "--permanent  --query-forward-port=port=88:proto=udp:toport=99 --zone=${default_zone}"
assert_good "--permanent --remove-forward-port port=100:proto=tcp:toport=200 --remove-forward-port=port=88:proto=udp:toport=99"
assert_bad  "--permanent  --query-forward-port port=100:proto=tcp:toport=200"
assert_bad  "--permanent  --query-forward-port=port=88:proto=udp:toport=99"

assert_good_contains "--zone=home --list-services" "ssh"
assert_good          "--zone home --list-ports"
assert_good          "--list-icmp-blocks"
assert_good          "--zone=home --list-forward-ports"

assert_good_contains "--permanent --zone=work --list-services" "ssh"
assert_good          "--permanent --list-forward-ports"

assert_bad           "--permanent --complete-reload" # impossible combination
assert_bad           "--permanent --zone=work --add-interface=dummy0" # impossible combination
assert_bad           "--permanent --add-interface=dummy0" # impossible combination
assert_bad           "--permanent --list-all" # impossible combination

# ... --direct  ...
assert_good_contains "--direct --passthrough ipv4 -nvL" "IN_ZONE_home_allow"
assert_bad           "--direct --passthrough ipv5 -nvL" # ipv5
assert_bad           "--direct --passthrough ipv4" # missing argument
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

assert_bad           "--direct --reload" # impossible combination
assert_bad           "--direct --list-all" # impossible combination
assert_bad           "--direct --get-services" # impossible combination
assert_bad           "--direct --get-default-zone" # impossible combination
assert_bad           "--direct --zone=home --list-services" # impossible combination
assert_bad           "--direct --permanent --list-all" # impossible combination
assert_bad           "--direct --passthrough --get-chains ipv4 filter" # impossible combination

echo "----------------------------------------------------------------------"
if [ ${failures} -eq 0 ]; then
    echo "Everything's OK, you rock :-)"
    exit 0
else
    echo "FAILED (failures=${failures})"
    exit 2
fi
