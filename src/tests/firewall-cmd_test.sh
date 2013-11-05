#!/bin/bash

path="/usr/bin/"
#path="../"

RED='\033[00;31m'
GREEN='\033[00;32m'
RESTORE='\033[0m'

assert_good() {
  args="${1}"
  ${path}firewall-cmd ${args} > /dev/null
  if [ $? == 0 ]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status)${RESTORE}"
  fi
}

assert_good_notempty() {
  args="${1}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a -n "${ret}" ]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or empty return value)${RESTORE}"
  fi
}

assert_good_empty() {
  args="${1}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a -z "${ret}" ]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or non-empty return value)${RESTORE}"
  fi
}

assert_good_equals() {
  args="${1}"
  value="${2}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [ $? == 0 -a "${ret}" == "${value}" ]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or '${ret}' != '${value}')${RESTORE}"
  fi
}

assert_good_contains() {
  args="${1}"
  value="${2}"
  ret=$(${path}firewall-cmd ${args}) > /dev/null
  if [[ ( $? == 0 ) && ( "${ret}" = *${value}* ) ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or '${ret}' does not contain '${value}')${RESTORE}"
  fi
}

assert_bad() {
  args="${1}"
  ${path}firewall-cmd ${args} 1> /dev/null 2>&1
  if [ $? != 0 ]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (zero exit status)${RESTORE}"
  fi
}

# rich rules need separate assert methods because of quotation hell
assert_rich_good() {
  operation="${1}"
  args="${2}"
  [[ "${operation}" = *permanent* ]] && permanent="--permanent"
  if [[ "${operation}" = *add* ]]; then
    command="--add-rich-rule"
  elif [[ "${operation}" = *remove* ]]; then
    command="--remove-rich-rule"
  elif [[ "${operation}" = *query* ]]; then
    command="--query-rich-rule"
  fi

  ${path}firewall-cmd ${permanent} ${command} "${args}" > /dev/null
  if [ $? == 0 ]; then
    echo ${permanent} ${command} "${args} ... OK"
  else
    ((failures++))
    echo -e ${permanent} ${command} "${args} ... ${RED}${failures}. FAILED (non-zero exit status)${RESTORE}"
  fi
}

assert_rich_bad() {
  operation="${1}"
  args="${2}"
  [[ "${operation}" = *permanent* ]] && permanent="--permanent"
  if [[ "${operation}" = *add* ]]; then
    command="--add-rich-rule"
  elif [[ "${operation}" = *remove* ]]; then
    command="--remove-rich-rule"
  elif [[ "${operation}" = *query* ]]; then
    command="--query-rich-rule"
  fi

  ${path}firewall-cmd ${permanent} ${command} "${args}" > /dev/null
  if [ $? != 0 ]; then
    echo ${permanent} ${command} "${args} ... OK"
  else
    ((failures++))
    echo -e ${permanent} ${command} "${args} ... ${RED}${failures}. FAILED (zero exit status)${RESTORE}"
  fi
}

${path}firewall-cmd --state --quiet
if [ $? != 0 ]; then
  echo "FirewallD is not running"
  exit $?
fi

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
#assert_good "--lockdown-on"
#assert_good "--query-lockdown"
#assert_good "--lockdown-off"
#assert_bad  "--query-lockdown"


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

assert_good             "--list-all-zones"
assert_good             "--list-all"
assert_good "--permanent --list-all-zones"
assert_good "--permanent --list-all"

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
assert_good          "--zone=${zone} --change-interface=${iface}" # should work as add
assert_good          "--zone=${zone} --query-interface ${iface}"
assert_good          "--zone=${zone} --remove-interface=${iface}"
assert_bad           "--zone=${zone} --query-interface ${iface}"
assert_bad           "--get-zone-of-interface=${iface}" # in no zone
assert_bad           "--get-zone-of-interface" # missing argument
assert_bad           "--zone=${zone} --get-zones" # impossible combination
assert_bad           "--zone=${zone} --get-services" # impossible combination
assert_bad           "--zone=${zone} --get-default-zone" # impossible combination
assert_bad           "--zone=${zone} --set-default-zone" # impossible combination
assert_bad           "--zone=${zone} --get-zone-of-interface" # impossible combination

iface="perm_dummy0"
zone="work"
assert_good          "--permanent --zone=${zone} --add-interface=${iface}"
assert_good_equals   "--permanent --get-zone-of-interface=${iface}" "${zone}"
assert_good          "--permanent --zone ${zone} --query-interface=${iface}"
assert_good_contains "--permanent --zone=${zone} --list-interfaces" "${iface}"
zone="public"
assert_bad           "--permanent --zone=${zone} --add-interface=${iface}" # already in another zone
assert_good          "--permanent --zone=${zone} --change-interface=${iface}"
assert_good_equals   "--permanent --get-zone-of-interface=${iface}" "${zone}"
assert_good          "--permanent --zone=${zone} --remove-interface=${iface}"
assert_bad           "--permanent --zone=${zone} --query-interface ${iface}"
assert_good          "--permanent --zone=${zone} --change-interface=${iface}" # should work as add
assert_good_equals   "--permanent --get-zone-of-interface=${iface}" "${zone}"
assert_good          "--permanent --zone=${zone} --remove-interface=${iface}"
assert_bad           "--permanent --zone=${zone} --query-interface ${iface}"

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

sources=( "dead:beef::babe" "3ffe:501:ffff::/64" "1.2.3.4" "192.168.1.0/24" )
for (( i=0;i<${#sources[@]};i++)); do
  zone="public"
  source=${sources[${i}]}
  assert_good          "--zone=${zone} --add-source=${source}"
  assert_good_equals   "--get-zone-of-source=${source}" "${zone}"
  assert_good_contains "--zone=${zone} --list-sources" "${source}"
  assert_good_contains "--zone=${zone} --list-all" "${source}"
  assert_good_contains "--get-active-zones" "${source}"
  assert_good          "--zone ${zone} --query-source=${source}"
  zone="work"
  assert_good          "--zone=${zone} --change-source=${source}"
  assert_good_equals   "--get-zone-of-source=${source}" "${zone}"
  assert_good          "--zone=${zone} --remove-source=${source}"
  assert_bad           "--zone ${zone} --query-source=${source}"
  assert_bad           "--get-zone-of-source=${source}" # in no zone
  assert_bad           "--get-zone-of-source" # missing argument
done 

for (( i=0;i<${#sources[@]};i++)); do
  zone="public"
  source=${sources[${i}]}
  assert_good          "--permanent --zone=${zone} --add-source=${source}"
  assert_good_equals   "--permanent --get-zone-of-source=${source}" "${zone}"
  assert_good_contains "--permanent --zone=${zone} --list-sources" "${source}"
  assert_good_contains "--permanent --zone=${zone} --list-all" "${source}"
  assert_good          "--permanent --zone ${zone} --query-source=${source}"
  zone="work"
  assert_bad           "--permanent --zone=${zone} --add-source=${source}" # already in another zone
  assert_good          "--permanent --zone=${zone} --change-source=${source}"
  assert_good_equals   "--permanent --get-zone-of-source=${source}" "${zone}"
  assert_good          "--permanent --zone=${zone} --remove-source=${source}"
  assert_bad           "--permanent --zone ${zone} --query-source=${source}"
done

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

# ... --direct  ...
assert_good_contains "--direct --passthrough ipv4 -nvL" "IN_home_allow"
assert_bad           "--direct --passthrough ipv5 -nvL" # ipv5
assert_bad           "--direct --passthrough ipv4" # missing argument
assert_bad           "--direct --get-all-passthroughs" # --permanent only

assert_good          "--direct --add-chain ipv4 filter mychain"
assert_good_contains "--direct --get-chains ipv4 filter" "mychain"
assert_good_contains "--direct --get-all-chains" "ipv4 filter mychain"
assert_good          "--direct --query-chain ipv4 filter mychain"

assert_good          "--direct --add-rule ipv4 filter mychain 3 -j ACCEPT"
assert_good_contains "--direct --get-rules ipv4 filter mychain" "3 -j ACCEPT"
assert_good_contains "--direct --get-all-rules" "ipv4 filter mychain 3 -j ACCEPT"
assert_good          "--direct --query-rule ipv4 filter mychain 3 -j ACCEPT"
assert_good          "--direct --remove-rule ipv4 filter mychain 3 -j ACCEPT"
assert_bad           "--direct --query-rule ipv4 filter mychain 3 -j ACCEPT"

assert_good          "--direct --add-rule ipv4 filter mychain 3 -s 192.168.1.1 -j ACCEPT"
assert_good          "--direct --add-rule ipv4 filter mychain 4 -s 192.168.1.2 -j ACCEPT"
assert_good          "--direct --add-rule ipv4 filter mychain 5 -s 192.168.1.3 -j ACCEPT"
assert_good          "--direct --add-rule ipv4 filter mychain 6 -s 192.168.1.4 -j ACCEPT"
assert_good_contains "--direct --get-rules ipv4 filter mychain" "3 -s 192.168.1.1 -j ACCEPT"
assert_good_contains "--direct --get-rules ipv4 filter mychain" "4 -s 192.168.1.2 -j ACCEPT"
assert_good_contains "--direct --get-rules ipv4 filter mychain" "5 -s 192.168.1.3 -j ACCEPT"
assert_good_contains "--direct --get-rules ipv4 filter mychain" "6 -s 192.168.1.4 -j ACCEPT"
assert_good          "--direct --remove-rules ipv4 filter mychain"
assert_bad           "--direct --query-rule ipv4 filter mychain 3 -s 192.168.1.1 -j ACCEPT"
assert_bad           "--direct --query-rule ipv4 filter mychain 4 -s 192.168.1.2 -j ACCEPT"
assert_bad           "--direct --query-rule ipv4 filter mychain 5 -s 192.168.1.3 -j ACCEPT"
assert_bad           "--direct --query-rule ipv4 filter mychain 6 -s 192.168.1.4 -j ACCEPT"

assert_good          "--direct --remove-chain ipv4 filter mychain"
assert_bad           "--direct --query-chain ipv4 filter mychain"
assert_good          "--direct --remove-chain ipv4 filter dummy" # removing nonexisting chain is just warning

assert_bad           "--direct --reload" # impossible combination
assert_bad           "--direct --list-all" # impossible combination
assert_bad           "--direct --get-services" # impossible combination
assert_bad           "--direct --get-default-zone" # impossible combination
assert_bad           "--direct --zone=home --list-services" # impossible combination
assert_bad           "--direct --permanent --list-all" # impossible combination
assert_bad           "--direct --passthrough --get-chains ipv4 filter" # impossible combination

# ... --permanent --direct ...
assert_bad           "--permanent --direct --add-passthrough ipv4" # missing argument
assert_good          "--permanent --direct --add-passthrough ipv4 -nvL"
assert_good_contains "--permanent --direct --get-passthroughs ipv4" "-nvL"
assert_good_contains "--permanent --direct --get-all-passthroughs" "ipv4 -nvL"
assert_good          "--permanent --direct --query-passthrough ipv4 -nvL"
assert_good          "--permanent --direct --remove-passthrough ipv4 -nvL"
assert_bad           "--permanent --direct --query-passthrough ipv4 -nvL"

# try some non-ascii magic
mychain_p="žluťoučký"
assert_good          "--permanent --direct --add-chain ipv4 filter ${mychain_p}"
assert_good_contains "--permanent --direct --get-chains ipv4 filter" "${mychain_p}"
assert_good_contains "--permanent --direct --get-all-chains" "ipv4 filter ${mychain_p}"
assert_good          "--permanent --direct --query-chain ipv4 filter ${mychain_p}"

assert_good          "--permanent --direct --add-rule ipv4 filter ${mychain_p} 3 -j ACCEPT"
assert_good_contains "--permanent --direct --get-rules ipv4 filter ${mychain_p}" "ACCEPT"
assert_good_contains "--permanent --direct --get-all-rules" "ipv4 filter ${mychain_p} 3 -j ACCEPT"
assert_good          "--permanent --direct --query-rule ipv4 filter ${mychain_p} 3 -j ACCEPT"
assert_good          "--permanent --direct --remove-rule ipv4 filter ${mychain_p} 3 -j ACCEPT"
assert_bad           "--permanent --direct --query-rule ipv4 filter ${mychain_p} 3 -j ACCEPT"

assert_good          "--permanent --direct --add-rule ipv4 filter ${mychain_p} 3 -s 192.168.1.1 -j ACCEPT"
assert_good          "--permanent --direct --add-rule ipv4 filter ${mychain_p} 4 -s 192.168.1.2 -j ACCEPT"
assert_good          "--permanent --direct --add-rule ipv4 filter ${mychain_p} 5 -s 192.168.1.3 -j ACCEPT"
assert_good          "--permanent --direct --add-rule ipv4 filter ${mychain_p} 6 -s 192.168.1.4 -j ACCEPT"
assert_good_contains "--permanent --direct --get-rules ipv4 filter ${mychain_p}" "3 -s 192.168.1.1 -j ACCEPT"
assert_good_contains "--permanent --direct --get-rules ipv4 filter ${mychain_p}" "4 -s 192.168.1.2 -j ACCEPT"
assert_good_contains "--permanent --direct --get-rules ipv4 filter ${mychain_p}" "5 -s 192.168.1.3 -j ACCEPT"
assert_good_contains "--permanent --direct --get-rules ipv4 filter ${mychain_p}" "6 -s 192.168.1.4 -j ACCEPT"
assert_good          "--permanent --direct --remove-rules ipv4 filter ${mychain_p}"
assert_bad           "--permanent --direct --query-rule ipv4 filter ${mychain_p} 3 -s 192.168.1.1 -j ACCEPT"
assert_bad           "--permanent --direct --query-rule ipv4 filter ${mychain_p} 4 -s 192.168.1.2 -j ACCEPT"
assert_bad           "--permanent --direct --query-rule ipv4 filter ${mychain_p} 5 -s 192.168.1.3 -j ACCEPT"
assert_bad           "--permanent --direct --query-rule ipv4 filter ${mychain_p} 6 -s 192.168.1.4 -j ACCEPT"

assert_good          "--permanent --direct --remove-chain ipv4 filter ${mychain_p}"
assert_bad           "--permanent --direct --query-chain ipv4 filter ${mychain_p}"
assert_good          "--permanent --direct --remove-chain ipv4 filter dummy" # removing nonexisting chain is just warning

# lockdown

cmd="/usr/bin/command"
ctxt="system_u:system_r:MadDaemon_t:s0"
uid="6666"
user="theboss"

assert_good          "--add-lockdown-whitelist-command ${cmd}"
assert_good          "--query-lockdown-whitelist-command ${cmd}"
assert_good_contains "--list-lockdown-whitelist-commands" "${cmd}"
assert_good          "--remove-lockdown-whitelist-command ${cmd}"
assert_bad           "--query-lockdown-whitelist-command ${cmd}"  # already removed

assert_good          "--add-lockdown-whitelist-context ${ctxt}"
assert_good          "--query-lockdown-whitelist-context ${ctxt}"
assert_good_contains "--list-lockdown-whitelist-contexts" "${ctxt}"
assert_good          "--remove-lockdown-whitelist-context ${ctxt}"
assert_bad           "--query-lockdown-whitelist-context ${ctxt}"  # already removed

assert_good          "--add-lockdown-whitelist-uid ${uid}"
assert_good          "--query-lockdown-whitelist-uid ${uid}"
assert_good_contains "--list-lockdown-whitelist-uids" "${uid}"
assert_good          "--remove-lockdown-whitelist-uid ${uid}"
assert_bad           "--query-lockdown-whitelist-uid ${uid}"   # already removed
assert_bad           "--add-lockdown-whitelist-uid ${uid}x"    # bad uid

assert_good          "--add-lockdown-whitelist-user ${user}"
assert_good          "--query-lockdown-whitelist-user ${user}"
assert_good_contains "--list-lockdown-whitelist-users" "${user}"
assert_good          "--remove-lockdown-whitelist-user ${user}"
assert_bad           "--query-lockdown-whitelist-user ${user}"  # already removed

assert_good          "--permanent --add-lockdown-whitelist-command ${cmd}"
assert_good          "--permanent --query-lockdown-whitelist-command ${cmd}"
assert_good_contains "--permanent --list-lockdown-whitelist-commands" "${cmd}"
assert_good          "--permanent --remove-lockdown-whitelist-command ${cmd}"
assert_bad           "--permanent --query-lockdown-whitelist-command ${cmd}"  # already removed

assert_good          "--permanent --add-lockdown-whitelist-context ${ctxt}"
assert_good          "--permanent --query-lockdown-whitelist-context ${ctxt}"
assert_good_contains "--permanent --list-lockdown-whitelist-contexts" "${ctxt}"
assert_good          "--permanent --remove-lockdown-whitelist-context ${ctxt}"
assert_bad           "--permanent --query-lockdown-whitelist-context ${ctxt}"  # already removed

assert_good          "--permanent --add-lockdown-whitelist-uid ${uid}"
assert_good          "--permanent --query-lockdown-whitelist-uid ${uid}"
assert_good_contains "--permanent --list-lockdown-whitelist-uids" "${uid}"
assert_good          "--permanent --remove-lockdown-whitelist-uid ${uid}"
assert_bad           "--permanent --query-lockdown-whitelist-uid ${uid}"   # already removed
assert_bad           "--permanent --add-lockdown-whitelist-uid ${uid}x"    # bad uid

assert_good          "--permanent --add-lockdown-whitelist-user ${user}"
assert_good          "--permanent --query-lockdown-whitelist-user ${user}"
assert_good_contains "--permanent --list-lockdown-whitelist-users" "${user}"
assert_good          "--permanent --remove-lockdown-whitelist-user ${user}"
assert_bad           "--permanent --query-lockdown-whitelist-user ${user}"  # already removed


# rich rules

bad_rules=(
 ''                                                         # empty
 'family="ipv6" accept'                                     # no 'rule'
 'name="dns" accept'                                        # no 'rule'
 'protocol value="ah" reject'                               # no 'rule'
 'rule'                                                     # no element
 'rule bad_element'                                         # no unknown element
 'rule family="ipv5"'                                       # bad family
 'rule name="dns" accept'                                   # name outside of element
 'rule protocol="ah" accept'                                # bad protocol usage
 'rule protocol value="ah" accept drop'                     # accept && drop
 'rule service name="radius" port port="4011" reject'       # service && port
 'rule service bad_attribute="dns"'                         # bad attribute
 'rule protocol value="mtp" log level="eror"'               # bad log level
 'rule source address="1:2:3:4:6::" icmp-block name="redirect" log level="info" limit value="1/2m"'         # bad limit
 'rule protocol value="esp"'                                # no action/log/audit
)

for (( i=0;i<${#bad_rules[@]};i++)); do
  rule=${bad_rules[${i}]}
  assert_rich_bad           "add"    "${rule}"
done

good_rules=(
 'rule service name="ftp" audit limit value="1/m" accept'
 'rule protocol value="ah" reject'
 'rule protocol value="esp" accept'
 'rule protocol value="sctp" log'
 'rule family="ipv4" source address="192.168.0.0/24" service name="tftp" log prefix="tftp" level="info" limit value="1/m" accept'
 'rule family="ipv4" source NOT address="192.168.0.0/24" service name="dns" log prefix="dns" level="info" limit value="2/m" drop'
 'rule family="ipv6" source address="1:2:3:4:6::" service name="radius" log prefix="dns" level="info" limit value="3/m" reject limit value="20/m"'
 'rule family="ipv6" source address="1:2:3:4:6::" port port="4011" protocol="tcp" log prefix="port 4011/tcp" level="info" limit value="4/m" drop'
 'rule family="ipv6" source address="1:2:3:4:6::" forward-port port="4011" protocol="tcp" to-port="4012" to-addr="1::2:3:4:7"'
 'rule family="ipv4" source address="192.168.0.0/24" icmp-block name="source-quench" log prefix="source-quench" level="info" limit value="4/m"'
 'rule family="ipv6" source address="1:2:3:4:6::" icmp-block name="redirect" log prefix="redirect" level="info" limit value="4/m"'
 'rule family="ipv4" source address="192.168.1.0/24" masquerade'
 'rule family="ipv6" masquerade'
 'rule forward-port port="2222" to-port="22" to-addr="192.168.100.2" protocol="tcp" family="ipv4" source address="192.168.2.100"')

for (( i=0;i<${#good_rules[@]};i++)); do
  rule=${good_rules[${i}]}
  assert_rich_good          "add"    "${rule}"
  assert_rich_good          "query"  "${rule}"
  assert_rich_good          "remove" "${rule}"
  assert_rich_bad           "query"  "${rule}"
done

for (( i=0;i<${#good_rules[@]};i++)); do
  rule=${good_rules[${i}]}
  assert_rich_good          "permanent add"    "${rule}"
  assert_rich_good          "permanent query"  "${rule}"
  assert_rich_good          "permanent remove" "${rule}"
  assert_rich_bad           "permanent query"  "${rule}"
done

echo "----------------------------------------------------------------------"
if [ ${failures} -eq 0 ]; then
    echo "Everything's OK, you rock :-)"
    exit 0
else
    echo "FAILED (failures=${failures})"
    exit 2
fi
