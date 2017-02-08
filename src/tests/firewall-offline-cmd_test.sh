#!/bin/bash

#readonly path="/usr/bin/"
readonly path="../"

readonly RED='\033[00;31m'
readonly GREEN='\033[00;32m'
readonly RESTORE='\033[0m'

assert_cmd_good() {
  local args="${1}"

  ${args} > /dev/null
  if [[ "$?" -eq 0 ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status)${RESTORE}"
  fi
}

assert_good() {
  local args="${1}"

  ${path}firewall-offline-cmd ${args} > /dev/null 2>&1
  if [[ "$?" -eq 0 ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status)${RESTORE}"
  fi
}

assert_good_notempty() {
  local args="${1}"
  local ret

  ret=$(${path}firewall-offline-cmd ${args}) > /dev/null 2>&1
  if [[ ( "$?" -eq 0 ) && ( -n "${ret}" ) ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or empty return value)${RESTORE}"
  fi
}

assert_good_empty() {
  local args="${1}"
  local ret

  ret=$(${path}firewall-offline-cmd ${args}) > /dev/null 2>&1
  if [[ ( "$?" -eq 0 ) && ( -z "${ret}" ) ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or non-empty return value)${RESTORE}"
  fi
}

assert_good_equals() {
  local args="${1}"
  local value="${2}"
  local ret

  ret=$(${path}firewall-offline-cmd ${args}) > /dev/null 2>&1
  if [[ ( "$?" -eq 0 ) && ( "${ret}" = "${value}" ) ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or '${ret}' != '${value}')${RESTORE}"
  fi
}

assert_good_contains() {
  local args="${1}"
  local value="${2}"
  local ret

  ret=$(${path}firewall-offline-cmd ${args}) > /dev/null 2>&1
  if [[ ( "$?" -eq 0 ) && ( "${ret}" = *${value}* ) ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or '${ret}' does not contain '${value}')${RESTORE}"
  fi
}

assert_bad() {
  local args="${1}"

  ${path}firewall-offline-cmd ${args} 1> /dev/null 2>&1 2>&1
  if [[ "$?" -ne 0 ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (zero exit status)${RESTORE}"
  fi
}

assert_bad_contains() {
  local args="${1}"
  local value="${2}"
  local ret

  ret=$(${path}firewall-offline-cmd ${args}) > /dev/null 2>&1
  if [[ ( "$?" -ne 0 ) || ( "${ret}" = *${value}* ) ]]; then
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (non-zero exit status or '${ret}' does contain '${value}')${RESTORE}"
  else
    echo "${args} ... OK"
  fi
}

# rich rules need separate assert methods because of quotation hell
assert_rich_good() {
  local operation="${1}"
  local args="${2}"
  local command

  if [[ "${operation}" = *add* ]]; then
    command="--add-rich-rule"
  elif [[ "${operation}" = *remove* ]]; then
    command="--remove-rich-rule"
  elif [[ "${operation}" = *query* ]]; then
    command="--query-rich-rule"
  fi

  ${path}firewall-offline-cmd ${command} "${args}" > /dev/null 2>&1
  if [[ "$?" -eq 0 ]]; then
    echo ${command} "${args} ... OK"
  else
    ((failures++))
    echo -e ${command} "${args} ... ${RED}${failures}. FAILED (non-zero exit status)${RESTORE}"
  fi
}

assert_rich_bad() {
  local operation="${1}"
  local args="${2}"
  local command

  if [[ "${operation}" = *add* ]]; then
    command="--add-rich-rule"
  elif [[ "${operation}" = *remove* ]]; then
    command="--remove-rich-rule"
  elif [[ "${operation}" = *query* ]]; then
    command="--query-rich-rule"
  fi

  ${path}firewall-offline-cmd ${command} "${args}" > /dev/null 2>&1
  if [[ "$?" -ne 0 ]]; then
    echo ${command} "${args} ... OK"
  else
    ((failures++))
    echo -e ${command} "${args} ... ${RED}${failures}. FAILED (zero exit status)${RESTORE}"
  fi
}

assert_exit_code() {
  local args="${1}"
  local ret="${2}"

  ${path}firewall-offline-cmd ${args} > /dev/null 2>&1
  got=$?
  if [[ "$got" -eq "$ret" ]]; then
    echo "${args} ... OK"
  else
    ((failures++))
    echo -e "${args} ... ${RED}${failures}. FAILED (bad exit status ${got} != ${ret})${RESTORE}"
  fi
}

test_lokkit_opts() {
rm -f /etc/firewalld/zones/*
assert_good "${lokkit_opts}"

assert_cmd_good "systemctl is-enabled firewalld.service"
assert_good     "--zone=trusted --query-interface=${trusted_iface1}"
assert_good     "--zone=trusted --query-interface=${trusted_iface2}"
assert_good     "--query-service ${service1}"
assert_good     "--query-service ${service2}"
assert_bad      "--query-service ${service3}"
assert_good     "--query-icmp-block ${icmp1}"
assert_good     "--query-icmp-block ${icmp2}"
assert_good     "--query-forward-port ${fw_port1}"
assert_good     "--query-forward-port ${fw_port2}"
}

# MAIN
failures=0

while true; do
    read -p "This test overwrites your /etc/firewalld/zones/* and /etc/sysconfig/system-config-firewall. Do you want to continue ?" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

assert_good "-h"
assert_good "--help"
assert_good "-V"

trusted_iface1="eth+"
trusted_iface2="em0"
service1="dns"
service2="ftp"
service3="dhcpv6-client"
icmp1="router-advertisement"
icmp2="router-solicitation"
fw_port1="port=13:proto=tcp:toport=15:toaddr=1.2.3.4"
fw_port2="port=333:proto=udp:toport=444"

lokkit_opts="--enabled --addmodule=abc --addmodule=efg --removemodule=xyz
 --trust=${trusted_iface1} --trust=${trusted_iface2}
 --masq=tun+ --masq=tap+ --port=7:tcp --port=666:udp
 --custom-rules=ipv4:mangle:/etc/sysconfig/ebtables-config
 --service=${service1} --service=${service2} --remove-service=${service3}
 --block-icmp=${icmp1} --block-icmp=${icmp2}
 --forward-port=if=ippp+:${fw_port1}
 --forward-port=if=ippp+:${fw_port2}"
test_lokkit_opts

cat << EOF > /etc/sysconfig/system-config-firewall
--enabled
--addmodule=abc
--addmodule=efg
--removemodule=xyz
--trust=${trusted_iface1}
--trust=${trusted_iface2}
--masq=tun+
--masq=tap+
--port=7:tcp
--port=666:udp
--custom-rules=ipv4:mangle:/etc/sysconfig/ebtables-config
--service=${service1}
--service=${service2}
--remove-service=${service3}
--block-icmp=${icmp1}
--block-icmp=${icmp2}
--forward-port=if=ippp+:${fw_port1}
--forward-port=if=ippp+:${fw_port2}
EOF

# running firewall-offline-cmd without options should import /etc/sysconfig/system-config-firewall
lokkit_opts=""
test_lokkit_opts

# disable dns again for later tests
assert_good --remove-service=${service1}

default_zone=$(${path}firewall-offline-cmd --get-default-zone 2>/dev/null)
zone="home"
assert_good_notempty "--get-default-zone"
assert_good          "--set-default-zone=${zone}"
assert_good_equals   "--get-default-zone" "${zone}"
assert_good          "--set-default-zone=${default_zone}"
assert_bad           "--set-default-zone" # missing argument

assert_good_notempty "--get-zones"
assert_good_notempty "--get-services"
assert_good_notempty "--get-icmptypes"

assert_good             "--list-all-zones"
assert_good             "--list-all"

iface="dummy0"
zone="work"
assert_good          "--zone=${zone} --add-interface=${iface}"
assert_good_equals   "--get-zone-of-interface=${iface}" "${zone}"
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

sources=( "dead:beef::babe" "3ffe:501:ffff::/64" "1.2.3.4" "192.168.1.0/24" )
for (( i=0;i<${#sources[@]};i++)); do
  zone="public"
  source=${sources[${i}]}
  assert_good          "--zone=${zone} --add-source=${source}"
  assert_good_equals   "--get-zone-of-source=${source}" "${zone}"
  assert_good_contains "--zone=${zone} --list-sources" "${source}"
  assert_good_contains "--zone=${zone} --list-all" "${source}"
  assert_good          "--zone ${zone} --query-source=${source}"
  zone="work"
  assert_good          "--zone=${zone} --change-source=${source}"
  assert_good_equals   "--get-zone-of-source=${source}" "${zone}"
  assert_good          "--zone=${zone} --remove-source=${source}"
  assert_bad           "--zone ${zone} --query-source=${source}"
  assert_bad           "--get-zone-of-source=${source}" # in no zone
  assert_bad           "--get-zone-of-source" # missing argument
done 

assert_good "   --add-service=dns --zone=${default_zone}"
assert_good " --query-service dns"
assert_good "--remove-service=dns"
assert_bad  " --query-service=dns"
assert_bad  "   --add-service=smtpssssssss" # bad service name
assert_bad  "   --add-service=dns --add-interface=dummy0" # impossible combination

assert_good "   --add-service=http --add-service=nfs"
assert_good " --query-service http"
assert_good " --query-service=nfs --zone=${default_zone}"
assert_good "--remove-service=nfs --remove-service=http"
assert_bad  " --query-service http"
assert_bad  " --query-service nfs"

assert_bad  "   --add-port=666" # no protocol
assert_bad  "   --add-port=666/dummy" # bad protocol
assert_good "   --add-port=666/tcp --zone=${default_zone}"
assert_good "--remove-port=666/tcp"
assert_good "   --add-port=111-222/udp"
assert_good " --query-port=111-222/udp --zone=${default_zone}"
assert_good "--remove-port 111-222/udp"
assert_bad  " --query-port=111-222/udp"

assert_good "   --add-port=80/tcp --add-port 443-444/udp"
assert_good " --query-port=80/tcp --zone=${default_zone}"
assert_good " --query-port=443-444/udp"
assert_good "--remove-port 80/tcp --remove-port=443-444/udp"
assert_bad  " --query-port=80/tcp"
assert_bad  " --query-port=443-444/udp"

assert_bad  "    --add-protocol=dummy" # bad protocol
assert_good "    --add-protocol=mux"
assert_good " --remove-protocol=mux     --zone=${default_zone}"
assert_good "    --add-protocol=dccp --zone=${default_zone}"
assert_good " --query-protocol=dccp"
assert_good "--remove-protocol dccp"
assert_bad  " --query-protocol=dccp"

assert_good "   --add-protocol=ddp --add-protocol gre"
assert_good " --query-protocol=ddp --zone=${default_zone}"
assert_good " --query-protocol=gre"
assert_good "--remove-protocol ddp --remove-protocol=gre"
assert_bad  " --query-protocol=ddp"
assert_bad  " --query-protocol=gre"

assert_bad  "   --add-source-port=666" # no protocol
assert_bad  "   --add-source-port=666/dummy" # bad protocol
assert_good "   --add-source-port=666/tcp --zone=${default_zone}"
assert_good "--remove-source-port=666/tcp"
assert_good "   --add-source-port=111-222/udp"
assert_good " --query-source-port=111-222/udp --zone=${default_zone}"
assert_good "--remove-source-port 111-222/udp"
assert_bad  " --query-source-port=111-222/udp"

assert_good "   --add-masquerade --zone=${default_zone}"
assert_good " --query-masquerade "
assert_good "--remove-masquerade"
assert_bad  " --query-masquerade"

assert_bad  "--zone=external    --add-icmp-block=dummyblock" # invalid icmp type
assert_good "--zone=external    --add-icmp-block=redirect"
assert_good "--zone=external  --query-icmp-block=redirect"

assert_good "   --add-icmp-block-inversion --zone=${default_zone}"
assert_good " --query-icmp-block-inversion "
assert_good "--remove-icmp-block-inversion"
assert_bad  " --query-icmp-block-inversion"

assert_good "--zone=external --remove-icmp-block redirect"
assert_bad  "--zone=external  --query-icmp-block=redirect"

assert_good "   --add-icmp-block-inversion --zone=block"
assert_good "--remove-icmp-block-inversion --zone=block"
assert_good "   --add-icmp-block-inversion --zone=drop"
assert_good "--remove-icmp-block-inversion --zone=drop"
assert_good "   --add-icmp-block-inversion --zone=trusted"
assert_good "--remove-icmp-block-inversion --zone=trusted"

assert_good "--zone=external    --add-icmp-block=echo-reply --add-icmp-block=router-solicitation"
assert_good "--zone=external  --query-icmp-block=echo-reply"
assert_good "--zone=external  --query-icmp-block=router-solicitation"
assert_good "--zone=external --remove-icmp-block echo-reply --remove-icmp-block=router-solicitation"
assert_bad  "--zone=external  --query-icmp-block=echo-reply"
assert_bad  "--zone=external  --query-icmp-block=router-solicitation"

assert_good "    --add-icmp-block-inversion"
assert_good "  --query-icmp-block-inversion --zone=${default_zone}"
assert_good " --remove-icmp-block-inversion --zone=${default_zone}"
assert_bad  "  --query-icmp-block-inversion"

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

assert_good "   --add-forward-port=port=88:proto=udp:toport=99 --add-forward-port port=100:proto=tcp:toport=200"
assert_good " --query-forward-port=port=100:proto=tcp:toport=200"
assert_good " --query-forward-port=port=88:proto=udp:toport=99 --zone=${default_zone}"
assert_good "--remove-forward-port port=100:proto=tcp:toport=200 --remove-forward-port=port=88:proto=udp:toport=99"
assert_bad  " --query-forward-port port=100:proto=tcp:toport=200"
assert_bad  " --query-forward-port=port=88:proto=udp:toport=99"

assert_good_contains "--zone=home --list-services" "ssh"
assert_good          "--zone home --list-ports"
assert_good          "--list-icmp-blocks"
assert_good          "--zone=home --list-forward-ports"

myzone="myzone"
myservice="myservice"
myicmp="myicmp"

# create new zone
assert_good "--new-zone=${myzone}"
assert_good_contains "--get-zones" "${myzone}"
# get/set default target
assert_good_contains "--zone=${myzone} --get-target" "default"
assert_bad "--zone=${myzone} --set-target=BAD"
assert_good "--zone=${myzone} --set-target=%%REJECT%%"
assert_good "--zone=${myzone} --set-target=DROP"
assert_good "--zone=${myzone} --set-target=ACCEPT"
assert_good_contains "--zone=${myzone} --get-target" "ACCEPT"
# create new service and icmptype
assert_good "--new-service=${myservice}"
assert_good_contains "--get-services" "${myservice}"
assert_good "--new-icmptype=${myicmp}"
assert_good_contains "--get-icmptypes" "${myicmp}"

# test service options
assert_bad  "--service=${myservice} --add-port=666" # no protocol
assert_bad  "--service=${myservice} --add-port=666/dummy" # bad protocol
assert_good "--service=${myservice} --add-port=666/tcp"
assert_good "--service=${myservice} --remove-port=666/tcp"
assert_good "--service=${myservice} --add-port=111-222/udp"
assert_good "--service=${myservice} --query-port=111-222/udp"
assert_good "--service=${myservice} --remove-port 111-222/udp"
assert_bad  "--service=${myservice} --query-port=111-222/udp"

assert_good "--service=${myservice} --add-protocol=ddp --add-protocol gre"
assert_good "--service=${myservice} --query-protocol=ddp"
assert_good "--service=${myservice} --query-protocol=gre"
assert_good "--service=${myservice} --remove-protocol ddp"
assert_good "--service=${myservice} --remove-protocol gre"
assert_bad  "--service=${myservice} --query-protocol=ddp"
assert_bad  "--service=${myservice} --query-protocol=gre"

assert_bad  "--service=${myservice} --add-source-port=666" # no protocol
assert_bad  "--service=${myservice} --add-source-port=666/dummy" # bad protocol
assert_good "--service=${myservice} --add-source-port=666/tcp"
assert_good "--service=${myservice} --remove-source-port=666/tcp"
assert_good "--service=${myservice} --add-source-port=111-222/udp"
assert_good "--service=${myservice} --query-source-port=111-222/udp"
assert_good "--service=${myservice} --remove-source-port 111-222/udp"
assert_bad  "--service=${myservice} --query-source-port=111-222/udp"

assert_good "--service=${myservice} --add-module=sip"
assert_good "--service=${myservice} --remove-module=sip"
assert_good "--service=${myservice} --add-module=ftp"
assert_good "--service=${myservice} --query-module=ftp"
assert_good "--service=${myservice} --remove-module=ftp"
assert_bad "--service=${myservice} --query-module=ftp"

assert_bad  "--service=${myservice} --set-destination=ipv4" # no address
assert_bad  "--service=${myservice} --set-destination=ipv4:foo" # bad address
assert_good "--service=${myservice} --set-destination=ipv4:1.2.3.4"
assert_good "--service=${myservice} --remove-destination=ipv4"
assert_good "--service=${myservice} --set-destination=ipv6:fd00:dead:beef:ff0::/64"
assert_good "--service=${myservice} --query-destination=ipv6:fd00:dead:beef:ff0::/64"
assert_good "--service=${myservice} --remove-destination=ipv6"
assert_bad "--service=${myservice} --query-destination=ipv6:fd00:dead:beef:ff0::/64"

# test icmptype options, ipv4 and ipv6 destinations are default
assert_bad  "--icmptype=${myicmp} --add-destination=ipv5"
assert_good "--icmptype=${myicmp} --add-destination=ipv4"
assert_good "--icmptype=${myicmp} --remove-destination=ipv4"
assert_good "--icmptype=${myicmp} --add-destination=ipv4"
assert_good "--icmptype=${myicmp} --query-destination=ipv4"
assert_good "--icmptype=${myicmp} --remove-destination=ipv4"
assert_bad "--icmptype=${myicmp} --query-destination=ipv4"

# add them to zone
assert_good "--zone=${myzone} --add-service=${myservice}"
assert_good "--zone=${myzone} --add-icmp-block=${myicmp}"
assert_good_contains "--zone=${myzone} --list-services" "${myservice}"
assert_good_contains "--zone=${myzone} --list-icmp-blocks" "${myicmp}"
# delete the service and icmptype
assert_good "--delete-service=${myservice}"
assert_good "--delete-icmptype=${myicmp}"
# make sure they were removed also from the zone
assert_good_empty "--zone=${myzone} --list-services" "${myservice}"
assert_good_empty "--zone=${myzone} --list-icmp-blocks" "${myicmp}"
# delete the zone
assert_good "--delete-zone=${myzone}"

# ipset tests
ipset="myipset"
source="ipset:${ipset}"
zone="public"
assert_good "--new-ipset=${ipset} --type=hash:ip"
assert_good_empty "--ipset=${ipset} --get-entries"
assert_good "--ipset=${ipset} --add-entry=1.2.3.4"
assert_good_notempty "--ipset=${ipset} --get-entries"
assert_bad "--ipset=${ipset} --add-entry=1.2.3.400"
assert_good "--ipset=${ipset} --remove-entry=1.2.3.4"
assert_good_empty "--ipset=${ipset} --get-entries"

assert_good "--zone=${zone} --add-source=${source}"
assert_good_contains "--get-zone-of-source=${source}" "${zone}"
assert_good_contains "--zone=public --list-sources" "${source}"
assert_good "--zone=${zone} --query-source=${source}"
assert_good "--zone=${zone} --remove-source=${source}"

assert_good "--delete-ipset=${ipset}"

# helper tests
myhelper="myhelper"
assert_bad "--new-helper=${myhelper} --module=foo"
assert_good "--new-helper=${myhelper} --module=nf_conntrack_foo"
assert_good_contains "--get-helpers" "${myhelper}"
assert_good_empty "--helper=${myhelper} --get-family"
assert_bad "--helper=${myhelper} --set-family=ipv5"
assert_good "--helper=${myhelper} --set-family=ipv4"
assert_good_equals "--helper=${myhelper} --get-family" "ipv4"
assert_good "--helper=${myhelper} --set-family="
assert_good_empty "--helper=${myhelper} --get-family"
assert_good_empty "--helper=${myhelper} --get-ports"
assert_good "--helper=${myhelper} --add-port=44/tcp"
assert_good_notempty "--helper=${myhelper} --get-ports"
assert_good "--helper=${myhelper} --query-port=44/tcp"
assert_good "--helper=${myhelper} --remove-port=44/tcp"
assert_bad "--helper=${myhelper} --query-port=44/tcp"
assert_good_empty "--helper=${myhelper} --get-ports"
assert_good "--delete-helper=${myhelper}"
assert_bad_contains "--get-helpers" "${myhelper}"

# exit return value tests
assert_exit_code "--remove-port 122/udp" 0
assert_exit_code "--add-port 122/udpp" 103
assert_exit_code "--add-port 122/udp --add-port 122/udpp" 0
assert_exit_code "--add-port 122/udp --add-port 122/udpp" 0
assert_exit_code "--add-port 122/udp --add-port 122/udpp --add-port 8745897/foo" 0
assert_exit_code "--add-port 122/udp --add-port 122/udpp --add-port 8745897/foo --add-port bar" 0
assert_exit_code "--add-port 122/udpa --add-port 122/udpp" 103
assert_exit_code "--add-port 122/udpa --add-port 122/udpp" 103
assert_exit_code "--add-port 122/udpa --add-port 122/udpp --add-port 8745897/foo" 254
assert_exit_code "--add-port 122/udpa --add-port 122/udpp --add-port 8745897/foo --add-port bar" 254
assert_exit_code "--add-port 122/udp --add-port 122/udp" 0
assert_exit_code "--remove-port 122/udp" 0

# ... --direct ...
assert_bad           "--direct --add-passthrough ipv7 --table filter -A INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT" # bad ipv
assert_good          "--direct --add-passthrough ipv4 --table filter --append INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT"
assert_bad           "--direct --query-passthrough ipv7 --table filter -A INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT" # bad ipv
assert_good          "--direct --query-passthrough ipv4 --table filter --append INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT"
assert_bad           "--direct --remove-passthrough ipv7 --table filter -A INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT" # bad ipv
assert_good          "--direct --remove-passthrough ipv4 --table filter --append INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT"
assert_bad           "--direct --query-passthrough ipv4 --table filter --append INPUT --in-interface dummy0 --protocol tcp --destination-port 67 --jump ACCEPT"

assert_good          "--direct --add-passthrough ipv6 --table filter --append FORWARD --destination fd00:dead:beef:ff0::/64 --in-interface dummy0 --out-interface dummy0 --jump ACCEPT"
assert_good_contains "--direct --get-passthroughs ipv6" "fd00:dead:beef:ff0::/64"
assert_good_contains "--direct --get-all-passthroughs" "fd00:dead:beef:ff0::/64"
assert_good          "--direct --remove-passthrough ipv6 --table filter --append FORWARD --destination fd00:dead:beef:ff0::/64 --in-interface dummy0 --out-interface dummy0 --jump ACCEPT"

assert_good          "--direct --add-chain ipv4 filter mychain"
assert_good_contains "--direct --get-chains ipv4 filter" "mychain"
assert_good_contains "--direct --get-all-chains" "ipv4 filter mychain"
assert_good          "--direct --query-chain ipv4 filter mychain"
assert_bad           "--direct --add-chain ipv5 filter mychain" # bad ipv
assert_bad           "--direct --add-chain ipv4 badtable mychain" # bad table name

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

assert_bad           "--direct --reload" # impossible combination
assert_bad           "--direct --list-all" # impossible combination
assert_bad           "--direct --get-services" # impossible combination
assert_bad           "--direct --get-default-zone" # impossible combination
assert_bad           "--direct --zone=home --list-services" # impossible combination

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


# rich rules

bad_rules=(
 ''                                                         # empty
 'family="ipv6" accept'                                     # no 'rule'
 'name="dns" accept'                                        # no 'rule'
 'protocol value="ah" reject'                               # no 'rule'
 'rule protocol value="ah" reject type="icmp-host-prohibited"' # reject type needs specific family
 'rule family="ipv4" protocol value="ah" reject type="dummy"'  # dummy reject type
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
 'rule family="ipv6" source address="1:2:3:4:6::" service name="radius" log prefix="dns" level="info" limit value="3/m" reject type="icmp6-addr-unreachable" limit value="20/m"'
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

echo "----------------------------------------------------------------------"
if [[ "${failures}" -eq 0 ]]; then
    echo "Everything's OK, you rock :-)"
    exit 0
else
    echo "FAILED (failures=${failures})"
    exit 2
fi
