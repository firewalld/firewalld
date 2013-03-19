#!/bin/bash
# requires libxml2 packages for xmllint

cd ..
for keyword in zone service icmptype; do
  echo "  ---  ${keyword}s  ---"
  cd "${keyword}s"
  for i in `ls *.xml`; do
    # for each XML add a reference to an XML Schema, copy output to backup
    sed -e "s,^<${keyword},<${keyword}\nxmlns=\"http://www.w3schools.com\"\nxmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\nxsi:schemaLocation=\"http://www.w3schools.com ${keyword}.xsd\",i" "${i}" > "_${i}"
    # validate backup
    xmllint --noout --schema ../xmlschema/${keyword}.xsd "_${i}"
    # remove backup
    rm "_${i}"
  done
  cd ..
done
