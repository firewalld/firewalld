#!/bin/bash
# requires libxml2 packages for xmllint

cd ..
for keyword in zone service icmptype; do
  echo "  ---  ${keyword}s  ---"
  pushd "${keyword}s"
  for i in *.xml; do
    xmllint --noout --schema ../xmlschema/${keyword}.xsd "${i}"
  done
  popd
done
