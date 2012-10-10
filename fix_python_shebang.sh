#!/bin/bash

sed -e "s@^#\!/usr/bin/python\$@#\!/usr/bin/python -Es@" -i $@
