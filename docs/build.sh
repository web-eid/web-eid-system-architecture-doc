#!/bin/bash

set -eu

DATE_STR=$(LANG='en_US' date '+%B %e, %Y')

sed -i "s/<<DATE>>/${DATE_STR}/" *.md

for f in *.md
do
	pandoc $f -s -o "${1}/${f/%.md/.pdf}" --number-sections
done
