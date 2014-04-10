#!/bin/sh
set -e

files=`find . -name '*.cc' -print | xargs grep -l 'flush;'`

for i in $files ; do
  sed 's/<< flush;/<< flush, fflush(NULL);/g' <$i >$i.tmp
  mv $i.tmp $i
done

exit 0
