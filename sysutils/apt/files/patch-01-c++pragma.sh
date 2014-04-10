#!/bin/sh
# must be run from ${worksrcpath}
# provided by Peter O'Gorman:
for i in `grep -rl '#ifdef __GNUG__' .` ; do perl -pi -e 's/#ifdef __GNUG__/#if defined(__GNUG__) && !defined(__APPLE_CC__)/' $i; done
