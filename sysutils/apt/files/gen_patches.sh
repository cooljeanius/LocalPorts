#!/bin/sh

# these are only the patches that are single files:
for file_to_patch in configure.ac configure buildlib/environment.mak.in apt-pkg/deb/dpkgpm.cc buildlib/ostable buildlib/library.mak apt-pkg/contrib/system.h apt-inst/deb/dpkgdb.cc aclocal.m4 acinclude.m4 apt-pkg/init.h; do diff -wub ${file_to_patch}.orig ${file_to_patch} > /opt/local/var/macports/sources/LocalPorts/sysutils/apt/files/patch-`echo ${file_to_patch} | tr \/ \_`.diff; done
# (some used the -r flag originally, but that is only applicable when patching
# multiple files and there are subdirectories present, and the above are all
# single-file patches)

# patch-01-c++pragma.diff generated with the following, provided by
# Peter O'Gorman:
# for i in `grep -rl '#ifdef __GNUG__' .` ; do perl -pi -e 's/#ifdef
# __GNUG__/#if defined(__GNUG__) && !defined(__APPLE_CC__)/' $i; done

# the following are also all multi-file patches:
# - patch-use-libintl.diff
# - patch-static-constructors.diff
# - patch-paths.diff
