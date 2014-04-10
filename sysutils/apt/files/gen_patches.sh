#!/bin/sh

# these are only the patches that are single files:
for file_to_patch in configure.ac configure buildlib/environment.mak.in apt-pkg/deb/dpkgpm.cc buildlib/ostable buildlib/library.mak apt-pkg/contrib/system.h apt-inst/deb/dpkgdb.cc aclocal.m4 acinclude.m4 apt-pkg/init.h apt-pkg/deb/deblistparser.cc cmdline/apt-get.cc cmdline/apt-sortpkgs.cc doc/apt_preferences.5 doc/apt-cache.8 doc/apt-cdrom.8 doc/apt-config.8 doc/apt-get.8 doc/sources.list.5 methods/connect.cc methods/ftp.cc methods/rfc2553emu.h; do echo "generating diff for ${file_to_patch}" && diff -wub ${file_to_patch}.orig ${file_to_patch} > /opt/local/var/macports/sources/LocalPorts/sysutils/apt/files/patch-`echo ${file_to_patch} | tr \/ \_`.diff; done
# (some used the -r flag originally, but that is only applicable when patching
# multiple files and there are subdirectories present, and the above are all
# single-file patches)

# patch-01-c++pragma.diff has been turned into a shell script

# the following are also all multi-file patches:
# - patch-use-libintl.diff
# - patch-static-constructors.diff
# - patch-paths.diff
