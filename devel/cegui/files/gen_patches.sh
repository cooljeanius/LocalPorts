#!/bin/sh

# leave out the ones that actually patch C++ source files
for file_to_patch in acinclude.m4 configure.ac Makefile.am Samples/*/Makefile.am Samples/common/include/Makefile.am; do (echo "generating patch for ${file_to_patch}") && (diff -u ${file_to_patch}.orig ${file_to_patch} > /opt/local/var/macports/sources/LocalPorts/devel/cegui/files/patch-`echo ${file_to_patch} | tr \/ \_`.diff); done
