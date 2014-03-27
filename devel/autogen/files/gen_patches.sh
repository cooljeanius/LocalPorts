#!/bin/sh

for file_to_patch in config/ag_macros.m4 configure.ac config/extensions.m4 config/libopts.m4 Makefile.am agen5/Makefile.am doc/Makefile.am config/unlocked-io.m4; do diff -u ${file_to_patch}.orig ${file_to_patch} > /opt/local/var/macports/sources/LocalPorts/devel/autogen/files/patch-`echo ${file_to_patch} | tr \/ \_`.diff; done
