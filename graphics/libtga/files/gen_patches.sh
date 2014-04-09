#!/bin/sh

for file_to_patch in acinclude.m4 configure.ac Makefile.am doc/Makefile.am; do diff -u ${file_to_patch}.orig ${file_to_patch} > /opt/local/var/macports/sources/LocalPorts/graphics/libtga/files/patch-`echo ${file_to_patch} | tr \/ \_`.diff; done
