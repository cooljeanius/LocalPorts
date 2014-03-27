#!/bin/sh

for file_to_patch in configure.ac lib/dpkg/dpkg.h lib/dpkg/tarfn.c src/archives.c src/remove.c utils/start-stop-daemon.c; do diff -u ${file_to_patch}.orig ${file_to_patch} > /opt/local/var/macports/sources/LocalPorts/sysutils/dpkg/files/patch-`echo ${file_to_patch} | tr \/ \_`.diff; done
