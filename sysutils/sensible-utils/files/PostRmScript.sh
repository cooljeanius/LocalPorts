#!/bin/sh

set -ex

if [ remove = "$1" -o disappear = "$1" ]; then
    if which update-mime >/dev/null;
    then
        update-mime
    fi
fi
