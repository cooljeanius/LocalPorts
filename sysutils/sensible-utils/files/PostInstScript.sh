#!/bin/sh

set -ex

if [ configure = "$1" ]; then
    if which update-mime >/dev/null;
    then
        update-mime
    fi
fi
