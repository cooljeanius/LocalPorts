#!/bin/sh

# Arguments:
# $1: MacPorts prefix
# $2: Port to format in shlibs.default style

if test -z "$1"; then
    echo "$0: first argument missing" >&2
    exit 1
fi
if test -z "$2"; then
    echo "$0: second argument missing" >&2
    exit 1
fi
export shlib=$2
export shlibver=`port -q info --version ${shlib}`
export shlibvf1=`echo ${shlibver} | cut -d. -f1`
#FIXME: some libraries use different versioning schemes:
export shlibdylibs=`port contents ${shlib} | grep ".${shlibvf1}.dylib"`
#(TODO: use other shlib extensions on other platforms in the above)
export shlibvf2=`echo ${shlibver} | cut -d. -f2`
if test -z "${shlibvf2}"; then
	export shlibvf2=0
fi
export shlibvf3=`echo ${shlibver} | cut -d. -f3`
if test -z "${shlibvf3}"; then
	export shlibvf3=0
fi
export shlibsemver="${shlibvf1}.${shlibvf2}.${shlibvf3}"
export shlibrev=`port -q info --revision ${shlib}`

for singledylib in ${shlibdylibs}; do
	echo "${singledylib} ${shlibsemver} ${shlib} (>= ${shlibver}-${shlibrev})"
done
