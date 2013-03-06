#!/bin/bash
cmd=$1
shift

export DYLD_LIBRARY_PATH=./lib/libnvpair/.libs/:./lib/libuutil/.libs/:./lib/libzpool/.libs/:./lib/libzfs/.libs/
exec cmd/$cmd/$cmd $*
