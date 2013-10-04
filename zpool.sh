#!/bin/bash

# ZOL needs /etc/mtab to do anything. 
touch /etc/mtab

export DYLD_LIBRARY_PATH=./lib/libnvpair/.libs/:./lib/libuutil/.libs/:./lib/libzpool/.libs/:./lib/libzfs/.libs/
exec cmd/zpool/zpool "$@" 

