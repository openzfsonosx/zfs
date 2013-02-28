
Very early work for ZFS on OSX.

Does not even compile yet, keep moving..


Current status:

```
# ./autogen.sh
# ./configure --with-spl=/path/to/your/spl
# make

# rsync -ar --delete module/zfs/zfs.kext/ /tmp/zfs.kext/
# chown -R root:wheel /tmp/zfs.kext

# kextload -r /tmp/ -v /tmp/zfs.kext/

Requesting load of /tmp/zfs.kext.
/tmp/zfs.kext loaded successfully (or already loaded).

: ZFS: Loaded module v0.01. Pool version -1
: kobj_open_file: "/etc/zfs/zpool.cache", err 0 from vnode_open
: ZFS: Loaded module v0.6.0-rc12alpha, ZFS pool version 5000, ZFS filesystem version 5

bash-3.2# ls -l /dev/zfs
crw-rw-rw-  1 root  wheel   33,   0 Feb 27 17:20 /dev/zfs


# Don't have zpool yet, so using MacZFS's zpool

# DYLD_LIBRARY_PATH=/Users/lundman/maczfs/build/zfs.build/Debug/libzfs.build/Objects-normal/x86_64/
# export DYLD_LIBRARY_PATH
# exec /Users/lundman/maczfs/build/zfs.build/Debug/zpool.build/Objects-normal/x86_64/zpool

missing command

# ./zpool.sh status
no pools available

# ./zpool.sh create BOOM /Users/lundman/maczfs/diskimage.bin

http://i.imgur.com/ldJFM7l.png


```

- lundman
