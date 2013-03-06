This is a very early alpha of ZFS on OSX, to be the next generation of MacZFS.
Test this with the expectation of a kernel panic.
zfs.kext depends upon spl.kext, so start with that repository.

It is tested primarily on Mac OS 10.8.2 and secondarily on 10.6.8, with
the latest Macports.

OSX claims that gcc has to be version 4.2
Hopefully the path to /System/Library/Frameworks/Kernel.framework is universal.

See https://github.com/zfs-osx/ and http://MacZFS.org/ for more information.
Note MacZFS's wiki on kernel development and panic decoding.

# git clone https://github.com/zfs-osx/zfs.git

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


# ./zpool.sh status
no pools available


# ./zpool.sh create BOOM /Users/lundman/maczfs/diskimage.bin

mach_kernel     : _return_from_trap
net.lundman.zfs : _dsl_pool_sync_context
net.lundman.zfs : _spa_guid
net.lundman.zfs : _spa_generate_guid
net.lundman.zfs : _vdev_alloc_common



```

- lundman
