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


KNOWN ISSUES.

*) Large sections are missing. File attributes, ACLs, xattr, etc etc.

*) zfs send and zfs recv only works with file IO, no pipes.

*) zfs clone is not correct



```

# ./autogen.sh
# ./configure --with-spl=/path/to/your/spl
# make

# rsync -ar --delete module/zfs/zfs.kext/ /tmp/zfs.kext/
# chown -R root:wheel /tmp/zfs.kext

# kextload -r /tmp/ -v /tmp/zfs.kext/

Requesting load of /tmp/zfs.kext.
/tmp/zfs.kext loaded successfully (or already loaded).

: kobj_open_file: "/etc/zfs/zpool.cache", err 0 from vnode_open
: ZFS: Loaded module v0.6.0-rc12alpha, ZFS pool version 5000, ZFS filesystem version 5

bash-3.2# ls -l /dev/zfs
crw-rw-rw-  1 root  wheel   33,   0 Feb 27 17:20 /dev/zfs


# ./zpool.sh status
no pools available


# ./zpool.sh create BOOM /Users/lundman/osx.zfs/diskimage.bin
zfs_mount: unused options: "defaults,atime,dev,exec,rw,suid,xattr,nomand,zfsutil"

# df -h
Filesystem      Size   Used  Avail Capacity iused   ifree %iused  Mounted on
/dev/disk0s2    20Gi   11Gi  8.5Gi    57% 2921478 2237422   57%   /
BOOM           472Mi   21Ki  472Mi     1%       6  966468    0%   /BOOM

# ls -l /BOOM/
total 3
drwx------  2 root  wheel  3 Apr  4 16:44 .fseventsd

# mkdir /BOOM/THIS.DIRECTORY.IS.ON.ZFS

drwxr-xr-x  2 root  wheel  2 Apr  4 16:45 THIS.DIRECTORY.IS.ON.ZFS

# ./cmd.sh zfs umount BOOM

# ./zpool.sh export BOOM

# ./zpool.sh import -d /Users/lundman/osx.zfs/
   pool: BOOM
     id: 17559987915944145476
  state: ONLINE
 action: The pool can be imported using its name or numeric identifier.
 config:

        BOOM                             ONLINE
          /Users/lundman/pool-image.bin  ONLINE

# ./zpool.sh import -d /Users/lundman/osx.zfs/ BOOM

# ls -l /BOOM/
total 3
drwx------  2 root  wheel  3 Apr  4 16:44 .fseventsd
drwxr-xr-x  2 root  wheel  2 Apr  4 16:45 THIS.DIRECTORY.IS.ON.ZFS

# ./zpool.sh import -d ~/image/ FROMSOLARIS
NAME          SIZE  ALLOC   FREE    CAP  DEDUP  HEALTH  ALTROOT
FROMSOLARIS   123M   354K   123M     0%  1.00x  ONLINE  -


```

- lundman
