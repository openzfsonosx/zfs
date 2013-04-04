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

# hexdump -C /Users/lundman/osx.zfs/diskimage.bin |less

00414880  07 00 00 00 00 00 00 40  00 00 00 00 00 00 54 48  |.......@......TH|
00414890  49 53 2e 44 49 52 45 43  54 4f 52 59 2e 49 53 2e  |IS.DIRECTORY.IS.|
004148a0  49 4e 2e 5a 46 53 00 00  00 00 00 00 00 00 00 00  |IN.ZFS..........|
004148b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

# echo "Hello World" > /BOOM/THIS.IS.A.FILE

# strings /Users/lundman/osx.zfs/diskimage.bin | grep Hello
Hello World

# ./cmd.sh zfs umount BOOM
cannot unmount 'BOOM': not currently mounted

# ./cmd.sh zfs create -o compression=on BOOM/roger
zfs_mount: unused options: "defaults,atime,dev,exec,rw,suid,xattr,nomand,zfsutil"

panic:

#0  0xffffff7f80f35444 in _zil_commit
#1  0xffffff7f80f25d52 in _zfs_vnop_fsync
#2  0xffffff800031206f in VNOP_MNOMAP
#3  0xffffff80002f9915 in prepare_coveredvp
#4  0xffffff80002f8385 in mount_common
#5  0xffffff80002f97ba in __mac_mount
#6  0xffffff80002f8f99 in mount_common
#7  0xffffff80005e17da in unix_syscall64

# umount /BOOM

panic:



```

- lundman
