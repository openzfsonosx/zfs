
OpenZFS on OS X (O3X) brings OpenZFS features to Apple's OS X.

** zfs.kext depends upon spl.kext, so start with that repository:
https://github.com/openzfsonosx/spl.git

It is tested primarily on Mac OS X Mavericks.

See http://openzfsonosx.org/ for more information.

Open Issues:

  https://github.com/openzfsonosx/zfs/issues?state=open

Please note that 'llvm-gcc' or 'clang' should be used for compiling the KEXTs.
Pure 'gcc' will produce unstable builds.

```
 # ./configure CC=clang CXX=clang++
or
 # ./configure CC=llvm-gcc CXX=llvm-g++
```

```
# git clone https://github.com/openzfsonosx/zfs.git
```

```
# ./autogen.sh
# ./configure CC=clang CXX=clang++ --with-spl=/path/to/your/spl
# make

# rsync -ar --delete module/zfs/zfs.kext/ /tmp/zfs.kext/
# chown -R root:wheel /tmp/zfs.kext

# kextload -r /tmp/ -v /tmp/zfs.kext/

In system log:
: ZFS: Loading module ... 
: ZFS: ARC limit set to (arc_c_max): 1073741824
: kobj_open_file: "/etc/zfs/zpool.cache", err 2 from vnode_open
: ZFS: Loaded module v0.6.2-rc1_2_g691a603, ZFS pool version 5000, ZFS filesystem version 5
: ZFS filesystem version: 5
: ZFS: hostid set to 9e5e1b35 from UUID 'C039E802-1F44-5F62-B3A2-5E252F3EFF2A'

bash-3.2# ls -l /dev/zfs
crw-rw-rw-  1 root  wheel   33,   0 Feb 27 17:20 /dev/zfs

# ./zpool.sh status
no pools available

# ./zpool.sh create BOOM /Users/lundman/openzfsonosx/diskimage.bin
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

# ./zpool.sh import -d /Users/lundman/openzfsonosx/
   pool: BOOM
     id: 17559987915944145476
  state: ONLINE
 action: The pool can be imported using its name or numeric identifier.
 config:

        BOOM                             ONLINE
          /Users/lundman/pool-image.bin  ONLINE

# ./zpool.sh import -d /Users/lundman/openzfsonosx/ BOOM

# ls -l /BOOM/
total 3
drwx------  2 root  wheel  3 Apr  4 16:44 .fseventsd
drwxr-xr-x  2 root  wheel  2 Apr  4 16:45 THIS.DIRECTORY.IS.ON.ZFS

# ./zpool.sh import -d ~/image/ FROMSOLARIS
NAME          SIZE  ALLOC   FREE    CAP  DEDUP  HEALTH  ALTROOT
FROMSOLARIS   123M   354K   123M     0%  1.00x  ONLINE  -

```

- lundman
