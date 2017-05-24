
OpenZFS on OS X (O3X) brings OpenZFS features to Apple's OS X.

** zfs.kext depends upon spl.kext, so start with that repository:
https://github.com/openzfsonosx/spl.git

It is tested primarily on Mac OS X Sierra.

See http://openzfsonosx.org/ for more information.

Open Issues:

  https://github.com/openzfsonosx/zfs/issues?state=open

Place repository directories "spl" and "zfs" next to each other, on
the same level.

```
# git clone https://github.com/openzfsonosx/zfs.git
# ./autogen.sh
# ./configure
# make
```

Issue "make install" if you want it installed on the system.

If you want to load it directly;

```
# ./load.sh
```

To use commands directly;

```
# ./cmd.sh zpool status
```

To load unsigned kexts you need to disable SIP for kexts. Or sign them
with your own keys.

For messages use:
* Pre-Sierra:
```
# tail -f /var/log/system.log
```

* Sierra and higher:
```
# log stream --source --predicate 'senderImagePath CONTAINS "zfs" OR senderImagePath CONTAINS "spl"'
```

For example:
```
: ZFS: Loading module ...
: ZFS: ARC limit set to (arc_c_max): 1073741824
: ZFS: Loaded module v0.6.2-rc1_2_g691a603, ZFS pool version 5000, ZFS filesystem version 5
: ZFS filesystem version: 5
: ZFS: hostid set to 9e5e1b35 from UUID 'C039E802-1F44-5F62-B3A2-5E252F3EFF2A'
```

- OpenZFSonOsX team
