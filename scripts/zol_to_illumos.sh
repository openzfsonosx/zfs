#!/bin/bash

cd ~/Developer/zfs

mkdir -p usr/src/uts/common/fs/zfs
mkdir -p usr/src/common/avl
mkdir -p usr/src/common/nvpair
mkdir -p usr/src/common/unicode
mkdir -p usr/src/common/zfs
mkdir -p usr/src/lib/libavl/common
mkdir -p usr/src/lib/libefi/common
mkdir -p usr/src/lib/libnvpair/common
mkdir -p usr/src/lib/libshare/common
mkdir -p usr/src/lib/libspl/common
mkdir -p usr/src/lib/libunicode/common
mkdir -p usr/src/lib/libuutil/common
mkdir -p usr/src/lib/libzfs/common
mkdir -p usr/src/lib/libzfs_core/common
mkdir -p usr/src/lib/libzpool/common
mkdir -p usr/src/cmd/InvariantDisks
mkdir -p usr/src/cmd/stat/arcstat
mkdir -p usr/src/cmd/arc_summary
mkdir -p usr/src/cmd/dbufstat
mkdir -p usr/src/cmd/fsck_zfs
mkdir -p usr/src/cmd/mount_zfs
mkdir -p usr/src/cmd/vdev_id
mkdir -p usr/src/cmd/zconfigd
mkdir -p usr/src/cmd/zdb
mkdir -p usr/src/cmd/zed
mkdir -p usr/src/cmd/zfs
mkdir -p usr/src/cmd/zfs_util
mkdir -p usr/src/cmd/zhack
mkdir -p usr/src/cmd/zinject
mkdir -p usr/src/cmd/zpios
mkdir -p usr/src/cmd/zpool
mkdir -p usr/src/cmd/zpool_layout
mkdir -p usr/src/cmd/zstreamdump
mkdir -p usr/src/cmd/zsysctl
mkdir -p usr/src/cmd/ztest
mkdir -p usr/src/cmd/zvol_id

git mv module/avl/* usr/src/common/avl
git mv module/nvpair/* usr/src/common/nvpair
git mv module/unicode/* usr/src/common/unicode
git mv module/zcommon/* usr/src/common/zfs
git mv module/zfs/* usr/src/uts/common/fs/zfs
git mv lib/Makefile.am usr/src/lib
git mv lib/libavl/* usr/src/lib/libavl/common
git mv lib/libefi/* usr/src/lib/libefi/common
git mv lib/libnvpair/* usr/src/lib/libnvpair/common
git mv lib/libshare/* usr/src/lib/libshare/common
git mv lib/libspl/* usr/src/lib/libspl/common
git mv lib/libuutil/* usr/src/lib/libuutil/common
git mv lib/libunicode/* usr/src/lib/libunicode/common
git mv lib/libzfs/* usr/src/lib/libzfs/common
git mv lib/libzfs/.gitignore usr/src/lib/libzfs/common
git mv lib/libzfs_core/* usr/src/lib/libzfs_core/common
git mv lib/libzpool/* usr/src/lib/libzpool/common
git mv cmd/arc_summary/* usr/src/cmd/arc_summary
git mv cmd/arcstat/* usr/src/cmd/stat/arcstat
git mv cmd/dbufstat/* usr/src/cmd/dbufstat
git mv cmd/fsck_zfs/* usr/src/cmd/fsck_zfs
git mv cmd/InvariantDisks/* usr/src/cmd/InvariantDisks
git mv cmd/mount_zfs/* usr/src/cmd/mount_zfs
git mv cmd/vdev_id/* usr/src/cmd/vdev_id
git mv cmd/zconfigd/* usr/src/cmd/zconfigd
git mv cmd/zdb/* usr/src/cmd/zdb
git mv cmd/zed/* usr/src/cmd/zed
git mv cmd/zfs/* usr/src/cmd/zfs
git mv cmd/zfs_util/* usr/src/cmd/zfs_util
git mv cmd/zhack/* usr/src/cmd/zhack
git mv cmd/zinject/* usr/src/cmd/zinject
git mv cmd/zpios/* usr/src/cmd/zpios
git mv cmd/zpool/* usr/src/cmd/zpool
git mv cmd/zpool_layout/* usr/src/cmd/zpool_layout
git mv cmd/zstreamdump/* usr/src/cmd/zstreamdump
git mv cmd/zsysctl/* usr/src/cmd/zsysctl
git mv cmd/ztest/* usr/src/cmd/ztest
git mv cmd/zvol_id/* usr/src/cmd/zvol_id
git mv cmd/Makefile.am usr/src/cmd

git mv cmd/InvariantDisks/.gitignore usr/src/cmd/InvariantDisks
git mv cmd/mount_zfs/.gitignore usr/src/cmd/mount_zfs
git mv cmd/zconfigd/.gitignore usr/src/cmd/zconfigd
git mv cmd/zdb/.gitignore usr/src/cmd/zdb
git mv cmd/zed/.gitignore usr/src/cmd/zed
git mv cmd/zfs/.gitignore usr/src/cmd/zfs
git mv cmd/zfs_util/.gitignore usr/src/cmd/zfs_util
git mv cmd/zhack/.gitignore usr/src/cmd/zhack
git mv cmd/zinject/.gitignore usr/src/cmd/zinject
git mv cmd/zpios/.gitignore usr/src/cmd/zpios
git mv cmd/zpool/.gitignore usr/src/cmd/zpool
git mv cmd/zstreamdump/.gitignore usr/src/cmd/zstreamdump
git mv cmd/zsysctl/.gitignore usr/src/cmd/zsysctl
git mv cmd/ztest/.gitignore usr/src/cmd/ztest
git mv cmd/zvol_id/.gitignore usr/src/cmd/zvol_id

perl -p -i -e 's/..\/..\/module\/avl\//..\/..\/..\/common\/avl\//g' usr/src/lib/libavl/common/Makefile.am
perl -p -i -e 's/..\/..\/module\/nvpair\//..\/..\/..\/common\/nvpair\//g' usr/src/lib/libnvpair/common/Makefile.am
perl -p -i -e 's/..\/..\/module\/unicode\//..\/..\/..\/common\/unicode\//g' usr/src/lib/libunicode/common/Makefile.am
perl -p -i -e 's/..\/..\/module\/zfs\//..\/..\/..\/uts\/common\/fs\/zfs\//g' usr/src/lib/libzpool/common/Makefile.am
perl -p -i -e 's/..\/..\/module\/zcommon\//..\/..\/..\/common\/zfs\//g' usr/src/lib/libzpool/common/Makefile.am

perl -p -i -e 's/lib\/libavl\//usr\/src\/lib\/libavl\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libefi\//usr\/src\/lib\/libefi\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libnvpair\//usr\/src\/lib\/libnvpair\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libshare\//usr\/src\/lib\/libshare\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libspl\//usr\/src\/lib\/libspl\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libunicode\//usr\/src\/lib\/libunicode\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libuutil\//usr\/src\/lib\/libuutil\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libzfs\//usr\/src\/lib\/libzfs\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libzfs_core\//usr\/src\/lib\/libzfs_core\/common\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/lib\/libzpool\//usr\/src\/lib\/libzpool\/common\//g' `find . -regex '.*\.am$'`

perl -p -i -e 's/cmd\//usr\/src\/cmd\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/usr\/src\/cmd\/arcstat\//usr\/src\/cmd\/stat\/arcstat\//g' `find . -regex '.*\.am$'`
perl -p -i -e 's/arcstat /stat /g' usr/src/cmd/Makefile.am

perl -p -i -e 's/module\/avl\//usr\/src\/common\/avl\//g' configure.ac
perl -p -i -e 's/module\/nvpair\//usr\/src\/common\/nvpair\//g' configure.ac
perl -p -i -e 's/module\/unicode\//usr\/src\/common\/unicode\//g' configure.ac
perl -p -i -e 's/module\/zcommon\//usr\/src\/common\/zfs\//g' configure.ac
perl -p -i -e 's/module\/zfs\//usr\/src\/uts\/common\/fs\/zfs\//g' configure.ac
perl -p -i -e 's/lib\/Makefile/usr\/src\/lib\/Makefile/g' configure.ac
perl -p -i -e 's/lib\/libavl\//usr\/src\/lib\/libavl\/common\//g' configure.ac
perl -p -i -e 's/lib\/libefi\//usr\/src\/lib\/libefi\/common\//g' configure.ac
perl -p -i -e 's/lib\/libnvpair\//usr\/src\/lib\/libnvpair\/common\//g' configure.ac
perl -p -i -e 's/lib\/libshare\//usr\/src\/lib\/libshare\/common\//g' configure.ac
perl -p -i -e 's/lib\/libspl\//usr\/src\/lib\/libspl\/common\//g' configure.ac
perl -p -i -e 's/lib\/libunicode\//usr\/src\/lib\/libunicode\/common\//g' configure.ac
perl -p -i -e 's/lib\/libuutil\//usr\/src\/lib\/libuutil\/common\//g' configure.ac
perl -p -i -e 's/lib\/libzfs\//usr\/src\/lib\/libzfs\/common\//g' configure.ac
perl -p -i -e 's/lib\/libzfs_core\//usr\/src\/lib\/libzfs_core\/common\//g' configure.ac
perl -p -i -e 's/lib\/libzpool\//usr\/src\/lib\/libzpool\/common\//g' configure.ac
perl -p -i -e 's/cmd\//usr\/src\/cmd\//g' configure.ac
perl -p -i -e 's/usr\/src\/cmd\/arcstat\//usr\/src\/cmd\/stat\/arcstat\//g' configure.ac

perl -p -i -e 's/module\/zcommon\//usr\/src\/common\/zfs\//g'  usr/src/common/zfs/Makefile.in

perl -p -i -e 's/\.\.\/nvpair\//\.\.\/\.\.\/\.\.\/\.\.\/common\/nvpair\//g' usr/src/uts/common/fs/zfs/Makefile.am
perl -p -i -e 's/\.\.\/unicode\//\.\.\/\.\.\/\.\.\/\.\.\/common\/unicode\//g' usr/src/uts/common/fs/zfs/Makefile.am
perl -p -i -e 's/\.\.\/zcommon\//\.\.\/\.\.\/\.\.\/\.\.\/common\/zfs\//g' usr/src/uts/common/fs/zfs/Makefile.am

perl -p -i -e 's/SUBDIRS \+= module/SUBDIRS \+= module usr/g' Makefile.am
perl -p -i -e 's/SUBDIRS \+= etc man scripts lib cmd zfs_bundle/SUBDIRS \+= etc man scripts zfs_bundle/g' Makefile.am

echo 'SUBDIRS = src' > usr/Makefile.am
echo 'SUBDIRS = lib cmd uts' > usr/src/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libavl/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libefi/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libnvpair/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libshare/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libspl/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libunicode/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libuutil/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libzfs/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libzfs_core/Makefile.am
echo 'SUBDIRS = common' > usr/src/lib/libzpool/Makefile.am
echo 'SUBDIRS = common' > usr/src/uts/Makefile.am
echo 'SUBDIRS = fs' > usr/src/uts/common/Makefile.am
echo 'SUBDIRS = zfs' > usr/src/uts/common/fs/Makefile.am
echo 'SUBDIRS = arcstat' > usr/src/cmd/stat/Makefile.am

echo '' > module/Makefile.am
git rm module/zfs/.gitignore

perl -p -i -e 's/export PATH=\${topdir}\/cmd\/\${c}\/.libs:$PATH/export PATH=\${topdir}\/usr\/src\/cmd\/\${c}\/.libs:$PATH/g' cmd.sh
perl -p -i -e 's/exec \${topdir}\/cmd\/\$cmd\/.libs\/\$cmd "\$@"/exec \${topdir}\/usr\/src\/cmd\/\$cmd\/.libs\/\$cmd "\$@"/g' cmd.sh

ed configure.ac << END
89i
	usr/Makefile
	usr/src/Makefile
.
w
q
END

ed configure.ac << END
92i
	usr/src/lib/libspl/Makefile
.
w
q
END


ed configure.ac << END
105i
	usr/src/lib/libavl/Makefile
.
w
q
END

ed configure.ac << END
107i
	usr/src/lib/libefi/Makefile
.
w
q
END

ed configure.ac << END
109i
	usr/src/lib/libnvpair/Makefile
.
w
q
END

ed configure.ac << END
111i
	usr/src/lib/libunicode/Makefile
.
w
q
END

ed configure.ac << END
113i
	usr/src/lib/libuutil/Makefile
.
w
q
END

ed configure.ac << END
118i
	usr/src/lib/libzfs/Makefile
.
w
q
END

ed configure.ac << END
120i
	usr/src/lib/libzfs_core/Makefile
.
w
q
END

ed configure.ac << END
115i
	usr/src/lib/libzpool/Makefile
.
w
q
END

ed configure.ac << END
123i
	usr/src/lib/libshare/Makefile
.
w
q
END

ed configure.ac << END
141i
	usr/src/cmd/stat/Makefile
.
w
q
END



ed configure.ac << END
158i
	usr/src/uts/Makefile
	usr/src/uts/common/Makefile
	usr/src/uts/common/fs/Makefile
.
w
q
END
