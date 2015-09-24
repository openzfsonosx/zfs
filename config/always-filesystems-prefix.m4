dnl #
dnl # Kernel modprefix is the kernel extensions directory.
dnl # At least for now, both config=kernel and config=user
dnl # need to know where to find zfs.kext. In particular,
dnl # userland needs to know where to find the custom volume
dnl # icon, which we store in zfs.kext/Contents/Resources.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_ALWAYS_FILESYSTEMS_PREFIX], [
	AC_ARG_WITH([filesystems-prefix],
		AS_HELP_STRING([--with-filesystems-prefix=PATH],
		[Path to Filesystems bundle prefix]),
		[filesystemsprefix="$withval"])

	AC_MSG_CHECKING([filesystems prefix])
	AS_IF([test -z "$filesystemsprefix"], [
		filesystemsprefix="/Library/Filesystems"
	])
	AC_MSG_RESULT([$filesystemsprefix])
	FILESYSTEMS_PREFIX=${filesystemsprefix}

	AC_DEFINE_UNQUOTED([FILESYSTEMS_PREFIX],
		["$FILESYSTEMS_PREFIX"],
		[Path where the Filesystems bundle is installed.]
	)
	AC_SUBST(FILESYSTEMS_PREFIX)
])
