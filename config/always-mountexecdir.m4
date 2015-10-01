--with-mountexecdir
dnl #
dnl # Kernel modprefix is the kernel extensions directory.
dnl # At least for now, both config=kernel and config=user
dnl # need to know where to find zfs.kext. In particular,
dnl # userland needs to know where to find the custom volume
dnl # icon, which we store in zfs.kext/Contents/Resources.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_ALWAYS_MOUNTEXECDIR], [
	AC_ARG_WITH([mountexecdir],
		AS_HELP_STRING([--with-mountexecdir=PATH],
		[Path to kernel module prefix]),
		[mountexecdir="$withval"])

	AC_MSG_CHECKING([kernel module prefix])
	AS_IF([test -z "$mountexecdir"], [
		mountexecdir="$sbindir"
	])
	AC_MSG_RESULT([$mountexecdir])
	MOUNTEXECDIR=${mountexecdir}

	AC_DEFINE_UNQUOTED([MOUNTEXECDIR],
		["$MOUNTEXECDIR"],
		[Path where the kernel module is installed.]
	)
	AC_SUBST(MOUNTEXECDIR)
])
