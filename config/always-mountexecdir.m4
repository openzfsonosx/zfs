AC_DEFUN([ZFS_AC_CONFIG_ALWAYS_MOUNTEXECDIR], [
	AC_ARG_WITH([mountexecdir],
		AS_HELP_STRING([--with-mountexecdir=PATH],
		[install mount_zfs in dir [SBINDIR]]),
		[mountexecdir="$withval"])

	AC_MSG_CHECKING([mount executable directory])
	AS_IF([test -z "$mountexecdir"], [
		mountexecdir="$sbindir"
	])
	AC_MSG_RESULT([$mountexecdir])
	MOUNTEXECDIR=${mountexecdir}

	AC_DEFINE_UNQUOTED([MOUNTEXECDIR],
		["$MOUNTEXECDIR"],
		[Define to a directory where mount(2) will look for mount_zfs.]
	)
	AC_SUBST(MOUNTEXECDIR)
])
