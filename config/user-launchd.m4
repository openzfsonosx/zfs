AC_DEFUN([ZFS_AC_CONFIG_USER_LAUNCHD], [
	AC_ARG_ENABLE(launchd,
		AC_HELP_STRING([--enable-launchd],
		[install launchd daemon/agent/script files [[default: yes]]]),
		[],enable_launchd=yes)

	AC_MSG_CHECKING([launchd daemon dir])
	AC_ARG_WITH(launchddaemondir,
		AC_HELP_STRING([--with-launchddaemondir=DIR],
		[install launchd daemon files in dir [[/Library/LaunchDaemons]]]),
		launchddaemondir=$withval,launchddaemondir=/Library/LaunchDaemons)
	AC_MSG_RESULT([$launchddaemondir])

	AC_MSG_CHECKING([launchd script dir])
	AC_ARG_WITH(launchdscriptdir,
		AC_HELP_STRING([--with-launchdscriptdir=DIR],
		[install launchd script files in dir [["${libexecdir}"/zfs/launchd.d]]]),
		launchdscriptdir=$withval,launchdscriptdir="${libexecdir}"/zfs/launchd.d)
	AC_MSG_RESULT([$launchdscriptdir])

	AS_IF([test "x$enable_launchd" = xyes],
		[
		ZFS_INIT_LAUNCHD=launchd
		])

	AC_SUBST(ZFS_INIT_LAUNCHD)
	AC_SUBST(launchdscriptdir)
	AC_SUBST(launchddaemondir)
])
