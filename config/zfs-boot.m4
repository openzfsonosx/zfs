AC_DEFUN([ZFS_AC_BOOT], [
	AC_ARG_ENABLE([boot],
		[AS_HELP_STRING([--enable-boot],
		[Enable boot @<:@default=no@:>@])],
		[],
		[enable_boot=no])

	AS_IF([test "x$enable_boot" != xno],
	[
		enable_boot=yes
		ZFS_BOOT=1
		AM_CONDITIONAL(ZFS_BOOT, true)
		KERNELCPPFLAGS="${KERNELCPPFLAGS} -DZFS_BOOT"
		CFLAGS_KMOD="${CFLAGS_KMOD} -DZFS_BOOT"
		AC_DEFINE(ZFS_BOOT, 1,
		[Define ZFS_BOOT to enable kext load at boot])
		AC_SUBST([ZFS_BOOT])
	],
	[
		AM_CONDITIONAL(ZFS_BOOT, false)
	])

	AC_MSG_CHECKING([whether kext load at boot is enabled])
	AC_MSG_RESULT([$enable_boot])
])
