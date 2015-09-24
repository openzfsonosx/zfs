dnl #
dnl # Kernel modprefix is the kernel extensions directory.
dnl # At least for now, both config=kernel and config=user
dnl # need to know where to find zfs.kext. In particular,
dnl # userland needs to know where to find the custom volume
dnl # icon, which we store in zfs.kext/Contents/Resources.
dnl #
AC_DEFUN([ZFS_AC_CONFIG_ALWAYS_KERNEL_MODPREFIX], [
	AC_ARG_WITH([kernel-modprefix],
		AS_HELP_STRING([--with-kernel-modprefix=PATH],
		[Path to kernel module prefix]),
		[kernelmodprefix="$withval"])

	AC_MSG_CHECKING([kernel module prefix])
	AS_IF([test -z "$kernelmodprefix"], [
		kernelmodprefix="/Library/Extensions"
	])
	AC_MSG_RESULT([$kernelmodprefix])
	KERNEL_MODPREFIX=${kernelmodprefix}

	AC_DEFINE_UNQUOTED([KERNEL_MODPREFIX],
		["$KERNEL_MODPREFIX"],
		[Path where the kernel module is installed.]
	)
	AC_SUBST(KERNEL_MODPREFIX)
])
