COMMON_H = \
	$(top_srcdir)/include/arch/intel/ia32/sys/asm_linkage.h \
	$(top_srcdir)/include/arch/intel/ia32/sys/stack.h \
	$(top_srcdir)/include/arch/intel/ia32/sys/trap.h

KERNEL_H =

USER_H =

EXTRA_DIST = $(COMMON_H) $(KERNEL_H) $(USER_H)

if CONFIG_USER
libzfsdir = $(includedir)/libzfs/arch/intel/ia32
libzfs_HEADERS = $(COMMON_H) $(USER_H)
endif

if CONFIG_KERNEL
kerneldir = @prefix@/src/zfs-$(VERSION)/include/arch/intel/ia32
kernel_HEADERS = $(COMMON_H) $(KERNEL_H)
endif
