COMMON_H = \
	$(top_srcdir)/include/arch/intel/sys/stack.h \
	$(top_srcdir)/include/arch/intel/sys/trap.h

KERNEL_H =

USER_H =

EXTRA_DIST = $(COMMON_H) $(KERNEL_H) $(USER_H)

if CONFIG_USER
libzfsdir = $(includedir)/libzfs/arch/intel/sys
libzfs_HEADERS = $(COMMON_H) $(USER_H)
endif

if CONFIG_KERNEL
kerneldir = @prefix@/src/zfs-$(VERSION)/include/arch/intel/sys
kernel_HEADERS = $(COMMON_H) $(KERNEL_H)
endif
