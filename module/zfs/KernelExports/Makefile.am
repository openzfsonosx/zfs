include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

noinst_PROGRAMS = kextsymboltool

kextsymboltool_SOURCES = \
	kextsymboltool.c

kextsymboltool_LDFLAGS = -lstdc++

KernelExports: zfs.exports
	./kextsymboltool -arch x86_64 -import allsymbols -export zfs.exports -output KernelExports_64
	./kextsymboltool -arch i386 -import allsymbols -export zfs.exports -output KernelExports_32
	lipo -create KernelExports_32 KernelExports_64 -output KernelExports

clean:
	rm -f KernelExports KernelExports_32 KernelExports_64 allsymbols
	rm -f kextsymboltool.o kextsymboltool

allsymbols:
	 nm -gj /mach_kernel > allsymbols

all:kextsymboltool allsymbols KernelExports
