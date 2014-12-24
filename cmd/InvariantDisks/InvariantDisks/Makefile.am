include $(top_srcdir)/config/Rules.am

AUTOMAKE_OPTIONS = subdir-objects

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include

sbin_PROGRAMS = InvariantDisks

InvariantDisks_SOURCES = \
	IDCLI.cpp \
	IDCLI.hpp \
	IDDiskArbitrationDispatcher.cpp \
	IDDiskArbitrationDispatcher.hpp \
	IDDiskArbitrationHandler.hpp \
	IDDiskArbitrationUtils.cpp \
	IDDiskArbitrationUtils.hpp \
	IDDiskInfoLogger.cpp \
	IDDiskInfoLogger.hpp \
	IDException.cpp \
	IDException.hpp \
	IDFileUtils.cpp \
	IDFileUtils.hpp \
	IDMediaPathLinker.cpp \
	IDMediaPathLinker.hpp \
	IDSerialLinker.cpp \
	IDSerialLinker.hpp \
	IDUUIDLinker.cpp \
	IDUUIDLinker.hpp \
	git-version.h \
	main.cpp

InvariantDisks_CXXFLAGS = -std=c++11 -stdlib=libc++
InvariantDisks_LDFLAGS = -static -framework IOKit -framework DiskArbitration -framework CoreFoundation
