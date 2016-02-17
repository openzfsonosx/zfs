
#include <AppKit/NSWorkspace.h>
#include <Foundation/NSString.h>

#include "zfs_osx.h"

void libzfs_refresh_finder(char *mountpoint)
{
  [[NSWorkspace sharedWorkspace] noteFileSystemChanged:[NSString stringWithUTF8String:mountpoint]];
}
