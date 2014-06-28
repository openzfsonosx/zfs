/*
 * Copyright (c) 2006 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This file implements Solaris compatible zmount() function.
 */


#ifdef __APPLE__

#include <sys/mount.h>
#include <sys/zfs_mount.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOBSD.h>
#include <libzfs.h>

/*
 * Lookup "POOL/DATASET" and return BSD Name "diskXsY".
 */
int
iokit_dataset_to_device(const char *spec, io_name_t volname)
{
	io_service_t service = IO_OBJECT_NULL;
	CFMutableDictionaryRef mySubDictionary;
	CFMutableDictionaryRef myMatchingDictionary;
	CFStringRef specRef = NULL;
	io_iterator_t iter = IO_OBJECT_NULL;
	int status;
	CFStringRef ioBSDName = NULL;

	if (spec == NULL)
		return (-1);

	specRef = CFStringCreateWithCString(NULL, spec,
	    kCFStringEncodingMacRoman);
	if (specRef == NULL)
		return (-1);

	mySubDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(mySubDictionary, CFSTR("DATASET"), specRef);

	myMatchingDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(myMatchingDictionary, CFSTR(kIOPropertyMatchKey),
	    mySubDictionary);

	/* always consumes one reference of myMatchingDictionary */
	status = IOServiceGetMatchingServices(kIOMasterPortDefault,
	    myMatchingDictionary, &iter);

	if ((status != KERN_SUCCESS) || (iter == IO_OBJECT_NULL)) {
		fprintf(stderr, "failed to GetMatchingService\n");
		CFRelease(specRef);
		CFRelease(mySubDictionary);
		CFRelease(myMatchingDictionary);
		return (-1);
	}

	while ((service = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
		fprintf(stderr, "Matching service is ok\n");
		if (IOObjectConformsTo(service, kIOMediaClass)) {
			fprintf(stderr, "Conforms to is ok\n");
			ioBSDName =
			    (CFStringRef) IORegistryEntryCreateCFProperty(
			    service, CFSTR(kIOBSDNameKey), kCFAllocatorDefault,
			    0);
			if (ioBSDName) {
				strlcpy(volname,
				    CFStringGetCStringPtr(ioBSDName,
				    kCFStringEncodingMacRoman),
				    sizeof (io_name_t));
				fprintf(stderr, "Found BSDName '%s'\n",
				    volname);
				CFRelease(ioBSDName);
			}

		}
		IOObjectRelease(service);
	}

	IOObjectRelease(iter);
	CFRelease(specRef);
	CFRelease(mySubDictionary);

	return (0);
}


static int diskutil_mount(io_name_t device, const char *path, int flags)
{
	char *argv[7] = {
	    "/usr/sbin/diskutil",
	    "mount",
		"-mountPoint",
	    NULL, NULL, NULL, NULL };
	int rc, count = 3;

#if 0
	if (flags & MS_FORCE) {
		argv[count] = force_opt;
		count++;
	}
#endif

	argv[count++] = (char *)path;
	argv[count++] = (char *)device;

	rc = libzfs_run_process(argv[0], argv, STDOUT_VERBOSE|STDERR_VERBOSE);

	return (rc ? EINVAL : 0);
}


int
zmount(const char *spec, const char *dir, int mflag, char *fstype,
    char *dataptr, int datalen, char *optptr, int optlen)
{
	int rv;
	struct zfs_mount_args mnt_args;
	io_name_t devname;

	assert(spec != NULL);
	assert(dir != NULL);
	assert(fstype != NULL);
	assert(mflag >= 0);
	assert(strcmp(fstype, MNTTYPE_ZFS) == 0);
	assert(dataptr == NULL);
	assert(datalen == 0);
	assert(optptr != NULL);
	assert(optlen > 0);

	/*
	 * If we can, we will translate from "$POOL/$DATASET" name here to
	 * the fake IOKIT "/dev/diskXsY". So that DiskArbitration and
	 * SpotLight is more involved. The zfs_vfs_mount() call in zfs_vfsops
	 * translates it back again.
	 */
	if (iokit_dataset_to_device(spec, devname) != 0)
		return (-1);
	if (devname)
		return (diskutil_mount(devname, dir, mflag));

	mnt_args.fspec = spec;
	mnt_args.mflag = mflag;
	mnt_args.optptr = optptr;
	mnt_args.optlen = optlen;

	rv = mount(fstype, dir, 0, &mnt_args);

	return (rv);
}

#endif
