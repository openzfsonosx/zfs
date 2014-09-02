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


char *iokit_device_to_dataset(char *device)
{
	char *result = NULL;
	CFMutableDictionaryRef matchingDict;
	io_service_t service;
	CFStringRef cfstr;

	if (!strncmp("/dev/", device, 5))
		device = &device[5];

	fprintf(stderr, "looking for '%s'\n", device);

	matchingDict = IOBSDNameMatching(kIOMasterPortDefault, 0, device);
	if (NULL == matchingDict)
		return NULL;

	/*
	 * Fetch the object with the matching BSD node name.
	 * Note that there should only be one match, so
	 * IOServiceGetMatchingService is used instead of
	 * IOServiceGetMatchingServices to simplify the code.
	 */
	service = IOServiceGetMatchingService(kIOMasterPortDefault,
										  matchingDict);

	if (IO_OBJECT_NULL == service) {
		return NULL;
	}

	if (IOObjectConformsTo(service, kIOMediaClass)) {

		cfstr = IORegistryEntryCreateCFProperty(service,
						CFSTR("DATASET"), kCFAllocatorDefault, 0);
		if (cfstr) {
			result = strdup(CFStringGetCStringPtr(cfstr,
						kCFStringEncodingMacRoman));
			CFRelease(cfstr);
		}
	}
	IOObjectRelease(service);
	return result;
}




int iokit_mark_device_to_mount(char *dataset)
{
	CFDictionaryRef matchingDict = NULL;
	io_iterator_t iter = 0;
	io_service_t service = 0;
	kern_return_t kr;
	int special_len;
	char *special_name = NULL;


	// Create a matching dictionary that will find any USB device.
	matchingDict = IOServiceMatching("IOMedia");

	// Create an iterator for all I/O Registry objects that match the dictionary.
	kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
	if (kr != KERN_SUCCESS)
		return -1;


	/*
	 * Due to some automatic namingin IOKit, the pool name "BOOM"
	 * becomes "ZVOL BOOM Media", so we have to handle that case as
	 * well.
	 */
	special_len = strlen(dataset) + 5 /* ZVOL. */ +
		6 /* .Media */ + 1 /* null */;
	special_name = malloc(special_len);
	if (!special_name) return -1;
	snprintf(special_name, special_len, "ZVOL %s Media",
			 dataset);

	fprintf(stderr, "Looking for device: '%s' or '%s'\n", dataset,
		special_name);



	// Iterate over all matching objects.
	while ((service = IOIteratorNext(iter)) != 0)
	{
		CFStringRef className;
		io_name_t name;
		io_connect_t connect;
		kern_return_t status;
		io_registry_entry_t *parent;
		io_registry_entry_t *child;
		io_iterator_t children;

		/*
		 * Look up the child of the IOMedia device, it will have two:
		 * : IOBSDClient
		 * : ZFSProxyMediaScheme
		 */
		status = IORegistryEntryGetChildIterator(
			service,
			kIOServicePlane,
			&children );

		while ((child = IOIteratorNext(children))) {

			className = IOObjectCopyClass(child);
			fprintf(stderr, "clientclass %s :\r\n",
					CFStringGetCStringPtr( className, kCFStringEncodingMacRoman)
				);


			if (CFEqual(className, CFSTR("ZFSProxyMediaScheme")) == true) {

				/* If this matches the dataset in question ... */
				IORegistryEntryGetName(service, name);
				fprintf(stderr, "device with name: %s\n", name);
				if (!strcmp(name, dataset) ||
					!strcmp(name, special_name)) {

					fprintf(stderr, "Found device with name: %s\n", name);

					/* Open connection to kernel */
					status = IOServiceOpen(child,
										   mach_task_self(), 0, &connect);
					fprintf(stderr, "XXX child open say %d : %p\n",
							status,connect);

					/* Fire off the request to change property */
					status = IOConnectSetCFProperty(connect,
													CFSTR("DOMOUNTME"),
													CFSTR("TRUE"));

					fprintf(stderr, "XXX IOConnectSetCFProp say %d : %p\n",
							status,connect);

					IOServiceClose(connect);

				} // Is dataset

			} // is ZFSProxyMedia

			IOObjectRelease(child);
			CFRelease(className);

		} // IOIteratorNext
		IOObjectRelease(children);

		IOObjectRelease(service);
	} // IteratorNext(iter)

	// Release the iterator.
	IOObjectRelease(iter);

	free(special_name);

}





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
	char *dataset = NULL;

	if (spec == NULL)
		return (-1);

	iokit_mark_device_to_mount(spec);

	specRef = CFStringCreateWithCString(NULL, spec,
	    kCFStringEncodingMacRoman);
	if (specRef == NULL)
		return (-1);

	mySubDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(mySubDictionary, CFSTR("DATASET"), specRef);

	myMatchingDictionary = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	fprintf(stderr, "myMatchingDict %p\n", myMatchingDictionary);
	CFDictionarySetValue(myMatchingDictionary, CFSTR(kIOPropertyMatchKey),
	    mySubDictionary);

	/* always consumes one reference of myMatchingDictionary */
	status = IOServiceGetMatchingServices(kIOMasterPortDefault,
	    myMatchingDictionary, &iter);

	fprintf(stderr, "status %d iter %p\n", status, iter);

	if ((status != KERN_SUCCESS) || (iter == IO_OBJECT_NULL)) {
		fprintf(stderr, "failed to GetMatchingService\n");
		CFRelease(specRef);
		fprintf(stderr, "failed to GetMatchingService2\n");
		CFRelease(mySubDictionary);
		fprintf(stderr, "failed to GetMatchingService3\n");
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

	free(dataset);

	return (0);
}


static int diskutil_mount(io_name_t device, const char *path, int flags)
{
	char *argv[7] = {
	    "/usr/sbin/diskutil",
	    "mount",
		//"-mountPoint",
	    NULL, NULL, NULL, NULL };
		int rc;
		//int count = 3;
		int count = 2;

#if 0
	if (flags & MS_FORCE) {
		argv[count] = force_opt;
		count++;
	}
#endif

		//argv[count++] = (char *)path;
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

	fprintf(stderr, "zmount spec '%s' dir '%s'\n", spec, dir);

	/*
	 * If we can, we will translate from "$POOL/$DATASET" name here to
	 * the fake IOKIT "/dev/diskXsY". So that DiskArbitration and
	 * SpotLight is more involved. The zfs_vfs_mount() call in zfs_vfsops
	 * translates it back again.
	 */
	if (iokit_dataset_to_device(spec, devname) == 0)
		if (devname)
			return (diskutil_mount(devname, dir, mflag));

	/* Regular mount wanted, from cmd/zfs manual_mount */
	fprintf(stderr, "zmount manual '%s' \n", spec);

	mnt_args.fspec = spec;
	mnt_args.mflag = mflag;
	mnt_args.optptr = optptr;
	mnt_args.optlen = optlen;

	rv = mount(fstype, dir, 0, &mnt_args);

	return (rv);
}

#endif
